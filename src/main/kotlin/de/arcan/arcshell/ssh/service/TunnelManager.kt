package de.arcan.arcshell.ssh.service

import de.arcan.arcshell.ssh.ForwardType
import de.arcan.arcshell.ssh.PortForwarding
import de.arcan.arcshell.ssh.nio.AsyncSshClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentHashMap

object TunnelManager {

    enum class TunnelStatus { STARTING, ACTIVE, FAILED, STOPPED }

    data class ActiveTunnel(
        val config: PortForwarding,
        val job: Job,
        val serverChannel: ServerSocketChannel?,
        var status: TunnelStatus = TunnelStatus.STARTING,
        var error: String? = null,
        var connectionCount: Int = 0
    )

    // Key: hostName → list of active tunnels for that host
    private val tunnelsByHost = ConcurrentHashMap<String, MutableList<ActiveTunnel>>()

    fun getTunnelsForHost(hostName: String): List<ActiveTunnel> =
        tunnelsByHost[hostName]?.toList() ?: emptyList()

    suspend fun activate(
        client: AsyncSshClient,
        tunnels: List<PortForwarding>,
        hostName: String,
        scope: CoroutineScope
    ) {
        val hostTunnels = tunnelsByHost.getOrPut(hostName) { mutableListOf() }

        for (config in tunnels) {
            if (!config.enabled) continue

            val tunnel = when (config.type) {
                ForwardType.LOCAL -> activateLocalForward(client, config, scope)
                ForwardType.REMOTE -> activateRemoteForward(client, config)
                ForwardType.DYNAMIC -> null // SOCKS proxy not implemented
            }
            if (tunnel != null) hostTunnels.add(tunnel)
        }
    }

    private fun activateLocalForward(
        client: AsyncSshClient,
        config: PortForwarding,
        scope: CoroutineScope
    ): ActiveTunnel {
        val serverChannel = ServerSocketChannel.open()
        serverChannel.configureBlocking(false)
        serverChannel.bind(InetSocketAddress("127.0.0.1", config.localPort))

        val tunnel = ActiveTunnel(
            config = config,
            job = Job(),
            serverChannel = serverChannel,
            status = TunnelStatus.STARTING
        )

        val job = scope.launch(Dispatchers.IO) {
            tunnel.status = TunnelStatus.ACTIVE
            try {
                // Accept loop - blocking accept in a coroutine
                serverChannel.configureBlocking(true)
                while (isActive) {
                    val clientSocket = try {
                        serverChannel.accept()
                    } catch (_: IOException) {
                        break
                    } ?: continue

                    tunnel.connectionCount++

                    // For each accepted connection, open SSH direct-tcpip channel
                    launch {
                        try {
                            val sshChannel = client.openDirectTcp(config.remoteHost, config.remotePort)
                            bridgeConnection(clientSocket, sshChannel)
                        } catch (_: Exception) {
                            try { clientSocket.close() } catch (_: Exception) {}
                        }
                    }
                }
            } catch (e: Exception) {
                if (isActive) {
                    tunnel.status = TunnelStatus.FAILED
                    tunnel.error = e.message
                }
            } finally {
                try { serverChannel.close() } catch (_: Exception) {}
                if (tunnel.status != TunnelStatus.FAILED) {
                    tunnel.status = TunnelStatus.STOPPED
                }
            }
        }

        // Replace the placeholder job
        return tunnel.copy(job = job)
    }

    private suspend fun activateRemoteForward(
        client: AsyncSshClient,
        config: PortForwarding
    ): ActiveTunnel {
        val job = Job()
        val tunnel = ActiveTunnel(
            config = config,
            job = job,
            serverChannel = null,
            status = TunnelStatus.STARTING
        )

        try {
            val success = client.requestRemoteForward("0.0.0.0", config.remotePort)
            if (success) {
                tunnel.status = TunnelStatus.ACTIVE
            } else {
                tunnel.status = TunnelStatus.FAILED
                tunnel.error = "Server rejected remote forward"
            }
        } catch (e: Exception) {
            tunnel.status = TunnelStatus.FAILED
            tunnel.error = e.message
        }

        return tunnel
    }

    // Bridge data between a local TCP socket and an SSH channel
    private suspend fun bridgeConnection(
        localSocket: SocketChannel,
        sshChannel: de.arcan.arcshell.ssh.nio.AsyncChannel
    ) {
        try {
            coroutineScope {
                // Local -> SSH
                launch(Dispatchers.IO) {
                    val buf = ByteBuffer.allocate(32768)
                    try {
                        while (isActive) {
                            buf.clear()
                            val n = localSocket.read(buf)
                            if (n <= 0) break
                            buf.flip()
                            val data = ByteArray(n)
                            buf.get(data)
                            sshChannel.write(data)
                        }
                    } catch (_: Exception) {}
                    try { sshChannel.sendEof() } catch (_: Exception) {}
                }
                // SSH -> Local
                launch(Dispatchers.IO) {
                    try {
                        while (isActive) {
                            val data = sshChannel.read()
                            if (data.isEmpty()) break
                            localSocket.write(ByteBuffer.wrap(data))
                        }
                    } catch (_: Exception) {}
                    try { localSocket.close() } catch (_: Exception) {}
                }
            }
        } finally {
            try { localSocket.close() } catch (_: Exception) {}
            try { sshChannel.close() } catch (_: Exception) {}
        }
    }

    fun stopTunnelsForHost(hostName: String) {
        tunnelsByHost.remove(hostName)?.forEach { tunnel ->
            tunnel.job.cancel()
            try { tunnel.serverChannel?.close() } catch (_: Exception) {}
        }
    }

    fun stopTunnel(hostName: String, tunnel: ActiveTunnel) {
        tunnel.job.cancel()
        try { tunnel.serverChannel?.close() } catch (_: Exception) {}
        tunnelsByHost[hostName]?.remove(tunnel)
    }

    fun stopAll() {
        tunnelsByHost.forEach { (_, tunnels) ->
            tunnels.forEach { t ->
                t.job.cancel()
                try { t.serverChannel?.close() } catch (_: Exception) {}
            }
        }
        tunnelsByHost.clear()
    }
}
