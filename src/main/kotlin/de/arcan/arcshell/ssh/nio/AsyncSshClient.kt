package de.arcan.arcshell.ssh.nio

import de.arcan.arcshell.ssh.SshConfig
import de.arcan.arcshell.ssh.SshMsgType
import de.arcan.arcshell.ssh.auth.AuthResult
import de.arcan.arcshell.ssh.auth.Prompt
import de.arcan.arcshell.ssh.transport.NegotiatedAlgorithms
import de.arcan.arcshell.ssh.transport.SshBufferWriter
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.net.InetSocketAddress
import java.nio.channels.SocketChannel

/**
 * High-level async SSH client. Non-blocking port of
 * [de.arcan.arcshell.ssh.SshClient].
 *
 * Provides a coroutine-based API for connecting, authenticating,
 * and opening shells/exec channels over NIO.
 *
 * Usage:
 * ```
 * val client = AsyncSshClient(config, hostKeyVerifier)
 * client.connect()
 * client.authPassword("mypassword")
 * val session = client.openSession()
 * session.requestPty(...)
 * session.requestShell()
 * // read/write via session
 * client.disconnect()
 * ```
 */
class AsyncSshClient(
    private val config: SshConfig,
    private val hostKeyVerifier: suspend (String, ByteArray) -> Boolean,
    private val legacyAlgorithmApprover: (suspend (List<String>) -> Boolean)? = null
) {
    private var socketChannel: SocketChannel? = null
    private var source: AsyncDataSource? = null
    private var packetIO: AsyncPacketIO? = null
    private var transport: AsyncSshTransport? = null
    private var authenticator: AsyncSshAuthenticator? = null
    private var connection: AsyncSshConnection? = null
    private var messageLoopJob: Job? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** True if connected and handshake completed. */
    val isConnected: Boolean get() = transport != null && source?.isClosed == false

    /** The server's version string. */
    val serverVersion: String get() = transport?.serverVersion ?: ""

    /** The negotiated KEX algorithm name (for display). */
    val kexAlgorithm: String get() = transport?.kexAlgorithmName ?: "none"

    /** All negotiated algorithm names. */
    val negotiatedAlgorithms: NegotiatedAlgorithms? get() = transport?.negotiated

    /** The SSH transport layer (for advanced use). */
    val transportLayer: AsyncSshTransport? get() = transport

    /** The SSH connection layer (for agent forwarding setup). */
    val connectionLayer: AsyncSshConnection? get() = connection

    /**
     * Connect to the SSH server via a new NIO socket channel and perform
     * the transport-layer handshake (version exchange, KEXINIT, key
     * exchange, NEWKEYS).
     *
     * The socket connect phase uses blocking mode (with the configured
     * timeout), then switches to non-blocking for all subsequent I/O.
     *
     * After this, the connection is encrypted but not yet authenticated.
     */
    suspend fun connect() {
        SshEventLoop.ensureRunning()
        val ch = SocketChannel.open()
        ch.configureBlocking(true) // blocking for connect phase
        ch.socket().connect(
            InetSocketAddress(config.hostname, config.port),
            config.connectTimeoutMs
        )
        ch.configureBlocking(false) // switch to non-blocking
        socketChannel = ch

        val src = SocketChannelSource(ch)
        src.register()
        source = src

        val pio = AsyncPacketIO(src)
        packetIO = pio

        val xport = AsyncSshTransport(src, pio, hostKeyVerifier, legacyAlgorithmApprover)
        xport.performHandshake()
        transport = xport

        authenticator = AsyncSshAuthenticator(xport)
        authenticator!!.requestAuthService()
    }

    /**
     * Connect through an existing [AsyncChannel] (e.g. a direct-tcpip
     * tunnel from a jumphost). No raw socket is used; all I/O flows
     * through the tunnel channel's data path.
     */
    suspend fun connectViaChannel(tunnelChannel: AsyncChannel) {
        val src = TunnelSource(tunnelChannel)
        source = src

        val pio = AsyncPacketIO(src)
        packetIO = pio

        val xport = AsyncSshTransport(src, pio, hostKeyVerifier, legacyAlgorithmApprover)
        xport.performHandshake()
        transport = xport

        authenticator = AsyncSshAuthenticator(xport)
        authenticator!!.requestAuthService()
    }

    /**
     * Authenticate with a password.
     */
    suspend fun authPassword(password: String): AuthResult {
        return authenticator?.authPassword(config.username, password)
            ?: throw IllegalStateException("Not connected")
    }

    /**
     * Authenticate with a public key.
     *
     * @param keyType e.g. "ssh-ed25519"
     * @param publicKeyBlob SSH wire-format public key
     * @param signer signs the auth data with the corresponding private key
     * @param certificateBlob optional SSH certificate blob for cert-based auth
     */
    suspend fun authPublicKey(
        keyType: String,
        publicKeyBlob: ByteArray,
        signer: (ByteArray) -> ByteArray,
        certificateBlob: ByteArray? = null
    ): AuthResult {
        return authenticator?.authPublicKey(config.username, keyType, publicKeyBlob, signer, certificateBlob)
            ?: throw IllegalStateException("Not connected")
    }

    /**
     * Authenticate with keyboard-interactive (2FA, TOTP, etc.).
     *
     * @param responder suspend callback that receives prompts and returns answers
     */
    suspend fun authKeyboardInteractive(
        responder: suspend (name: String, instruction: String, prompts: List<Prompt>) -> List<String>
    ): AuthResult {
        return authenticator?.authKeyboardInteractive(config.username, responder)
            ?: throw IllegalStateException("Not connected")
    }

    /** Query available auth methods (sends "none" auth). */
    suspend fun queryAuthMethods(): List<String> {
        val result = authenticator?.authNone(config.username)
            ?: throw IllegalStateException("Not connected")
        return when (result) {
            is AuthResult.Failure -> result.methodsCanContinue
            is AuthResult.Success -> emptyList() // no auth needed (unlikely)
            else -> emptyList()
        }
    }

    /**
     * Open a session channel. Call after successful authentication.
     * The session can be used for shell, exec, or subsystem.
     *
     * Ensures the message loop is running before opening.
     */
    suspend fun openSession(): AsyncSessionChannel {
        ensureMessageLoop()
        return connection!!.openSession()
    }

    /**
     * Open a direct TCP/IP channel for local port forwarding.
     *
     * Ensures the message loop is running before opening.
     */
    suspend fun openDirectTcp(remoteHost: String, remotePort: Int): AsyncChannel {
        ensureMessageLoop()
        return connection!!.openDirectTcp(remoteHost, remotePort)
    }

    /**
     * Request remote port forwarding. The server will listen on
     * [bindAddress]:[bindPort] and forward incoming connections back
     * to the client.
     *
     * Ensures the message loop is running before sending the request.
     *
     * @return true if the server accepted the request
     */
    suspend fun requestRemoteForward(bindAddress: String, bindPort: Int): Boolean {
        ensureMessageLoop()
        return connection!!.requestRemoteForward(bindAddress, bindPort)
    }

    /**
     * Start an SSH-level keep-alive. Emits an
     * `SSH_MSG_GLOBAL_REQUEST` "keepalive@openssh.com" with
     * `want_reply=true` every [intervalMs] milliseconds.
     *
     * This is the mechanism OpenSSH's `ClientAliveInterval` check
     * expects: the server sees the traffic and responds with
     * `SSH_MSG_REQUEST_FAILURE`, which proves both ends are alive.
     *
     * Call this AFTER authentication has succeeded -- sending global
     * requests before the connection is established breaks the auth
     * state machine.
     */
    fun startKeepAlive(intervalMs: Long) {
        if (intervalMs <= 0) return
        scope.launch {
            try {
                while (isActive) {
                    delay(intervalMs)
                    val payload = SshBufferWriter()
                        .writeByte(SshMsgType.GLOBAL_REQUEST)
                        .writeUtf8("keepalive@openssh.com")
                        .writeBoolean(true)
                        .toByteArray()
                    transport?.sendPacket(payload)
                }
            } catch (_: Exception) {
                // transport dead or scope cancelled -- clean exit
            }
        }
    }

    /** Disconnect gracefully. Cancels all coroutines and closes the transport. */
    fun disconnect() {
        scope.cancel()
        try {
            // transport.disconnect() is suspend (writes a DISCONNECT packet);
            // use runBlocking since we are tearing down and this is best-effort.
            val xport = transport
            if (xport != null) {
                runBlocking { xport.disconnect() }
            }
        } catch (_: Exception) {}
        try { source?.close() } catch (_: Exception) {}
        try { socketChannel?.close() } catch (_: Exception) {}
        transport = null
        authenticator = null
        connection = null
        source = null
        packetIO = null
        socketChannel = null
    }

    /**
     * Ensure an [AsyncSshConnection] exists. Lazy-creates it so callers
     * can start the message loop after connect()+auth without needing to
     * openSession() first.
     */
    private fun ensureConnection() {
        if (connection == null) {
            connection = AsyncSshConnection(
                transport ?: throw IllegalStateException("Not connected")
            )
        }
    }

    /**
     * Ensure the message loop coroutine is running. The loop dispatches
     * incoming channel data, window adjusts, close notifications, etc.
     *
     * Blocks until the loop has actually started its first receivePacket()
     * call — without this, a subsequent openSession() can race ahead and
     * send CHANNEL_OPEN before anyone is reading the confirmation.
     *
     * Idempotent: calling when already running is a no-op.
     */
    private suspend fun ensureMessageLoop() {
        ensureConnection()
        if (messageLoopJob == null || messageLoopJob?.isActive != true) {
            val conn = connection!!
            val started = kotlinx.coroutines.CompletableDeferred<Unit>()
            messageLoopJob = scope.launch {
                started.complete(Unit)
                try {
                    conn.messageLoop()
                } catch (_: Exception) {
                }
            }
            started.await()
            kotlinx.coroutines.yield()
        }
    }
}
