package de.arcan.arcshell.ssh

import de.arcan.arcshell.ssh.auth.AuthResult
import de.arcan.arcshell.ssh.auth.Prompt
import de.arcan.arcshell.ssh.auth.SshAuthenticator
import de.arcan.arcshell.ssh.connection.Channel
import de.arcan.arcshell.ssh.connection.SessionChannel
import de.arcan.arcshell.ssh.connection.SshConnection
import de.arcan.arcshell.ssh.transport.HostKeyVerifier
import de.arcan.arcshell.ssh.transport.SshProtocolException
import de.arcan.arcshell.ssh.transport.SshTransport
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Configuration for an SSH connection.
 */
data class SshConfig(
    val hostname: String,
    val port: Int = 22,
    val username: String,
    val connectTimeoutMs: Int = 10_000,
    val keepAliveIntervalMs: Int = 0
)

/**
 * High-level SSH client. Provides a simple API for connecting, authenticating,
 * and opening shells/exec channels.
 *
 * Usage:
 * ```
 * val client = SshClient(config, hostKeyVerifier)
 * client.connect()
 * client.authPassword("mypassword")
 * val session = client.openSession()
 * session.requestPty()
 * session.requestShell()
 * // read/write data via session.read() / session.write()
 * client.disconnect()
 * ```
 */
class SshClient(
    private val config: SshConfig,
    private val hostKeyVerifier: HostKeyVerifier
) {
    private var socket: Socket? = null
    private var transport: SshTransport? = null
    private var authenticator: SshAuthenticator? = null
    private var connection: SshConnection? = null

    /** True if connected and handshake completed. */
    val isConnected: Boolean get() = transport != null && socket?.isConnected == true

    /** The SSH transport layer (for advanced use). */
    val transportLayer: SshTransport? get() = transport

    /** The negotiated KEX algorithm name (for display). */
    val kexAlgorithm: String get() = transport?.kexAlgorithmName ?: "none"

    /** All negotiated algorithm names. */
    val negotiatedAlgorithms: de.arcan.arcshell.ssh.transport.NegotiatedAlgorithms?
        get() = transport?.negotiatedAlgorithms

    /** The server's version string. */
    val serverVersion: String get() = transport?.serverVersion ?: ""

    /**
     * Connect to the SSH server and perform the transport-layer handshake
     * (version exchange, KEXINIT, key exchange, NEWKEYS).
     *
     * After this, the connection is encrypted but not yet authenticated.
     */
    fun connect() {
        val sock = Socket()
        sock.tcpNoDelay = true
        sock.soTimeout = config.connectTimeoutMs // timeout for handshake only
        sock.connect(InetSocketAddress(config.hostname, config.port), config.connectTimeoutMs)

        if (config.keepAliveIntervalMs > 0) {
            sock.keepAlive = true
        }

        socket = sock
        val input = sock.getInputStream()
        val output = sock.getOutputStream()

        val xport = SshTransport(input, output, hostKeyVerifier)
        xport.performHandshake(input, output)
        transport = xport

        authenticator = SshAuthenticator(xport)
        authenticator!!.requestAuthService()

        // Remove read timeout after handshake — the session can idle indefinitely
        sock.soTimeout = 0
    }

    /** Authenticate with password. */
    fun authPassword(password: String): AuthResult {
        return authenticator?.authPassword(config.username, password)
            ?: throw IllegalStateException("Not connected")
    }

    /**
     * Authenticate with a public key.
     *
     * @param keyType e.g. "ssh-ed25519"
     * @param publicKeyBlob SSH wire-format public key
     * @param signer signs the auth data with the corresponding private key
     */
    fun authPublicKey(
        keyType: String,
        publicKeyBlob: ByteArray,
        signer: (ByteArray) -> ByteArray
    ): AuthResult {
        return authenticator?.authPublicKey(config.username, keyType, publicKeyBlob, signer)
            ?: throw IllegalStateException("Not connected")
    }

    /**
     * Authenticate with keyboard-interactive (2FA, TOTP, etc.).
     *
     * @param responder callback that receives prompts and returns answers
     */
    fun authKeyboardInteractive(
        responder: (name: String, instruction: String, prompts: List<Prompt>) -> List<String>
    ): AuthResult {
        return authenticator?.authKeyboardInteractive(config.username, responder)
            ?: throw IllegalStateException("Not connected")
    }

    /** Query available auth methods (sends "none" auth). */
    fun queryAuthMethods(): List<String> {
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
     */
    fun openSession(): SessionChannel {
        ensureConnection()
        return connection!!.openSession()
    }

    /**
     * Open a direct TCP channel for local port forwarding.
     */
    fun openDirectTcp(remoteHost: String, remotePort: Int): Channel {
        ensureConnection()
        return connection!!.openDirectTcp(remoteHost, remotePort)
    }

    /** Request remote port forwarding. */
    fun requestRemoteForward(bindAddress: String, bindPort: Int): Boolean {
        ensureConnection()
        return connection!!.requestRemoteForward(bindAddress, bindPort)
    }

    /**
     * Start the message processing loop. This should run on a dedicated thread.
     * Dispatches incoming channel data, window adjusts, close notifications etc.
     *
     * Returns when the connection is closed.
     */
    fun processMessages() {
        val conn = connection ?: throw IllegalStateException("Not connected")
        val xport = transport ?: throw IllegalStateException("Not connected")
        conn.messageLoopActive.set(true)
        try {
            while (true) {
                val payload = xport.receivePacket()
                if (!conn.processMessage(payload)) break
            }
        } catch (e: SshProtocolException) {
            if (e.message?.contains("disconnected") != true) throw e
        } catch (e: IOException) {
            // Connection closed
        } finally {
            conn.messageLoopActive.set(false)
        }
    }

    /**
     * Spawn a daemon thread running [processMessages] and block until that
     * thread has reached the receive loop. Callers that need the message loop
     * must use this method rather than starting [processMessages] themselves
     * — otherwise a subsequent [openSession] racing ahead of the loop reads
     * the OPEN_CONFIRMATION directly off the transport (because
     * `messageLoopActive` is still false), and the now-started loop consumes
     * the NEXT packet (e.g. the server's CHANNEL_REQUEST reply). The caller
     * later blocks forever on `requestResults.take()` because the reply has
     * been silently dropped by the unrelated [readChannelResponse] path.
     *
     * Idempotent: starting twice is a no-op (guarded by `messageLoopActive`).
     */
    fun startMessageLoop(threadName: String = "ssh-msg-${config.hostname}"): Thread {
        // Lazy-create the SshConnection so callers can start the loop directly
        // after connect()+auth without needing to openSession() first just to
        // materialise `connection`.
        ensureConnection()
        val conn = connection ?: throw IllegalStateException("Not connected")
        if (conn.messageLoopActive.get()) {
            // Already running; return a placeholder thread ref the caller
            // can't interact with in a harmful way.
            return Thread.currentThread()
        }
        val started = java.util.concurrent.CountDownLatch(1)
        val t = Thread({
            // Set the flag BEFORE the first receivePacket so any concurrent
            // openSession sees messageLoopActive=true and routes through the
            // queue instead of doing a direct read.
            conn.messageLoopActive.set(true)
            started.countDown()
            val xport = transport ?: return@Thread
            try {
                while (true) {
                    val payload = xport.receivePacket()
                    if (!conn.processMessage(payload)) break
                }
            } catch (e: SshProtocolException) {
                if (e.message?.contains("disconnected") != true) throw e
            } catch (_: IOException) {
                // Connection closed
            } finally {
                conn.messageLoopActive.set(false)
            }
        }, threadName)
        t.isDaemon = true
        t.start()
        // Wait up to 2 s for the loop to be live. Missing this is a bug, not
        // a timeout case — the socket is already connected; scheduling the
        // thread is local CPU work.
        check(started.await(2, java.util.concurrent.TimeUnit.SECONDS)) {
            "ssh message loop failed to start within 2 s (scheduling starved?)"
        }
        return t
    }

    /** Disconnect gracefully. */
    fun disconnect() {
        stopKeepAlive()
        try {
            transport?.disconnect()
        } catch (_: Exception) {
            // Best effort
        }
        try {
            socket?.close()
        } catch (_: Exception) {
            // Best effort
        }
        transport = null
        authenticator = null
        connection = null
        socket = null
    }

    /** Thread that periodically emits SSH keep-alive pings. `null` when
     *  no keep-alive is running (interval 0 or disconnect). */
    private var keepAliveThread: Thread? = null

    /**
     * Starts an SSH-level keep-alive. Emits an
     * `SSH_MSG_GLOBAL_REQUEST` "keepalive@openssh.com" with
     * `want_reply=true` every [intervalMs] milliseconds. This is the
     * mechanism OpenSSH's `ClientAliveInterval` check expects: the
     * server sees the traffic and responds with
     * `SSH_MSG_REQUEST_FAILURE`, which proves both ends are alive.
     *
     * Call this AFTER authentication has succeeded — sending global
     * requests before the connection is established breaks the auth
     * state machine. TerminalSession wires it from its auth-success
     * callback.
     *
     * A stable 20–30 s interval survives almost every real-world
     * idle window (OS lock/PIN, Doze nap) because a
     * PARTIAL_WAKE_LOCK on SessionService keeps the CPU + this
     * thread scheduled even when the screen is off. Without the
     * wake-lock the timer would stop firing during deep idle and the
     * server-side `ClientAliveInterval` (often 60 s) would still fire
     * first.
     */
    fun startKeepAlive(intervalMs: Long) {
        stopKeepAlive()
        if (intervalMs <= 0) return
        val t = transport ?: return
        val thread = Thread({
            try {
                while (!Thread.currentThread().isInterrupted) {
                    Thread.sleep(intervalMs)
                    val payload = de.arcan.arcshell.ssh.transport.SshBufferWriter()
                        .writeByte(SshMsgType.GLOBAL_REQUEST)
                        .writeUtf8("keepalive@openssh.com")
                        .writeBoolean(true)
                        .toByteArray()
                    // sendPacket is thread-safe (synchronized on
                    // PacketIO.output) so we don't race the reader.
                    // Server's reply is consumed by SshConnection's
                    // message loop and discarded (unknown request id).
                    t.sendPacket(payload)
                }
            } catch (_: InterruptedException) {
                // clean shutdown
            } catch (_: Exception) {
                // transport dead — disconnect will clean up
            }
        }, "ssh-keepalive")
        thread.isDaemon = true
        keepAliveThread = thread
        thread.start()
    }

    private fun stopKeepAlive() {
        keepAliveThread?.interrupt()
        keepAliveThread = null
    }

    private fun ensureConnection() {
        if (connection == null) {
            connection = SshConnection(transport ?: throw IllegalStateException("Not connected"))
        }
    }
}
