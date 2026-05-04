package de.arcan.arcshell.ssh.nio

import de.arcan.arcshell.ssh.SshMsgType
import de.arcan.arcshell.ssh.transport.SshBufferReader
import de.arcan.arcshell.ssh.transport.SshBufferWriter

/**
 * Async SSH session channel (RFC 4254 SS6). Supports shell, exec, subsystem requests
 * plus PTY allocation and environment variables.
 *
 * Non-blocking coroutine-based replacement for
 * [de.arcan.arcshell.ssh.connection.SessionChannel].
 */
class AsyncSessionChannel(
    localId: Int,
    transport: AsyncSshTransport
) : AsyncChannel(localId, transport) {

    var exitStatus: Int? = null
        private set
    var exitSignal: String? = null
        private set

    /**
     * Request a pseudo-terminal (PTY) on this session.
     * Must be called before requestShell/requestExec.
     */
    suspend fun requestPty(
        term: String = "xterm-256color",
        columns: Int = 80,
        rows: Int = 24,
        pixelWidth: Int = 0,
        pixelHeight: Int = 0
    ): Boolean {
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.CHANNEL_REQUEST)
            .writeUint32(remoteId)
            .writeUtf8("pty-req")
            .writeBoolean(true) // want reply
            .writeUtf8(term)
            .writeUint32(columns)
            .writeUint32(rows)
            .writeUint32(pixelWidth)
            .writeUint32(pixelHeight)
            .writeString(encodeTerminalModes())
            .toByteArray()
        transport.sendPacket(payload)
        return waitRequestReply()
    }

    /** Change the terminal window size (SIGWINCH). */
    suspend fun windowChange(columns: Int, rows: Int, pixelWidth: Int = 0, pixelHeight: Int = 0) {
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.CHANNEL_REQUEST)
            .writeUint32(remoteId)
            .writeUtf8("window-change")
            .writeBoolean(false) // no reply
            .writeUint32(columns)
            .writeUint32(rows)
            .writeUint32(pixelWidth)
            .writeUint32(pixelHeight)
            .toByteArray()
        transport.sendPacket(payload)
    }

    /** Set an environment variable on the remote session. */
    suspend fun setEnv(name: String, value: String): Boolean {
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.CHANNEL_REQUEST)
            .writeUint32(remoteId)
            .writeUtf8("env")
            .writeBoolean(true)
            .writeUtf8(name)
            .writeUtf8(value)
            .toByteArray()
        transport.sendPacket(payload)
        return waitRequestReply()
    }

    /** Request a login shell. */
    suspend fun requestShell(): Boolean {
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.CHANNEL_REQUEST)
            .writeUint32(remoteId)
            .writeUtf8("shell")
            .writeBoolean(true)
            .toByteArray()
        transport.sendPacket(payload)
        return waitRequestReply()
    }

    /** Execute a single command. */
    suspend fun requestExec(command: String): Boolean {
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.CHANNEL_REQUEST)
            .writeUint32(remoteId)
            .writeUtf8("exec")
            .writeBoolean(true)
            .writeUtf8(command)
            .toByteArray()
        transport.sendPacket(payload)
        return waitRequestReply()
    }

    /** Start a subsystem (e.g., "sftp"). */
    suspend fun requestSubsystem(subsystem: String): Boolean {
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.CHANNEL_REQUEST)
            .writeUint32(remoteId)
            .writeUtf8("subsystem")
            .writeBoolean(true)
            .writeUtf8(subsystem)
            .toByteArray()
        transport.sendPacket(payload)
        return waitRequestReply()
    }

    /**
     * Request SSH agent forwarding on this session.
     * Must be called before requestShell/requestExec.
     * The server will open "auth-agent@openssh.com" channels back to us
     * when it needs key operations.
     */
    suspend fun requestAgentForwarding(): Boolean {
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.CHANNEL_REQUEST)
            .writeUint32(remoteId)
            .writeUtf8("auth-agent-req@openssh.com")
            .writeBoolean(true) // want reply
            .toByteArray()
        transport.sendPacket(payload)
        return waitRequestReply()
    }

    /** Send a signal to the remote process. */
    suspend fun sendSignal(signal: String) {
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.CHANNEL_REQUEST)
            .writeUint32(remoteId)
            .writeUtf8("signal")
            .writeBoolean(false)
            .writeUtf8(signal)
            .toByteArray()
        transport.sendPacket(payload)
    }

    override fun onRequest(requestType: String, wantReply: Boolean, reader: SshBufferReader) {
        when (requestType) {
            "exit-status" -> {
                exitStatus = reader.readUint32().toInt()
            }
            "exit-signal" -> {
                exitSignal = reader.readUtf8()
            }
        }
        if (wantReply) {
            val payload = SshBufferWriter()
                .writeByte(SshMsgType.CHANNEL_SUCCESS)
                .writeUint32(remoteId)
                .toByteArray()
            transport.sendPacketBlocking(payload)
        }
    }

    /** Encode terminal modes (RFC 4254 SS8). Minimal: just send TTY_OP_END. */
    private fun encodeTerminalModes(): ByteArray {
        return byteArrayOf(0) // TTY_OP_END
    }
}
