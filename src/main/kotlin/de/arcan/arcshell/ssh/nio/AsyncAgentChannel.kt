package de.arcan.arcshell.ssh.nio

import de.arcan.arcshell.ssh.SshMsgType
import de.arcan.arcshell.ssh.transport.SshBufferWriter
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Handler interface for SSH agent protocol messages.
 * Implemented by the app layer to provide key listing and signing.
 */
interface AgentMessageHandler {
    /**
     * Handle an incoming SSH agent message.
     * @param type the agent message opcode
     * @param data the message body (after the type byte)
     * @return the full response bytes (type byte + body), which will be
     *         wrapped in a length-prefixed agent message and sent back
     */
    suspend fun handleAgentMessage(type: Int, data: ByteArray): ByteArray
}

/**
 * SSH agent channel (auth-agent@openssh.com). Handles the SSH agent protocol
 * when the server opens a channel back to the client for agent forwarding.
 *
 * Each agent message has the format: uint32 length + byte type + byte[] body.
 * This channel buffers incoming data, parses complete messages, dispatches
 * them to [messageHandler], and sends the response back through the channel.
 */
class AsyncAgentChannel(
    localId: Int,
    transport: AsyncSshTransport,
    private val messageHandler: AgentMessageHandler
) : AsyncChannel(localId, transport) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Accumulation buffer for incoming agent protocol data. */
    private var buffer = ByteArray(0)

    companion object {
        const val SSH_AGENT_FAILURE = 5
    }

    /**
     * Called by AsyncSshConnection when CHANNEL_DATA arrives.
     * Buffers bytes and processes complete agent messages.
     */
    override fun onData(data: ByteArray) {
        // Append to buffer
        buffer = buffer + data

        // Process all complete messages in the buffer
        while (true) {
            // Need at least 4 bytes for the length prefix
            if (buffer.size < 4) break

            val msgLen = ((buffer[0].toInt() and 0xFF) shl 24) or
                ((buffer[1].toInt() and 0xFF) shl 16) or
                ((buffer[2].toInt() and 0xFF) shl 8) or
                (buffer[3].toInt() and 0xFF)

            // Need the full message (4 byte length + msgLen bytes)
            if (buffer.size < 4 + msgLen) break
            if (msgLen < 1) {
                // Invalid message — skip the 4-byte header
                buffer = buffer.copyOfRange(4, buffer.size)
                continue
            }

            val msgType = buffer[4].toInt() and 0xFF
            val msgBody = if (msgLen > 1) buffer.copyOfRange(5, 4 + msgLen) else ByteArray(0)

            // Consume this message from the buffer
            buffer = if (buffer.size > 4 + msgLen) {
                buffer.copyOfRange(4 + msgLen, buffer.size)
            } else {
                ByteArray(0)
            }

            // Dispatch to handler asynchronously and send response
            scope.launch {
                try {
                    val response = messageHandler.handleAgentMessage(msgType, msgBody)
                    sendAgentResponse(response)
                } catch (_: Exception) {
                    sendAgentResponse(byteArrayOf(SSH_AGENT_FAILURE.toByte()))
                }
            }
        }
    }

    /**
     * Send an agent protocol response through the channel.
     * Wraps the response in length-prefixed format.
     */
    private suspend fun sendAgentResponse(response: ByteArray) {
        val lengthPrefixed = SshBufferWriter()
            .writeUint32(response.size)
            .writeBytes(response)
            .toByteArray()

        val payload = SshBufferWriter()
            .writeByte(SshMsgType.CHANNEL_DATA)
            .writeUint32(remoteId)
            .writeString(lengthPrefixed)
            .toByteArray()
        transport.sendPacket(payload)
    }
}
