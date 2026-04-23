package de.arcan.arcshell.ssh.connection

import de.arcan.arcshell.ssh.SshMsgType
import de.arcan.arcshell.ssh.SshService
import de.arcan.arcshell.ssh.transport.SshBufferReader
import de.arcan.arcshell.ssh.transport.SshBufferWriter
import de.arcan.arcshell.ssh.transport.SshProtocolException
import de.arcan.arcshell.ssh.transport.SshTransport
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * SSH connection protocol (RFC 4254). Manages channels, handles multiplexing,
 * window management, and channel lifecycle.
 */
class SshConnection(private val transport: SshTransport) {

    private val channels = ConcurrentHashMap<Int, Channel>()
    private val nextLocalId = AtomicInteger(0)

    /** True when processMessages() is running — channel opens use the response queue. */
    val messageLoopActive = AtomicBoolean(false)

    /** Queue for CHANNEL_OPEN_CONFIRMATION/FAILURE responses when message loop is active. */
    private val channelOpenResponses = LinkedBlockingQueue<ByteArray>()

    /** Queue for REQUEST_SUCCESS/FAILURE responses when message loop is active. */
    private val globalRequestResponses = LinkedBlockingQueue<ByteArray>()

    /** Request the ssh-connection service. */
    fun requestConnectionService() {
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.SERVICE_REQUEST)
            .writeUtf8(SshService.CONNECTION)
            .toByteArray()
        transport.sendPacket(payload)

        val response = transport.receivePacket()
        if (response[0].toInt() != SshMsgType.SERVICE_ACCEPT) {
            throw SshProtocolException("Service request for ${SshService.CONNECTION} rejected")
        }
    }

    /**
     * Open a new session channel (for shell, exec, or subsystem).
     *
     * @param initialWindowSize how many bytes the server may send before we must adjust
     * @param maxPacketSize maximum data packet size within this channel
     */
    fun openSession(
        initialWindowSize: Int = DEFAULT_WINDOW_SIZE,
        maxPacketSize: Int = DEFAULT_MAX_PACKET_SIZE
    ): SessionChannel {
        val localId = nextLocalId.getAndIncrement()
        val channel = SessionChannel(localId, transport)

        // Send CHANNEL_OPEN
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.CHANNEL_OPEN)
            .writeUtf8("session")
            .writeUint32(localId)
            .writeUint32(initialWindowSize)
            .writeUint32(maxPacketSize)
            .toByteArray()
        transport.sendPacket(payload)

        // Read response: direct from transport if pre-message-loop, else via queue
        val response = if (messageLoopActive.get()) {
            channelOpenResponses.take() // blocks until processMessage dispatches it
        } else {
            readChannelResponse()
        }
        when (response[0].toInt()) {
            SshMsgType.CHANNEL_OPEN_CONFIRMATION -> {
                val reader = SshBufferReader(response, 1)
                val recipientChannel = reader.readUint32().toInt() // our local id echoed back
                val senderChannel = reader.readUint32().toInt()    // server's channel id
                val remoteWindowSize = reader.readUint32()
                val remoteMaxPacketSize = reader.readUint32().toInt()

                channel.remoteId = senderChannel
                channel.remoteWindowSize = remoteWindowSize
                channel.remoteMaxPacketSize = remoteMaxPacketSize
                channel.localWindowSize = initialWindowSize.toLong()
                channel.isOpen = true
                channels[localId] = channel
                return channel
            }
            SshMsgType.CHANNEL_OPEN_FAILURE -> {
                val reader = SshBufferReader(response, 1)
                reader.readUint32() // recipient channel
                val reasonCode = reader.readUint32().toInt()
                val description = reader.readUtf8()
                throw SshProtocolException("Channel open failed: reason=$reasonCode $description")
            }
            else -> throw SshProtocolException("Unexpected response to CHANNEL_OPEN: ${response[0]}")
        }
    }

    /**
     * Open a direct TCP/IP channel for local port forwarding.
     */
    fun openDirectTcp(
        remoteHost: String,
        remotePort: Int,
        originatorAddress: String = "127.0.0.1",
        originatorPort: Int = 0,
        initialWindowSize: Int = DEFAULT_WINDOW_SIZE,
        maxPacketSize: Int = DEFAULT_MAX_PACKET_SIZE
    ): Channel {
        val localId = nextLocalId.getAndIncrement()
        val channel = Channel(localId, transport)

        val payload = SshBufferWriter()
            .writeByte(SshMsgType.CHANNEL_OPEN)
            .writeUtf8("direct-tcpip")
            .writeUint32(localId)
            .writeUint32(initialWindowSize)
            .writeUint32(maxPacketSize)
            .writeUtf8(remoteHost)
            .writeUint32(remotePort)
            .writeUtf8(originatorAddress)
            .writeUint32(originatorPort)
            .toByteArray()
        transport.sendPacket(payload)

        val response = if (messageLoopActive.get()) channelOpenResponses.take() else readChannelResponse()
        when (response[0].toInt()) {
            SshMsgType.CHANNEL_OPEN_CONFIRMATION -> {
                val reader = SshBufferReader(response, 1)
                reader.readUint32() // recipient
                channel.remoteId = reader.readUint32().toInt()
                channel.remoteWindowSize = reader.readUint32()
                channel.remoteMaxPacketSize = reader.readUint32().toInt()
                channel.localWindowSize = initialWindowSize.toLong()
                channel.isOpen = true
                channels[localId] = channel
                return channel
            }
            SshMsgType.CHANNEL_OPEN_FAILURE -> {
                val reader = SshBufferReader(response, 1)
                reader.readUint32()
                val reason = reader.readUint32().toInt()
                val desc = reader.readUtf8()
                throw SshProtocolException("Direct TCP channel failed: reason=$reason $desc")
            }
            else -> throw SshProtocolException("Unexpected: ${response[0]}")
        }
    }

    /** Request remote port forwarding (server listens, we connect back). */
    fun requestRemoteForward(bindAddress: String, bindPort: Int): Boolean {
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.GLOBAL_REQUEST)
            .writeUtf8("tcpip-forward")
            .writeBoolean(true) // want reply
            .writeUtf8(bindAddress)
            .writeUint32(bindPort)
            .toByteArray()
        transport.sendPacket(payload)

        val response = if (messageLoopActive.get()) {
            globalRequestResponses.take()
        } else {
            transport.receivePacket()
        }
        return response[0].toInt() == SshMsgType.REQUEST_SUCCESS
    }

    /**
     * Process incoming channel messages. Call this in a loop from the
     * reader thread. Dispatches data/eof/close to the appropriate channel.
     *
     * @return false if the connection should be closed
     */
    fun processMessage(payload: ByteArray): Boolean {
        val msgType = payload[0].toInt()
        val reader = SshBufferReader(payload, 1)

        when (msgType) {
            SshMsgType.CHANNEL_DATA -> {
                val channelId = reader.readUint32().toInt()
                val data = reader.readString()
                channels[channelId]?.onData(data)
            }
            SshMsgType.CHANNEL_EXTENDED_DATA -> {
                val channelId = reader.readUint32().toInt()
                val dataType = reader.readUint32().toInt() // 1 = stderr
                val data = reader.readString()
                channels[channelId]?.onExtendedData(dataType, data)
            }
            SshMsgType.CHANNEL_WINDOW_ADJUST -> {
                val channelId = reader.readUint32().toInt()
                val bytesToAdd = reader.readUint32()
                channels[channelId]?.adjustRemoteWindow(bytesToAdd)
            }
            SshMsgType.CHANNEL_EOF -> {
                val channelId = reader.readUint32().toInt()
                channels[channelId]?.onEof()
            }
            SshMsgType.CHANNEL_CLOSE -> {
                val channelId = reader.readUint32().toInt()
                channels[channelId]?.onClose()
                channels.remove(channelId)
            }
            SshMsgType.CHANNEL_REQUEST -> {
                val channelId = reader.readUint32().toInt()
                val requestType = reader.readUtf8()
                val wantReply = reader.readBoolean()
                channels[channelId]?.onRequest(requestType, wantReply, reader)
            }
            SshMsgType.CHANNEL_SUCCESS -> {
                val channelId = reader.readUint32().toInt()
                channels[channelId]?.onRequestSuccess()
            }
            SshMsgType.CHANNEL_FAILURE -> {
                val channelId = reader.readUint32().toInt()
                channels[channelId]?.onRequestFailure()
            }
            SshMsgType.CHANNEL_OPEN_CONFIRMATION, SshMsgType.CHANNEL_OPEN_FAILURE -> {
                // Dispatched to openSession/openDirectTcp waiting on the queue
                channelOpenResponses.put(payload)
            }
            SshMsgType.REQUEST_SUCCESS, SshMsgType.REQUEST_FAILURE -> {
                // Dispatched to requestRemoteForward waiting on the queue
                globalRequestResponses.put(payload)
            }
            SshMsgType.GLOBAL_REQUEST -> {
                val requestName = reader.readUtf8()
                val wantReply = reader.readBoolean()
                if (wantReply) {
                    transport.sendPacket(SshBufferWriter().writeByte(SshMsgType.REQUEST_FAILURE).toByteArray())
                }
            }
            SshMsgType.DISCONNECT -> return false
            else -> {
                // Unknown/unhandled (e.g. EXT_INFO type 7) — silently skip
            }
        }
        return true
    }

    fun getChannel(localId: Int): Channel? = channels[localId]

    /**
     * Read packets until we get a channel-level response (OPEN_CONFIRMATION, OPEN_FAILURE).
     * Handles GLOBAL_REQUEST and other non-channel messages that the server may send
     * between auth and the first channel open (e.g. ext-info, no-more-sessions).
     */
    private fun readChannelResponse(): ByteArray {
        while (true) {
            val response = transport.receivePacket()
            when (response[0].toInt()) {
                SshMsgType.CHANNEL_OPEN_CONFIRMATION,
                SshMsgType.CHANNEL_OPEN_FAILURE -> return response
                SshMsgType.GLOBAL_REQUEST -> {
                    // Server global request (e.g. hostkeys-00@openssh.com) — reply if wanted
                    val reader = SshBufferReader(response, 1)
                    reader.readUtf8() // request name
                    val wantReply = reader.readBoolean()
                    if (wantReply) {
                        transport.sendPacket(
                            SshBufferWriter().writeByte(SshMsgType.REQUEST_FAILURE).toByteArray()
                        )
                    }
                }
                else -> {
                    // Skip unknown messages (EXT_INFO type 7, etc.)
                }
            }
        }
    }

    companion object {
        const val DEFAULT_WINDOW_SIZE = 2 * 1024 * 1024 // 2 MB
        const val DEFAULT_MAX_PACKET_SIZE = 32768         // 32 KB
    }
}
