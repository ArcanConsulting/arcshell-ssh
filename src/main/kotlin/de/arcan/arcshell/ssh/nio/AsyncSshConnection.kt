package de.arcan.arcshell.ssh.nio

import de.arcan.arcshell.ssh.SshChannelOpenFailure
import de.arcan.arcshell.ssh.SshMsgType
import de.arcan.arcshell.ssh.SshService
import de.arcan.arcshell.ssh.transport.SshBufferReader
import de.arcan.arcshell.ssh.transport.SshBufferWriter
import de.arcan.arcshell.ssh.transport.SshProtocolException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Async SSH connection protocol (RFC 4254). Manages channels, handles multiplexing,
 * window management, and channel lifecycle.
 *
 * Non-blocking coroutine-based replacement for
 * [de.arcan.arcshell.ssh.connection.SshConnection].
 *
 * Key differences from the blocking version:
 * - Channel open uses per-channel CompletableDeferred instead of a shared BlockingQueue
 * - Global request responses use a coroutine Channel
 * - No messageLoopActive flag — the message loop is always a coroutine
 * - No readChannelResponse() — all reads go through the message loop
 */
class AsyncSshConnection(private val transport: AsyncSshTransport) {

    private val channels = ConcurrentHashMap<Int, AsyncChannel>()
    private val nextLocalId = AtomicInteger(0)

    /**
     * Agent message handler for SSH agent forwarding. When set, inbound
     * "auth-agent@openssh.com" CHANNEL_OPEN requests from the server are
     * accepted and routed to this handler. When null, such requests are
     * rejected with SSH_OPEN_ADMINISTRATIVELY_PROHIBITED.
     */
    var agentHandler: AgentMessageHandler? = null

    /** Pending channel open responses, keyed by local channel ID. */
    private val channelOpenResponses = ConcurrentHashMap<Int, CompletableDeferred<ByteArray>>()

    /** Queue for REQUEST_SUCCESS/FAILURE responses. */
    private val globalRequestResponses = Channel<ByteArray>(Channel.UNLIMITED)

    /** Request the ssh-connection service. */
    suspend fun requestConnectionService() {
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
    suspend fun openSession(
        initialWindowSize: Int = DEFAULT_WINDOW_SIZE,
        maxPacketSize: Int = DEFAULT_MAX_PACKET_SIZE
    ): AsyncSessionChannel {
        val localId = nextLocalId.getAndIncrement()
        val channel = AsyncSessionChannel(localId, transport)
        channels[localId] = channel

        // Register deferred before sending to avoid race with message loop
        val deferred = CompletableDeferred<ByteArray>()
        channelOpenResponses[localId] = deferred

        // Send CHANNEL_OPEN
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.CHANNEL_OPEN)
            .writeUtf8("session")
            .writeUint32(localId)
            .writeUint32(initialWindowSize)
            .writeUint32(maxPacketSize)
            .toByteArray()
        transport.sendPacket(payload)

        // Await response from message loop
        val response = deferred.await()
        channelOpenResponses.remove(localId)

        when (response[0].toInt()) {
            SshMsgType.CHANNEL_OPEN_CONFIRMATION -> {
                val reader = SshBufferReader(response, 1)
                val recipientChannel = reader.readUint32().toInt() // our local id echoed back
                val senderChannel = reader.readUint32().toInt()    // server's channel id
                val remoteWindowSize = reader.readUint32()
                val remoteMaxPacketSize = reader.readUint32().toInt()

                channel.remoteId = senderChannel
                channel.remoteWindowSize.set(remoteWindowSize)
                channel.remoteMaxPacketSize = remoteMaxPacketSize
                channel.localWindowSize.set(initialWindowSize.toLong())
                channel.isOpen = true
                return channel
            }
            SshMsgType.CHANNEL_OPEN_FAILURE -> {
                channels.remove(localId)
                val reader = SshBufferReader(response, 1)
                reader.readUint32() // recipient channel
                val reasonCode = reader.readUint32().toInt()
                val description = reader.readUtf8()
                throw SshProtocolException("Channel open failed: reason=$reasonCode $description")
            }
            else -> {
                channels.remove(localId)
                throw SshProtocolException("Unexpected response to CHANNEL_OPEN: ${response[0]}")
            }
        }
    }

    /**
     * Open a direct TCP/IP channel for local port forwarding.
     */
    suspend fun openDirectTcp(
        remoteHost: String,
        remotePort: Int,
        originatorAddress: String = "127.0.0.1",
        originatorPort: Int = 0,
        initialWindowSize: Int = DEFAULT_WINDOW_SIZE,
        maxPacketSize: Int = DEFAULT_MAX_PACKET_SIZE
    ): AsyncChannel {
        val localId = nextLocalId.getAndIncrement()
        val channel = AsyncChannel(localId, transport)
        channels[localId] = channel

        // Register deferred before sending to avoid race with message loop
        val deferred = CompletableDeferred<ByteArray>()
        channelOpenResponses[localId] = deferred

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

        // Await response from message loop
        val response = deferred.await()
        channelOpenResponses.remove(localId)

        when (response[0].toInt()) {
            SshMsgType.CHANNEL_OPEN_CONFIRMATION -> {
                val reader = SshBufferReader(response, 1)
                reader.readUint32() // recipient
                channel.remoteId = reader.readUint32().toInt()
                channel.remoteWindowSize.set(reader.readUint32())
                channel.remoteMaxPacketSize = reader.readUint32().toInt()
                channel.localWindowSize.set(initialWindowSize.toLong())
                channel.isOpen = true
                return channel
            }
            SshMsgType.CHANNEL_OPEN_FAILURE -> {
                channels.remove(localId)
                val reader = SshBufferReader(response, 1)
                reader.readUint32()
                val reason = reader.readUint32().toInt()
                val desc = reader.readUtf8()
                throw SshProtocolException("Direct TCP channel failed: reason=$reason $desc")
            }
            else -> {
                channels.remove(localId)
                throw SshProtocolException("Unexpected: ${response[0]}")
            }
        }
    }

    /** Request remote port forwarding (server listens, we connect back). */
    suspend fun requestRemoteForward(bindAddress: String, bindPort: Int): Boolean {
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.GLOBAL_REQUEST)
            .writeUtf8("tcpip-forward")
            .writeBoolean(true) // want reply
            .writeUtf8(bindAddress)
            .writeUint32(bindPort)
            .toByteArray()
        transport.sendPacket(payload)

        val response = globalRequestResponses.receive()
        return response[0].toInt() == SshMsgType.REQUEST_SUCCESS
    }

    /**
     * Main message loop. Reads packets from the transport and dispatches them
     * to the appropriate channel or response queue. Runs until the coroutine
     * is cancelled or a DISCONNECT is received.
     */
    suspend fun messageLoop() {
        try {
            while (currentCoroutineContext().isActive) {
                val payload = transport.receivePacket()
                if (!processMessage(payload)) break
            }
        } finally {
            channels.values.forEach { it.onClose() }
            channels.clear()
        }
    }

    /**
     * Process a single incoming message. Dispatches data/eof/close to the
     * appropriate channel, and channel open/global request responses to
     * their waiting coroutines.
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
            SshMsgType.CHANNEL_OPEN -> {
                // Server-initiated channel open (e.g. agent forwarding)
                handleInboundChannelOpen(reader)
            }
            SshMsgType.CHANNEL_OPEN_CONFIRMATION -> {
                // Find the waiting coroutine by recipient channel ID (our local ID)
                val recipientId = SshBufferReader(payload, 1).readUint32().toInt()
                channelOpenResponses[recipientId]?.complete(payload)
            }
            SshMsgType.CHANNEL_OPEN_FAILURE -> {
                // Find the waiting coroutine by recipient channel ID (our local ID)
                val recipientId = SshBufferReader(payload, 1).readUint32().toInt()
                channelOpenResponses[recipientId]?.complete(payload)
            }
            SshMsgType.REQUEST_SUCCESS, SshMsgType.REQUEST_FAILURE -> {
                globalRequestResponses.trySend(payload)
            }
            SshMsgType.GLOBAL_REQUEST -> {
                val requestName = reader.readUtf8()
                val wantReply = reader.readBoolean()
                if (wantReply) {
                    transport.sendPacketBlocking(
                        SshBufferWriter().writeByte(SshMsgType.REQUEST_FAILURE).toByteArray()
                    )
                }
            }
            SshMsgType.DISCONNECT -> return false
            else -> {
                // Unknown/unhandled (e.g. EXT_INFO type 7) — silently skip
            }
        }
        return true
    }

    /**
     * Handle a server-initiated CHANNEL_OPEN. Currently supports
     * "auth-agent@openssh.com" for SSH agent forwarding.
     *
     * The reader is positioned after the message type byte (offset 1),
     * so we read the channel type, sender channel, window size, and
     * max packet size in order per RFC 4254 SS5.1.
     */
    private fun handleInboundChannelOpen(reader: SshBufferReader) {
        val channelType = reader.readUtf8()
        val senderChannel = reader.readUint32().toInt()
        val initialWindowSize = reader.readUint32()
        val maxPacketSize = reader.readUint32().toInt()

        val handler = agentHandler
        if (channelType == "auth-agent@openssh.com" && handler != null) {
            val localId = nextLocalId.getAndIncrement()
            val channel = AsyncAgentChannel(localId, transport, handler)
            channel.remoteId = senderChannel
            channel.remoteWindowSize.set(initialWindowSize)
            channel.remoteMaxPacketSize = maxPacketSize
            channel.localWindowSize.set(DEFAULT_WINDOW_SIZE.toLong())
            channel.isOpen = true
            channels[localId] = channel

            // Send CHANNEL_OPEN_CONFIRMATION
            transport.sendPacketBlocking(
                SshBufferWriter()
                    .writeByte(SshMsgType.CHANNEL_OPEN_CONFIRMATION)
                    .writeUint32(senderChannel)       // recipient channel (server's ID)
                    .writeUint32(localId)              // sender channel (our local ID)
                    .writeUint32(DEFAULT_WINDOW_SIZE)  // initial window size
                    .writeUint32(DEFAULT_MAX_PACKET_SIZE) // max packet size
                    .toByteArray()
            )
        } else {
            // Reject unsupported or disabled channel types
            transport.sendPacketBlocking(
                SshBufferWriter()
                    .writeByte(SshMsgType.CHANNEL_OPEN_FAILURE)
                    .writeUint32(senderChannel)
                    .writeUint32(SshChannelOpenFailure.ADMINISTRATIVELY_PROHIBITED)
                    .writeUtf8("Channel type not supported")
                    .writeUtf8("") // language tag
                    .toByteArray()
            )
        }
    }

    fun getChannel(localId: Int): AsyncChannel? = channels[localId]

    companion object {
        const val DEFAULT_WINDOW_SIZE = 2 * 1024 * 1024 // 2 MB
        const val DEFAULT_MAX_PACKET_SIZE = 32768         // 32 KB
    }
}
