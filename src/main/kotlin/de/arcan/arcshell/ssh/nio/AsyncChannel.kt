package de.arcan.arcshell.ssh.nio

import de.arcan.arcshell.ssh.SshMsgType
import de.arcan.arcshell.ssh.transport.SshBufferReader
import de.arcan.arcshell.ssh.transport.SshBufferWriter
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import java.util.concurrent.atomic.AtomicLong

/**
 * Async SSH channel (RFC 4254 SS5). Base class for session, direct-tcpip, etc.
 * Non-blocking coroutine-based replacement for [de.arcan.arcshell.ssh.connection.Channel].
 *
 * Key differences from the blocking version:
 * - Data queues use coroutine Channels instead of LinkedBlockingQueue
 * - Window sizes use AtomicLong to fix race conditions
 * - write() suspends on a CompletableDeferred when the window is exhausted
 * - read()/readExtended() are suspend functions (no timeout)
 */
open class AsyncChannel(
    val localId: Int,
    protected val transport: AsyncSshTransport
) {
    var remoteId: Int = -1
    val remoteWindowSize = AtomicLong(0)
    var remoteMaxPacketSize: Int = 0
    val localWindowSize = AtomicLong(0)
    var isOpen: Boolean = false
    var isEof: Boolean = false
        private set

    /** Data received from the remote side (stdout). */
    private val dataChannel = Channel<ByteArray>(Channel.UNLIMITED)

    /** Extended data (stderr). */
    private val extDataChannel = Channel<ByteArray>(Channel.UNLIMITED)

    /** Pending channel request results. */
    private val requestResults = Channel<Boolean>(Channel.UNLIMITED)

    /** Signal for writers waiting on window space. */
    @Volatile
    var windowSignal = CompletableDeferred<Unit>()

    /** Called by AsyncSshConnection when CHANNEL_DATA arrives. */
    fun onData(data: ByteArray) {
        dataChannel.trySend(data)
    }

    /** Called by AsyncSshConnection when CHANNEL_EXTENDED_DATA arrives. */
    fun onExtendedData(dataType: Int, data: ByteArray) {
        extDataChannel.trySend(data)
    }

    /** Called by AsyncSshConnection when CHANNEL_WINDOW_ADJUST arrives. */
    fun adjustRemoteWindow(bytesToAdd: Long) {
        remoteWindowSize.addAndGet(bytesToAdd)
        val signal = windowSignal
        windowSignal = CompletableDeferred()
        signal.complete(Unit)
    }

    fun onEof() {
        isEof = true
        dataChannel.trySend(ByteArray(0))    // signal EOF to stdout reader
        extDataChannel.trySend(ByteArray(0)) // signal EOF to stderr reader — without this,
                                              // any coroutine suspended on readExtended() leaks
                                              // forever (commands without stderr never push
                                              // anything onto extDataChannel otherwise)
    }

    fun onClose() {
        isOpen = false
        isEof = true
        dataChannel.trySend(ByteArray(0))
        extDataChannel.trySend(ByteArray(0))
        dataChannel.close()
        extDataChannel.close()
    }

    open fun onRequest(requestType: String, wantReply: Boolean, reader: SshBufferReader) {
        if (wantReply) {
            sendChannelFailure()
        }
    }

    fun onRequestSuccess() {
        requestResults.trySend(true)
    }

    fun onRequestFailure() {
        requestResults.trySend(false)
    }

    /** Read data from the channel. Suspends until data arrives. Returns empty on EOF. */
    suspend fun read(): ByteArray {
        val data = try {
            dataChannel.receive()
        } catch (_: kotlinx.coroutines.channels.ClosedReceiveChannelException) {
            return ByteArray(0)
        }
        if (data.isEmpty()) return data
        adjustLocalWindow(data.size.toLong())
        return data
    }

    /** Read extended data (stderr). Suspends until data arrives. Returns empty on EOF. */
    suspend fun readExtended(): ByteArray {
        val data = try {
            extDataChannel.receive()
        } catch (_: kotlinx.coroutines.channels.ClosedReceiveChannelException) {
            return ByteArray(0)
        }
        if (data.isEmpty()) return data
        adjustLocalWindow(data.size.toLong())
        return data
    }

    /** Send data through the channel. Respects remote window size, suspends when exhausted. */
    suspend fun write(data: ByteArray) {
        var offset = 0
        while (offset < data.size) {
            val currentWindow = remoteWindowSize.get()
            val chunkSize = minOf(
                (data.size - offset).toLong(),
                remoteMaxPacketSize.toLong(),
                currentWindow.coerceAtLeast(0)
            ).toInt()
            if (chunkSize <= 0) {
                // Suspend until adjustRemoteWindow() signals window space available
                windowSignal.await()
                continue
            }

            val payload = SshBufferWriter()
                .writeByte(SshMsgType.CHANNEL_DATA)
                .writeUint32(remoteId)
                .writeString(data.copyOfRange(offset, offset + chunkSize))
                .toByteArray()
            transport.sendPacket(payload)
            remoteWindowSize.addAndGet(-chunkSize.toLong())
            offset += chunkSize
        }
    }

    /** Send EOF on this channel. */
    suspend fun sendEof() {
        if (!isOpen || isEof) return
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.CHANNEL_EOF)
            .writeUint32(remoteId)
            .toByteArray()
        transport.sendPacket(payload)
    }

    /** Close this channel. */
    suspend fun close() {
        if (!isOpen) return
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.CHANNEL_CLOSE)
            .writeUint32(remoteId)
            .toByteArray()
        transport.sendPacket(payload)
        isOpen = false
    }

    /** Adjust our local window (tell server they can send more). */
    private suspend fun adjustLocalWindow(consumed: Long) {
        val newSize = localWindowSize.addAndGet(-consumed)
        if (newSize < AsyncSshConnection.DEFAULT_WINDOW_SIZE / 2) {
            val adjust = AsyncSshConnection.DEFAULT_WINDOW_SIZE.toLong()
            val payload = SshBufferWriter()
                .writeByte(SshMsgType.CHANNEL_WINDOW_ADJUST)
                .writeUint32(remoteId)
                .writeUint32(adjust.toInt())
                .toByteArray()
            transport.sendPacket(payload)
            localWindowSize.addAndGet(adjust)
        }
    }

    /** Wait for a channel request reply. */
    protected suspend fun waitRequestReply(): Boolean {
        return requestResults.receive()
    }

    private fun sendChannelFailure() {
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.CHANNEL_FAILURE)
            .writeUint32(remoteId)
            .toByteArray()
        // Fire-and-forget from non-suspend context — enqueue via runBlocking-free path
        transport.sendPacketBlocking(payload)
    }
}

/**
 * Wraps an [AsyncChannel] as an [AsyncDataSource] for use in tunnel/proxy scenarios
 * where channel data needs to be piped through NIO-based packet I/O.
 */
class TunnelSource(private val channel: AsyncChannel) : AsyncDataSource {
    private var buffer: ByteArray = ByteArray(0)
    private var pos: Int = 0

    override suspend fun read(dst: java.nio.ByteBuffer): Int {
        if (pos >= buffer.size) {
            buffer = channel.read()
            pos = 0
            if (buffer.isEmpty()) return -1
        }
        val count = minOf(dst.remaining(), buffer.size - pos)
        dst.put(buffer, pos, count)
        pos += count
        return count
    }

    override suspend fun write(src: java.nio.ByteBuffer) {
        val data = ByteArray(src.remaining())
        src.get(data)
        channel.write(data)
    }

    override fun close() {
        try {
            @Suppress("BlockingMethodInNonBlockingContext")
            kotlinx.coroutines.runBlocking { channel.close() }
        } catch (_: Exception) {
        }
    }

    override val isClosed: Boolean get() = !channel.isOpen
}
