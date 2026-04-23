package de.arcan.arcshell.ssh.connection

import de.arcan.arcshell.ssh.SshMsgType
import de.arcan.arcshell.ssh.transport.SshBufferReader
import de.arcan.arcshell.ssh.transport.SshBufferWriter
import de.arcan.arcshell.ssh.transport.SshTransport
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.LinkedBlockingQueue

/**
 * SSH channel (RFC 4254 §5). Base class for session, direct-tcpip, etc.
 * Provides data streams and window management.
 */
open class Channel(
    val localId: Int,
    protected val transport: SshTransport
) {
    var remoteId: Int = -1
    var remoteWindowSize: Long = 0
    var remoteMaxPacketSize: Int = 0
    var localWindowSize: Long = 0
    var isOpen: Boolean = false
    var isEof: Boolean = false
        private set

    /** Data received from the remote side (stdout). */
    private val dataQueue = LinkedBlockingQueue<ByteArray>()

    /** Extended data (stderr). */
    private val extDataQueue = LinkedBlockingQueue<ByteArray>()

    /** Pending channel request results. */
    private val requestResults = LinkedBlockingQueue<Boolean>()

    /** Called by SshConnection when CHANNEL_DATA arrives. */
    fun onData(data: ByteArray) {
        dataQueue.put(data)
    }

    /** Called by SshConnection when CHANNEL_EXTENDED_DATA arrives. */
    fun onExtendedData(dataType: Int, data: ByteArray) {
        extDataQueue.put(data)
    }

    /** Called by SshConnection when CHANNEL_WINDOW_ADJUST arrives. */
    fun adjustRemoteWindow(bytesToAdd: Long) {
        remoteWindowSize += bytesToAdd
    }

    fun onEof() {
        isEof = true
        dataQueue.put(ByteArray(0))    // signal EOF to stdout reader
        extDataQueue.put(ByteArray(0)) // signal EOF to stderr reader — without this,
                                       // any thread blocked on readExtended() leaks
                                       // forever (commands without stderr never push
                                       // anything onto extDataQueue otherwise)
    }

    fun onClose() {
        isOpen = false
        isEof = true
        dataQueue.put(ByteArray(0))
        extDataQueue.put(ByteArray(0))
    }

    open fun onRequest(requestType: String, wantReply: Boolean, reader: SshBufferReader) {
        if (wantReply) {
            sendChannelFailure()
        }
    }

    fun onRequestSuccess() {
        requestResults.put(true)
    }

    fun onRequestFailure() {
        requestResults.put(false)
    }

    /** Read data from the channel (blocks until data available). Returns empty on EOF. */
    fun read(): ByteArray {
        val data = dataQueue.take()
        if (data.isEmpty()) return data // EOF
        adjustLocalWindow(data.size.toLong())
        return data
    }

    /** Read extended data (stderr). Returns empty on EOF (mirrors [read]). */
    fun readExtended(): ByteArray {
        val data = extDataQueue.take()
        if (data.isEmpty()) return data
        adjustLocalWindow(data.size.toLong())
        return data
    }

    /** Send data through the channel. Respects remote window size. */
    fun write(data: ByteArray) {
        var offset = 0
        while (offset < data.size) {
            val chunkSize = minOf(
                data.size - offset,
                remoteMaxPacketSize,
                remoteWindowSize.toInt().coerceAtLeast(0)
            )
            if (chunkSize <= 0) {
                Thread.sleep(10) // wait for window adjust
                continue
            }

            val payload = SshBufferWriter()
                .writeByte(SshMsgType.CHANNEL_DATA)
                .writeUint32(remoteId)
                .writeString(data.copyOfRange(offset, offset + chunkSize))
                .toByteArray()
            transport.sendPacket(payload)
            remoteWindowSize -= chunkSize
            offset += chunkSize
        }
    }

    /** Send EOF on this channel. */
    fun sendEof() {
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.CHANNEL_EOF)
            .writeUint32(remoteId)
            .toByteArray()
        transport.sendPacket(payload)
    }

    /** Close this channel. */
    fun close() {
        if (!isOpen) return
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.CHANNEL_CLOSE)
            .writeUint32(remoteId)
            .toByteArray()
        transport.sendPacket(payload)
        isOpen = false
    }

    /** Adjust our local window (tell server they can send more). */
    private fun adjustLocalWindow(consumed: Long) {
        localWindowSize -= consumed
        if (localWindowSize < SshConnection.DEFAULT_WINDOW_SIZE / 2) {
            val adjust = SshConnection.DEFAULT_WINDOW_SIZE.toLong()
            val payload = SshBufferWriter()
                .writeByte(SshMsgType.CHANNEL_WINDOW_ADJUST)
                .writeUint32(remoteId)
                .writeUint32(adjust.toInt())
                .toByteArray()
            transport.sendPacket(payload)
            localWindowSize += adjust
        }
    }

    /** Wait for a channel request reply. */
    protected fun waitRequestReply(): Boolean {
        return requestResults.take()
    }

    private fun sendChannelFailure() {
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.CHANNEL_FAILURE)
            .writeUint32(remoteId)
            .toByteArray()
        transport.sendPacket(payload)
    }
}
