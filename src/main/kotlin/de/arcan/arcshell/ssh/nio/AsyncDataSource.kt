package de.arcan.arcshell.ssh.nio

import de.arcan.arcshell.ssh.transport.SshProtocolException
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.suspendCancellableCoroutine
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.SocketChannel
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume

interface AsyncDataSource {
    suspend fun read(dst: ByteBuffer): Int
    suspend fun write(src: ByteBuffer)
    fun close()
    val isClosed: Boolean
}

class SocketChannelSource(
    private val socketChannel: SocketChannel
) : AsyncDataSource {

    private val closed = AtomicBoolean(false)
    private var selectionKey: SelectionKey? = null

    @Volatile private var readCont: CancellableContinuation<Unit>? = null
    @Volatile private var writeCont: CancellableContinuation<Unit>? = null

    fun register() {
        selectionKey = SshEventLoop.register(socketChannel, this)
    }

    override suspend fun read(dst: ByteBuffer): Int {
        if (closed.get()) return -1
        val n = socketChannel.read(dst)
        if (n != 0) return n
        awaitReadable()
        if (closed.get()) return -1
        return socketChannel.read(dst)
    }

    override suspend fun write(src: ByteBuffer) {
        while (src.hasRemaining()) {
            if (closed.get()) throw SshProtocolException("Connection closed")
            val n = socketChannel.write(src)
            if (n == 0) awaitWritable()
        }
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            selectionKey?.cancel()
            try { socketChannel.close() } catch (_: Exception) {}
            readCont?.cancel()
            writeCont?.cancel()
        }
    }

    override val isClosed: Boolean get() = closed.get()

    internal fun onReadReady() {
        val key = selectionKey ?: return
        SshEventLoop.clearRead(key)
        val cont = readCont
        readCont = null
        cont?.resume(Unit)
    }

    internal fun onWriteReady() {
        val key = selectionKey ?: return
        SshEventLoop.clearWrite(key)
        val cont = writeCont
        writeCont = null
        cont?.resume(Unit)
    }

    internal fun onError() {
        close()
    }

    private suspend fun awaitReadable() = suspendCancellableCoroutine { cont: CancellableContinuation<Unit> ->
        readCont = cont
        selectionKey?.let { SshEventLoop.requestRead(it) }
        cont.invokeOnCancellation {
            readCont = null
            close()
        }
    }

    private suspend fun awaitWritable() = suspendCancellableCoroutine { cont: CancellableContinuation<Unit> ->
        writeCont = cont
        selectionKey?.let { SshEventLoop.requestWrite(it) }
        cont.invokeOnCancellation {
            writeCont = null
            close()
        }
    }
}

