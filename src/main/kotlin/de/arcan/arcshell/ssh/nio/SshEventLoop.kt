package de.arcan.arcshell.ssh.nio

import java.nio.channels.SelectableChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean

object SshEventLoop {

    private var selector: Selector? = null
    private var thread: Thread? = null
    private val started = AtomicBoolean(false)
    private val pendingActions = ConcurrentLinkedQueue<() -> Unit>()

    fun ensureRunning() {
        if (!started.compareAndSet(false, true)) return
        val sel = Selector.open()
        selector = sel
        val t = Thread({
            try {
                while (!Thread.currentThread().isInterrupted) {
                    drainActions()
                    sel.select(100)
                    if (Thread.currentThread().isInterrupted) break
                    val keys = sel.selectedKeys().iterator()
                    while (keys.hasNext()) {
                        val key = keys.next()
                        keys.remove()
                        if (!key.isValid) continue
                        val source = key.attachment() as? SocketChannelSource ?: continue
                        try {
                            if (key.isReadable) source.onReadReady()
                            if (key.isValid && key.isWritable) source.onWriteReady()
                        } catch (_: Exception) {
                            source.onError()
                        }
                    }
                }
            } catch (_: java.nio.channels.ClosedSelectorException) {
            } finally {
                started.set(false)
            }
        }, "ssh-nio-event-loop")
        t.isDaemon = true
        thread = t
        t.start()
    }

    fun submit(action: () -> Unit) {
        pendingActions.add(action)
        selector?.wakeup()
    }

    fun register(channel: SocketChannel, source: SocketChannelSource): SelectionKey {
        ensureRunning()
        channel.configureBlocking(false)
        val sel = selector ?: throw IllegalStateException("Event loop not started")
        return channel.register(sel, 0, source)
    }

    fun requestRead(key: SelectionKey) {
        submit {
            if (key.isValid) key.interestOps(key.interestOps() or SelectionKey.OP_READ)
        }
        selector?.wakeup()
    }

    fun requestWrite(key: SelectionKey) {
        submit {
            if (key.isValid) key.interestOps(key.interestOps() or SelectionKey.OP_WRITE)
        }
        selector?.wakeup()
    }

    fun clearRead(key: SelectionKey) {
        if (key.isValid) key.interestOps(key.interestOps() and SelectionKey.OP_READ.inv())
    }

    fun clearWrite(key: SelectionKey) {
        if (key.isValid) key.interestOps(key.interestOps() and SelectionKey.OP_WRITE.inv())
    }

    fun shutdown() {
        thread?.interrupt()
        try { selector?.close() } catch (_: Exception) {}
        selector = null
        thread = null
        started.set(false)
    }

    val registeredCount: Int get() = selector?.keys()?.size ?: 0

    private fun drainActions() {
        while (true) {
            val action = pendingActions.poll() ?: break
            try { action() } catch (_: Exception) {}
        }
    }
}
