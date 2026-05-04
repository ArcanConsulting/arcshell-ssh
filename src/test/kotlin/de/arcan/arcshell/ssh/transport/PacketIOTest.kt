package de.arcan.arcshell.ssh.transport

import de.arcan.arcshell.ssh.nio.AsyncDataSource
import de.arcan.arcshell.ssh.nio.AsyncPacketIO
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.nio.ByteBuffer

class PacketIOTest {

    @Test
    fun `plaintext write-read round-trip single byte payload`() = runBlocking {
        val pipe = createPipe()
        pipe.writer.writePacket(byteArrayOf(2)) // SSH_MSG_IGNORE
        val payload = pipe.reader.readPacket()
        assertEquals(1, payload.size)
        assertEquals(2, payload[0].toInt())
    }

    @Test
    fun `plaintext write-read round-trip larger payload`() = runBlocking {
        val pipe = createPipe()
        val data = ByteArray(200) { (it % 256).toByte() }
        pipe.writer.writePacket(data)
        val payload = pipe.reader.readPacket()
        assertArrayEquals(data, payload)
    }

    @Test
    fun `plaintext write-read multiple packets`() = runBlocking {
        val pipe = createPipe()
        pipe.writer.writePacket(byteArrayOf(20, 1, 2, 3))
        pipe.writer.writePacket(byteArrayOf(21))
        pipe.writer.writePacket(byteArrayOf(5, 0x41, 0x42))

        assertEquals(20, pipe.reader.readPacket()[0].toInt())
        assertEquals(21, pipe.reader.readPacket()[0].toInt())
        val third = pipe.reader.readPacket()
        assertEquals(5, third[0].toInt())
        assertEquals(0x42, third[2].toInt())
    }

    @Test
    fun `plaintext packet has correct padding`() = runBlocking {
        // Capture the raw bytes to verify padding structure
        val source = ByteArraySource(ByteArray(0))
        val packetIO = AsyncPacketIO(source)

        val payload = byteArrayOf(20) // 1 byte payload
        packetIO.writePacket(payload)

        val packet = source.getWrittenBytes()
        // packet_length(4) + padding_length(1) + payload(1) + padding(N)
        val packetLength = ((packet[0].toInt() and 0xFF) shl 24) or
                ((packet[1].toInt() and 0xFF) shl 16) or
                ((packet[2].toInt() and 0xFF) shl 8) or
                (packet[3].toInt() and 0xFF)
        val paddingLength = packet[4].toInt() and 0xFF

        // Total = 4 + packetLength, and (5 + 1 + paddingLength) must be multiple of 8
        assertEquals(packetLength, 1 + 1 + paddingLength)
        assertEquals(0, (4 + packetLength) % 8)
        assertTrue("Padding must be at least 4", paddingLength >= 4)
    }

    @Test
    fun `empty payload is valid`() = runBlocking {
        val pipe = createPipe()
        pipe.writer.writePacket(byteArrayOf())
        val payload = pipe.reader.readPacket()
        assertEquals(0, payload.size)
    }

    @Test(expected = SshProtocolException::class)
    fun `read from closed stream throws`() {
        runBlocking {
            val source = ByteArraySource(byteArrayOf())
            val packetIO = AsyncPacketIO(source)
            packetIO.readPacket()
        }
    }

    @Test
    fun `large payload round-trips correctly`() = runBlocking {
        val pipe = createPipe()
        val data = ByteArray(32000) { (it % 251).toByte() } // just under 32KB
        pipe.writer.writePacket(data)
        assertArrayEquals(data, pipe.reader.readPacket())
    }

    private fun assertTrue(message: String, condition: Boolean) {
        org.junit.Assert.assertTrue(message, condition)
    }

    private data class Pipe(val writer: AsyncPacketIO, val reader: AsyncPacketIO)

    private fun createPipe(): Pipe {
        val shared = PipeSource()
        val writer = AsyncPacketIO(shared)
        val reader = AsyncPacketIO(shared)
        return Pipe(writer, reader)
    }
}

/** In-memory [AsyncDataSource] backed by a byte array for read, capturing writes. */
open class ByteArraySource(input: ByteArray) : AsyncDataSource {
    private val buf = ByteBuffer.wrap(input)
    private val out = java.io.ByteArrayOutputStream()
    override suspend fun read(dst: ByteBuffer): Int {
        if (!buf.hasRemaining()) return -1
        val count = minOf(dst.remaining(), buf.remaining())
        val bytes = ByteArray(count)
        buf.get(bytes)
        dst.put(bytes)
        return count
    }
    override suspend fun write(src: ByteBuffer) {
        val bytes = ByteArray(src.remaining())
        src.get(bytes)
        out.write(bytes)
    }
    override fun close() {}
    override val isClosed = false
    fun getWrittenBytes(): ByteArray = out.toByteArray()
}

/** In-memory pipe [AsyncDataSource]: writes go into a buffer, reads consume from it. */
class PipeSource : AsyncDataSource {
    private val buffer = java.io.ByteArrayOutputStream()
    private var readBuf: ByteBuffer? = null

    override suspend fun read(dst: ByteBuffer): Int {
        val rb = readBuf ?: run {
            val bytes = buffer.toByteArray()
            if (bytes.isEmpty()) return -1
            buffer.reset()
            ByteBuffer.wrap(bytes).also { readBuf = it }
        }
        if (!rb.hasRemaining()) return -1
        val count = minOf(dst.remaining(), rb.remaining())
        val bytes = ByteArray(count)
        rb.get(bytes)
        dst.put(bytes)
        return count
    }

    override suspend fun write(src: ByteBuffer) {
        val bytes = ByteArray(src.remaining())
        src.get(bytes)
        synchronized(buffer) {
            buffer.write(bytes)
        }
        // Make written data available for reading
        val allData = if (readBuf != null && readBuf!!.hasRemaining()) {
            val remaining = ByteArray(readBuf!!.remaining())
            readBuf!!.get(remaining)
            remaining + bytes
        } else {
            synchronized(buffer) { buffer.toByteArray() }
        }
        readBuf = ByteBuffer.wrap(allData)
        synchronized(buffer) { buffer.reset() }
    }

    override fun close() {}
    override val isClosed = false
}
