package de.arcan.arcshell.ssh.transport

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream

class PacketIOTest {

    @Test
    fun `plaintext write-read round-trip single byte payload`() {
        val pipe = createPipe()
        pipe.writer.writePacket(byteArrayOf(2)) // SSH_MSG_IGNORE
        val payload = pipe.reader.readPacket()
        assertEquals(1, payload.size)
        assertEquals(2, payload[0].toInt())
    }

    @Test
    fun `plaintext write-read round-trip larger payload`() {
        val pipe = createPipe()
        val data = ByteArray(200) { (it % 256).toByte() }
        pipe.writer.writePacket(data)
        val payload = pipe.reader.readPacket()
        assertArrayEquals(data, payload)
    }

    @Test
    fun `plaintext write-read multiple packets`() {
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
    fun `plaintext packet has correct padding`() {
        // Capture the raw bytes to verify padding structure
        val raw = ByteArrayOutputStream()
        val packetIO = PacketIO(ByteArrayInputStream(ByteArray(0)), raw)

        val payload = byteArrayOf(20) // 1 byte payload
        packetIO.writePacket(payload)

        val packet = raw.toByteArray()
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
    fun `empty payload is valid`() {
        val pipe = createPipe()
        pipe.writer.writePacket(byteArrayOf())
        val payload = pipe.reader.readPacket()
        assertEquals(0, payload.size)
    }

    @Test(expected = SshProtocolException::class)
    fun `read from closed stream throws`() {
        val input = ByteArrayInputStream(byteArrayOf())
        val packetIO = PacketIO(input, ByteArrayOutputStream())
        packetIO.readPacket()
    }

    @Test
    fun `large payload round-trips correctly`() {
        val pipe = createPipe()
        val data = ByteArray(32000) { (it % 251).toByte() } // just under 32KB
        pipe.writer.writePacket(data)
        assertArrayEquals(data, pipe.reader.readPacket())
    }

    private fun assertTrue(message: String, condition: Boolean) {
        org.junit.Assert.assertTrue(message, condition)
    }

    private data class Pipe(val writer: PacketIO, val reader: PacketIO)

    private fun createPipe(): Pipe {
        val pipeOut = PipedOutputStream()
        val pipeIn = PipedInputStream(pipeOut, 256 * 1024)
        val writer = PacketIO(ByteArrayInputStream(ByteArray(0)), pipeOut)
        val reader = PacketIO(pipeIn, ByteArrayOutputStream())
        return Pipe(writer, reader)
    }
}
