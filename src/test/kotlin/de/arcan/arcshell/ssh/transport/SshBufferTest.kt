package de.arcan.arcshell.ssh.transport

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

class SshBufferWriterTest {

    @Test
    fun `writeByte produces single byte`() {
        val buf = SshBufferWriter()
        buf.writeByte(0x42)
        assertArrayEquals(byteArrayOf(0x42), buf.toByteArray())
    }

    @Test
    fun `writeUint32 big-endian`() {
        val buf = SshBufferWriter()
        buf.writeUint32(0x01020304L)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), buf.toByteArray())
    }

    @Test
    fun `writeUint32 max value`() {
        val buf = SshBufferWriter()
        buf.writeUint32(0xFFFFFFFFL)
        val bytes = buf.toByteArray()
        assertEquals(4, bytes.size)
        assertEquals(0xFF.toByte(), bytes[0])
        assertEquals(0xFF.toByte(), bytes[3])
    }

    @Test
    fun `writeString includes length prefix`() {
        val buf = SshBufferWriter()
        buf.writeString(byteArrayOf(0x41, 0x42, 0x43))
        val result = buf.toByteArray()
        assertEquals(7, result.size) // 4 bytes length + 3 bytes data
        assertEquals(0, result[0].toInt())
        assertEquals(0, result[1].toInt())
        assertEquals(0, result[2].toInt())
        assertEquals(3, result[3].toInt())
        assertEquals(0x41, result[4].toInt())
    }

    @Test
    fun `writeUtf8 handles unicode`() {
        val buf = SshBufferWriter()
        buf.writeUtf8("Ärger")
        val reader = SshBufferReader(buf.toByteArray())
        assertEquals("Ärger", reader.readUtf8())
    }

    @Test
    fun `writeMpint zero`() {
        val buf = SshBufferWriter()
        buf.writeMpint(BigInteger.ZERO)
        val reader = SshBufferReader(buf.toByteArray())
        assertEquals(BigInteger.ZERO, reader.readMpint())
    }

    @Test
    fun `writeMpint positive`() {
        val value = BigInteger("12345678901234567890")
        val buf = SshBufferWriter()
        buf.writeMpint(value)
        val reader = SshBufferReader(buf.toByteArray())
        assertEquals(value, reader.readMpint())
    }

    @Test
    fun `writeMpint negative`() {
        val value = BigInteger("-42")
        val buf = SshBufferWriter()
        buf.writeMpint(value)
        val reader = SshBufferReader(buf.toByteArray())
        assertEquals(value, reader.readMpint())
    }

    @Test
    fun `writeNameList comma-separated`() {
        val buf = SshBufferWriter()
        buf.writeNameList(listOf("aes256-ctr", "aes128-ctr", "chacha20-poly1305@openssh.com"))
        val reader = SshBufferReader(buf.toByteArray())
        assertEquals(
            listOf("aes256-ctr", "aes128-ctr", "chacha20-poly1305@openssh.com"),
            reader.readNameList()
        )
    }

    @Test
    fun `writeNameList empty`() {
        val buf = SshBufferWriter()
        buf.writeNameList(emptyList())
        val reader = SshBufferReader(buf.toByteArray())
        assertEquals(emptyList<String>(), reader.readNameList())
    }

    @Test
    fun `writeBoolean true and false`() {
        val buf = SshBufferWriter()
        buf.writeBoolean(true)
        buf.writeBoolean(false)
        val reader = SshBufferReader(buf.toByteArray())
        assertTrue(reader.readBoolean())
        assertFalse(reader.readBoolean())
    }

    @Test
    fun `chained writes produce correct sequence`() {
        val buf = SshBufferWriter()
            .writeByte(20) // KEXINIT
            .writeUint32(1)
            .writeUtf8("hello")
        val reader = SshBufferReader(buf.toByteArray())
        assertEquals(20, reader.readByte())
        assertEquals(1L, reader.readUint32())
        assertEquals("hello", reader.readUtf8())
        assertEquals(0, reader.remaining)
    }
}

class SshBufferReaderTest {

    @Test
    fun `readByte consumes one byte`() {
        val reader = SshBufferReader(byteArrayOf(0xFF.toByte(), 0x00))
        assertEquals(255, reader.readByte())
        assertEquals(1, reader.remaining)
    }

    @Test
    fun `readUint32 big-endian`() {
        val reader = SshBufferReader(byteArrayOf(0, 0, 1, 0))
        assertEquals(256L, reader.readUint32())
    }

    @Test
    fun `readString with data`() {
        val data = byteArrayOf(0, 0, 0, 3, 0x41, 0x42, 0x43)
        val reader = SshBufferReader(data)
        assertArrayEquals(byteArrayOf(0x41, 0x42, 0x43), reader.readString())
    }

    @Test
    fun `readString empty`() {
        val data = byteArrayOf(0, 0, 0, 0)
        val reader = SshBufferReader(data)
        assertArrayEquals(byteArrayOf(), reader.readString())
    }

    @Test(expected = IllegalStateException::class)
    fun `readUint32 underflow throws`() {
        val reader = SshBufferReader(byteArrayOf(0, 0))
        reader.readUint32()
    }

    @Test(expected = IllegalStateException::class)
    fun `readString with truncated data throws`() {
        val data = byteArrayOf(0, 0, 0, 10, 0x41) // claims 10 bytes, only has 1
        val reader = SshBufferReader(data)
        reader.readString()
    }

    @Test
    fun `skip advances position`() {
        val reader = SshBufferReader(byteArrayOf(1, 2, 3, 4, 5))
        reader.skip(3)
        assertEquals(2, reader.remaining)
        assertEquals(4, reader.readByte())
    }

    @Test
    fun `readUint64 works`() {
        val buf = SshBufferWriter().writeUint64(Long.MAX_VALUE)
        val reader = SshBufferReader(buf.toByteArray())
        assertEquals(Long.MAX_VALUE, reader.readUint64())
    }
}
