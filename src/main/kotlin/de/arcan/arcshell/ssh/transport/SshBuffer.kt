package de.arcan.arcshell.ssh.transport

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets

/**
 * SSH wire format reader. Parses SSH binary data types per RFC 4251 §5.
 *
 * All multi-byte integers are big-endian (network byte order).
 */
class SshBufferReader(private val data: ByteArray, private var pos: Int = 0) {

    val remaining: Int get() = data.size - pos
    val position: Int get() = pos

    fun readByte(): Int {
        check(remaining >= 1) { "Buffer underflow: need 1 byte, have $remaining" }
        return data[pos++].toInt() and 0xFF
    }

    fun readBoolean(): Boolean = readByte() != 0

    fun readUint32(): Long {
        check(remaining >= 4) { "Buffer underflow: need 4 bytes, have $remaining" }
        val v = ((data[pos].toLong() and 0xFF) shl 24) or
                ((data[pos + 1].toLong() and 0xFF) shl 16) or
                ((data[pos + 2].toLong() and 0xFF) shl 8) or
                (data[pos + 3].toLong() and 0xFF)
        pos += 4
        return v
    }

    fun readUint64(): Long {
        check(remaining >= 8) { "Buffer underflow: need 8 bytes, have $remaining" }
        var v = 0L
        for (i in 0 until 8) {
            v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        }
        pos += 8
        return v
    }

    /** Read an SSH string (uint32 length + data). */
    fun readString(): ByteArray {
        val len = readUint32().toInt()
        check(len >= 0 && remaining >= len) { "Buffer underflow: need $len bytes, have $remaining" }
        val result = data.copyOfRange(pos, pos + len)
        pos += len
        return result
    }

    /** Read an SSH string as UTF-8 text. */
    fun readUtf8(): String = String(readString(), StandardCharsets.UTF_8)

    /** Read an SSH mpint (multi-precision integer, RFC 4251 §5). */
    fun readMpint(): BigInteger {
        val bytes = readString()
        if (bytes.isEmpty()) return BigInteger.ZERO
        return BigInteger(bytes)
    }

    /** Read SSH name-list (comma-separated string). */
    fun readNameList(): List<String> {
        val s = readUtf8()
        if (s.isEmpty()) return emptyList()
        return s.split(",")
    }

    /** Read raw bytes without length prefix. */
    fun readBytes(count: Int): ByteArray {
        check(remaining >= count) { "Buffer underflow: need $count bytes, have $remaining" }
        val result = data.copyOfRange(pos, pos + count)
        pos += count
        return result
    }

    /** Skip bytes. */
    fun skip(count: Int) {
        check(remaining >= count) { "Buffer underflow: need $count bytes, have $remaining" }
        pos += count
    }
}

/**
 * SSH wire format writer. Builds SSH binary data per RFC 4251 §5.
 */
class SshBufferWriter(initialCapacity: Int = 256) {

    private val buf = ByteArrayOutputStream(initialCapacity)

    val size: Int get() = buf.size()

    fun writeByte(v: Int): SshBufferWriter {
        buf.write(v and 0xFF)
        return this
    }

    fun writeBoolean(v: Boolean): SshBufferWriter {
        buf.write(if (v) 1 else 0)
        return this
    }

    fun writeUint32(v: Long): SshBufferWriter {
        buf.write(((v shr 24) and 0xFF).toInt())
        buf.write(((v shr 16) and 0xFF).toInt())
        buf.write(((v shr 8) and 0xFF).toInt())
        buf.write((v and 0xFF).toInt())
        return this
    }

    fun writeUint32(v: Int): SshBufferWriter = writeUint32(v.toLong())

    fun writeUint64(v: Long): SshBufferWriter {
        for (i in 56 downTo 0 step 8) {
            buf.write(((v shr i) and 0xFF).toInt())
        }
        return this
    }

    /** Write an SSH string (uint32 length + data). */
    fun writeString(data: ByteArray): SshBufferWriter {
        writeUint32(data.size)
        buf.write(data)
        return this
    }

    /** Write an SSH string from UTF-8 text. */
    fun writeUtf8(s: String): SshBufferWriter = writeString(s.toByteArray(StandardCharsets.UTF_8))

    /** Write an SSH mpint (multi-precision integer, RFC 4251 §5). */
    fun writeMpint(v: BigInteger): SshBufferWriter {
        if (v == BigInteger.ZERO) {
            writeUint32(0)
            return this
        }
        val bytes = v.toByteArray()
        writeString(bytes)
        return this
    }

    /** Write SSH name-list (comma-separated string). */
    fun writeNameList(names: List<String>): SshBufferWriter = writeUtf8(names.joinToString(","))

    /** Write raw bytes without length prefix. */
    fun writeBytes(data: ByteArray): SshBufferWriter {
        buf.write(data)
        return this
    }

    fun toByteArray(): ByteArray = buf.toByteArray()

    fun reset() = buf.reset()
}
