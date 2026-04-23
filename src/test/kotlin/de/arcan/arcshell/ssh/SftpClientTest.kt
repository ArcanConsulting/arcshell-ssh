package de.arcan.arcshell.ssh.sftp

import de.arcan.arcshell.ssh.transport.SshBufferReader
import de.arcan.arcshell.ssh.transport.SshBufferWriter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for SFTP packet construction and parsing.
 * These test the wire format at the protocol level without needing
 * a real SSH connection — verifying that our encoding matches the
 * SFTP v3 spec (draft-ietf-secsh-filexfer-02).
 */
class SftpClientTest {

    @Test
    fun `SSH_FXP_INIT packet has correct format`() {
        // SSH_FXP_INIT: uint32 length, byte type=1, uint32 version=3
        val payload = SshBufferWriter()
            .writeUint32(SftpConstants.SFTP_VERSION)
            .toByteArray()
        val length = 1 + payload.size // type byte + payload
        val packet = SshBufferWriter()
            .writeUint32(length)
            .writeByte(SftpConstants.SSH_FXP_INIT)
            .writeBytes(payload)
            .toByteArray()

        val reader = SshBufferReader(packet)
        assertEquals(5L, reader.readUint32()) // length = 1 (type) + 4 (version)
        assertEquals(SftpConstants.SSH_FXP_INIT, reader.readByte())
        assertEquals(3L, reader.readUint32()) // version
        assertEquals(0, reader.remaining)
    }

    @Test
    fun `SSH_FXP_VERSION response can be parsed`() {
        val response = SshBufferWriter()
            .writeUint32(3) // server version
            .toByteArray()
        val reader = SshBufferReader(response)
        val version = reader.readUint32().toInt()
        assertEquals(3, version)
    }

    @Test
    fun `SSH_FXP_VERSION with extensions can be parsed`() {
        val response = SshBufferWriter()
            .writeUint32(3) // version
            .writeUtf8("posix-rename@openssh.com")
            .writeUtf8("1")
            .writeUtf8("statvfs@openssh.com")
            .writeUtf8("2")
            .toByteArray()
        val reader = SshBufferReader(response)
        assertEquals(3, reader.readUint32().toInt())
        // Parse extensions
        val extensions = mutableMapOf<String, String>()
        while (reader.remaining > 0) {
            extensions[reader.readUtf8()] = reader.readUtf8()
        }
        assertEquals("1", extensions["posix-rename@openssh.com"])
        assertEquals("2", extensions["statvfs@openssh.com"])
    }

    @Test
    fun `SSH_FXP_OPENDIR request format`() {
        val requestId = 42
        val payload = SshBufferWriter()
            .writeUint32(requestId)
            .writeUtf8("/home/user")
            .toByteArray()
        val reader = SshBufferReader(payload)
        assertEquals(42L, reader.readUint32())
        assertEquals("/home/user", reader.readUtf8())
    }

    @Test
    fun `SSH_FXP_HANDLE response parsing`() {
        // Simulate server response: type=HANDLE, request-id, handle-bytes
        val handle = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val response = SshBufferWriter()
            .writeUint32(42) // request-id
            .writeString(handle) // handle
            .toByteArray()
        val reader = SshBufferReader(response)
        assertEquals(42L, reader.readUint32())
        val parsedHandle = reader.readString()
        assertEquals(4, parsedHandle.size)
        assertEquals(0x01, parsedHandle[0].toInt())
    }

    @Test
    fun `SSH_FXP_NAME response with single entry`() {
        val nameResponse = SshBufferWriter()
            .writeUint32(1) // request-id
            .writeUint32(1) // count
            .writeUtf8("test.txt")
            .writeUtf8("-rw-r--r--  1 root root  1234 Jan  1 00:00 test.txt")
            // attrs: size + permissions
            .writeUint32(SftpConstants.SSH_FILEXFER_ATTR_SIZE or SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS)
            .writeUint64(1234)
            .writeUint32(0x81A4) // S_IFREG | 0644
            .toByteArray()

        val reader = SshBufferReader(nameResponse)
        reader.readUint32() // request-id
        val count = reader.readUint32().toInt()
        assertEquals(1, count)

        val filename = reader.readUtf8()
        val longname = reader.readUtf8()
        val attrs = SftpAttributes.decode(reader)

        assertEquals("test.txt", filename)
        assertTrue(longname.contains("test.txt"))
        assertEquals(1234L, attrs.size)
        assertTrue(attrs.isRegularFile)
    }

    @Test
    fun `SSH_FXP_NAME response with multiple entries`() {
        val writer = SshBufferWriter()
            .writeUint32(5) // request-id
            .writeUint32(3) // count

        // Entry 1: directory
        writer.writeUtf8("docs")
            .writeUtf8("drwxr-xr-x  2 root root  4096 Jan  1 00:00 docs")
            .writeUint32(SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS)
            .writeUint32(0x41ED) // S_IFDIR | 0755

        // Entry 2: regular file
        writer.writeUtf8("readme.md")
            .writeUtf8("-rw-r--r--  1 root root   512 Jan  2 00:00 readme.md")
            .writeUint32(SftpConstants.SSH_FILEXFER_ATTR_SIZE or SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS)
            .writeUint64(512)
            .writeUint32(0x81A4)

        // Entry 3: symlink
        writer.writeUtf8("link")
            .writeUtf8("lrwxrwxrwx  1 root root     5 Jan  3 00:00 link -> target")
            .writeUint32(SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS)
            .writeUint32(0xA1FF) // S_IFLNK | 0777

        val reader = SshBufferReader(writer.toByteArray())
        reader.readUint32() // request-id
        val count = reader.readUint32().toInt()
        assertEquals(3, count)

        val entries = List(count) {
            val fn = reader.readUtf8()
            val ln = reader.readUtf8()
            val a = SftpAttributes.decode(reader)
            SftpFile(fn, ln, a)
        }

        assertEquals("docs", entries[0].filename)
        assertTrue(entries[0].isDirectory)

        assertEquals("readme.md", entries[1].filename)
        assertTrue(entries[1].isRegularFile)
        assertEquals(512L, entries[1].size)

        assertEquals("link", entries[2].filename)
        assertTrue(entries[2].isSymlink)
    }

    @Test
    fun `SSH_FXP_STATUS OK can be parsed`() {
        val status = SshBufferWriter()
            .writeUint32(10) // request-id
            .writeUint32(SftpConstants.SSH_FX_OK)
            .writeUtf8("Success")
            .writeUtf8("en")
            .toByteArray()
        val reader = SshBufferReader(status)
        assertEquals(10L, reader.readUint32())
        assertEquals(SftpConstants.SSH_FX_OK.toLong(), reader.readUint32())
    }

    @Test
    fun `SSH_FXP_STATUS error can be parsed`() {
        val status = SshBufferWriter()
            .writeUint32(11) // request-id
            .writeUint32(SftpConstants.SSH_FX_PERMISSION_DENIED)
            .writeUtf8("Permission denied")
            .writeUtf8("en")
            .toByteArray()
        val reader = SshBufferReader(status)
        reader.readUint32() // request-id
        val code = reader.readUint32().toInt()
        val message = reader.readUtf8()

        assertEquals(SftpConstants.SSH_FX_PERMISSION_DENIED, code)
        assertEquals("Permission denied", message)
    }

    @Test
    fun `SSH_FXP_OPEN request format for reading`() {
        val id = 7
        val writer = SshBufferWriter()
            .writeUint32(id)
            .writeUtf8("/var/log/syslog")
            .writeUint32(SftpConstants.SSH_FXF_READ)
        SftpAttributes.EMPTY.encode(writer)

        val reader = SshBufferReader(writer.toByteArray())
        assertEquals(7L, reader.readUint32())
        assertEquals("/var/log/syslog", reader.readUtf8())
        assertEquals(SftpConstants.SSH_FXF_READ.toLong(), reader.readUint32())
        val attrs = SftpAttributes.decode(reader)
        assertEquals(-1L, attrs.size) // no attributes set
    }

    @Test
    fun `SSH_FXP_OPEN request format for writing with create and truncate`() {
        val flags = SftpConstants.SSH_FXF_WRITE or SftpConstants.SSH_FXF_CREAT or SftpConstants.SSH_FXF_TRUNC
        val attrs = SftpAttributes(permissions = 0x81A4) // S_IFREG | 0644

        val writer = SshBufferWriter()
            .writeUint32(1)
            .writeUtf8("/tmp/test.txt")
            .writeUint32(flags)
        attrs.encode(writer)

        val reader = SshBufferReader(writer.toByteArray())
        reader.readUint32() // request-id
        assertEquals("/tmp/test.txt", reader.readUtf8())
        val readFlags = reader.readUint32().toInt()
        assertTrue(readFlags and SftpConstants.SSH_FXF_WRITE != 0)
        assertTrue(readFlags and SftpConstants.SSH_FXF_CREAT != 0)
        assertTrue(readFlags and SftpConstants.SSH_FXF_TRUNC != 0)
    }

    @Test
    fun `SSH_FXP_READ request format`() {
        val handle = byteArrayOf(0x0A, 0x0B, 0x0C)
        val writer = SshBufferWriter()
            .writeUint32(15) // request-id
            .writeString(handle)
            .writeUint64(1024) // offset
            .writeUint32(65536) // length
        val reader = SshBufferReader(writer.toByteArray())
        assertEquals(15L, reader.readUint32())
        assertEquals(3, reader.readString().size)
        assertEquals(1024L, reader.readUint64())
        assertEquals(65536L, reader.readUint32())
    }

    @Test
    fun `SSH_FXP_DATA response parsing`() {
        val fileData = "Hello, SFTP!".toByteArray()
        val response = SshBufferWriter()
            .writeUint32(15) // request-id
            .writeString(fileData)
            .toByteArray()
        val reader = SshBufferReader(response)
        reader.readUint32() // request-id
        val data = reader.readString()
        assertEquals("Hello, SFTP!", String(data))
    }

    @Test
    fun `SSH_FXP_WRITE request format`() {
        val handle = byteArrayOf(0x01, 0x02)
        val data = "test data".toByteArray()
        val writer = SshBufferWriter()
            .writeUint32(20) // request-id
            .writeString(handle)
            .writeUint64(0) // offset
            .writeString(data)
        val reader = SshBufferReader(writer.toByteArray())
        assertEquals(20L, reader.readUint32())
        assertEquals(2, reader.readString().size) // handle
        assertEquals(0L, reader.readUint64()) // offset
        assertEquals("test data", String(reader.readString()))
    }

    @Test
    fun `SSH_FXP_MKDIR request format`() {
        val attrs = SftpAttributes(permissions = 0x41ED) // S_IFDIR | 0755
        val writer = SshBufferWriter()
            .writeUint32(30)
            .writeUtf8("/home/user/newdir")
        attrs.encode(writer)

        val reader = SshBufferReader(writer.toByteArray())
        assertEquals(30L, reader.readUint32())
        assertEquals("/home/user/newdir", reader.readUtf8())
        val decoded = SftpAttributes.decode(reader)
        assertTrue(decoded.isDirectory)
    }

    @Test
    fun `SSH_FXP_RENAME request format`() {
        val writer = SshBufferWriter()
            .writeUint32(40)
            .writeUtf8("/home/old.txt")
            .writeUtf8("/home/new.txt")
        val reader = SshBufferReader(writer.toByteArray())
        assertEquals(40L, reader.readUint32())
        assertEquals("/home/old.txt", reader.readUtf8())
        assertEquals("/home/new.txt", reader.readUtf8())
    }

    @Test
    fun `SftpConstants statusMessage returns human-readable strings`() {
        assertEquals("OK", SftpConstants.statusMessage(SftpConstants.SSH_FX_OK))
        assertEquals("No such file", SftpConstants.statusMessage(SftpConstants.SSH_FX_NO_SUCH_FILE))
        assertEquals("Permission denied", SftpConstants.statusMessage(SftpConstants.SSH_FX_PERMISSION_DENIED))
        assertEquals("End of file", SftpConstants.statusMessage(SftpConstants.SSH_FX_EOF))
        assertTrue(SftpConstants.statusMessage(999).contains("999"))
    }

    @Test
    fun `SftpException includes status code and message`() {
        val ex = SftpException(SftpConstants.SSH_FX_PERMISSION_DENIED)
        assertEquals(SftpConstants.SSH_FX_PERMISSION_DENIED, ex.statusCode)
        assertTrue(ex.message!!.contains("Permission denied"))
        assertTrue(ex.message!!.contains("3"))
    }

    @Test
    fun `SftpFile formattedSize returns human-readable sizes`() {
        assertEquals("0 B", SftpFile("f", "", SftpAttributes(size = 0)).formattedSize())
        assertEquals("512 B", SftpFile("f", "", SftpAttributes(size = 512)).formattedSize())
        assertEquals("1 KB", SftpFile("f", "", SftpAttributes(size = 1024)).formattedSize())
        assertEquals("10 KB", SftpFile("f", "", SftpAttributes(size = 10240)).formattedSize())
        assertTrue(SftpFile("f", "", SftpAttributes(size = 1500000)).formattedSize().contains("MB"))
        assertTrue(SftpFile("f", "", SftpAttributes(size = 5000000000L)).formattedSize().contains("GB"))
        assertEquals("", SftpFile("f", "", SftpAttributes()).formattedSize())
    }
}
