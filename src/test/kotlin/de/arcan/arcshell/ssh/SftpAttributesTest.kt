package de.arcan.arcshell.ssh.sftp

import de.arcan.arcshell.ssh.transport.SshBufferReader
import de.arcan.arcshell.ssh.transport.SshBufferWriter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SftpAttributesTest {

    @Test
    fun `empty attributes encode as flags=0`() {
        val attrs = SftpAttributes.EMPTY
        val writer = SshBufferWriter()
        attrs.encode(writer)
        val reader = SshBufferReader(writer.toByteArray())
        assertEquals(0L, reader.readUint32()) // flags = 0
        assertEquals(0, reader.remaining)
    }

    @Test
    fun `size-only attributes roundtrip`() {
        val original = SftpAttributes(size = 12345)
        val writer = SshBufferWriter()
        original.encode(writer)

        val decoded = SftpAttributes.decode(SshBufferReader(writer.toByteArray()))
        assertEquals(12345L, decoded.size)
        assertEquals(-1, decoded.uid)
        assertEquals(-1, decoded.permissions)
    }

    @Test
    fun `full attributes roundtrip`() {
        val original = SftpAttributes(
            size = 999_999_999L,
            uid = 1000,
            gid = 1000,
            permissions = 0x81A4, // S_IFREG | 0644
            atime = 1700000000L,
            mtime = 1700000100L
        )
        val writer = SshBufferWriter()
        original.encode(writer)

        val decoded = SftpAttributes.decode(SshBufferReader(writer.toByteArray()))
        assertEquals(original.size, decoded.size)
        assertEquals(original.uid, decoded.uid)
        assertEquals(original.gid, decoded.gid)
        assertEquals(original.permissions, decoded.permissions)
        assertEquals(original.atime, decoded.atime)
        assertEquals(original.mtime, decoded.mtime)
    }

    @Test
    fun `permissions-only attributes roundtrip`() {
        val original = SftpAttributes(permissions = 0x41ED) // S_IFDIR | 0755
        val writer = SshBufferWriter()
        original.encode(writer)

        val decoded = SftpAttributes.decode(SshBufferReader(writer.toByteArray()))
        assertEquals(-1L, decoded.size)
        assertEquals(0x41ED, decoded.permissions)
        assertTrue(decoded.isDirectory)
    }

    @Test
    fun `isDirectory detects directory type`() {
        val dir = SftpAttributes(permissions = 0x41ED) // S_IFDIR | 0755
        assertTrue(dir.isDirectory)
        assertFalse(dir.isRegularFile)
        assertFalse(dir.isSymlink)
    }

    @Test
    fun `isRegularFile detects regular file`() {
        val file = SftpAttributes(permissions = 0x81A4) // S_IFREG | 0644
        assertFalse(file.isDirectory)
        assertTrue(file.isRegularFile)
        assertFalse(file.isSymlink)
    }

    @Test
    fun `isSymlink detects symbolic link`() {
        val link = SftpAttributes(permissions = 0xA1FF) // S_IFLNK | 0777
        assertFalse(link.isDirectory)
        assertFalse(link.isRegularFile)
        assertTrue(link.isSymlink)
    }

    @Test
    fun `fileType returns correct enum values`() {
        assertEquals(SftpAttributes.FileType.DIRECTORY, SftpAttributes(permissions = 0x41ED).fileType)
        assertEquals(SftpAttributes.FileType.REGULAR_FILE, SftpAttributes(permissions = 0x81A4).fileType)
        assertEquals(SftpAttributes.FileType.SYMLINK, SftpAttributes(permissions = 0xA1FF).fileType)
        assertEquals(SftpAttributes.FileType.CHARACTER_DEVICE, SftpAttributes(permissions = 0x21B6).fileType)
        assertEquals(SftpAttributes.FileType.BLOCK_DEVICE, SftpAttributes(permissions = 0x6190).fileType)
        assertEquals(SftpAttributes.FileType.FIFO, SftpAttributes(permissions = 0x11A4).fileType)
        assertEquals(SftpAttributes.FileType.SOCKET, SftpAttributes(permissions = 0xC1ED).fileType)
        assertEquals(SftpAttributes.FileType.UNKNOWN, SftpAttributes().fileType)
    }

    @Test
    fun `permissionString formats correctly`() {
        assertEquals("rwxr-xr-x", SftpAttributes(permissions = 0x41ED).permissionString()) // 0755
        assertEquals("rw-r--r--", SftpAttributes(permissions = 0x81A4).permissionString()) // 0644
        assertEquals("rwx------", SftpAttributes(permissions = 0x81C0).permissionString()) // 0700
        assertEquals("---------", SftpAttributes(permissions = 0x8000).permissionString()) // 0000
        assertEquals("---------", SftpAttributes().permissionString()) // no permissions
    }

    @Test
    fun `typeChar returns correct prefix`() {
        assertEquals('d', SftpAttributes(permissions = 0x41ED).typeChar())
        assertEquals('-', SftpAttributes(permissions = 0x81A4).typeChar())
        assertEquals('l', SftpAttributes(permissions = 0xA1FF).typeChar())
        assertEquals('c', SftpAttributes(permissions = 0x21B6).typeChar())
        assertEquals('b', SftpAttributes(permissions = 0x6190).typeChar())
        assertEquals('p', SftpAttributes(permissions = 0x11A4).typeChar())
        assertEquals('s', SftpAttributes(permissions = 0xC1ED).typeChar())
        assertEquals('-', SftpAttributes().typeChar())
    }

    @Test
    fun `decode handles extended attributes`() {
        val writer = SshBufferWriter()
        // flags: PERMISSIONS + EXTENDED
        writer.writeUint32(SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS or SftpConstants.SSH_FILEXFER_ATTR_EXTENDED)
        writer.writeUint32(0x81A4) // permissions
        writer.writeUint32(1) // 1 extended pair
        writer.writeUtf8("posix-acl@openssh.com")
        writer.writeUtf8("some-acl-data")

        val decoded = SftpAttributes.decode(SshBufferReader(writer.toByteArray()))
        assertEquals(0x81A4, decoded.permissions)
        assertTrue(decoded.isRegularFile)
    }

    @Test
    fun `decode handles size as uint64`() {
        val writer = SshBufferWriter()
        writer.writeUint32(SftpConstants.SSH_FILEXFER_ATTR_SIZE)
        writer.writeUint64(5_000_000_000L) // 5 GB
        val decoded = SftpAttributes.decode(SshBufferReader(writer.toByteArray()))
        assertEquals(5_000_000_000L, decoded.size)
    }
}
