package de.arcan.arcshell.ssh.sftp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SftpConstantsTest {

    // =========================================================================
    // SFTP_VERSION
    // =========================================================================

    @Test
    fun `SFTP_VERSION is 3`() {
        assertEquals(3, SftpConstants.SFTP_VERSION)
    }

    // =========================================================================
    // Packet types
    // =========================================================================

    @Test
    fun `SSH_FXP_INIT is 1`() {
        assertEquals(1, SftpConstants.SSH_FXP_INIT)
    }

    @Test
    fun `SSH_FXP_VERSION is 2`() {
        assertEquals(2, SftpConstants.SSH_FXP_VERSION)
    }

    @Test
    fun `SSH_FXP_OPEN is 3`() {
        assertEquals(3, SftpConstants.SSH_FXP_OPEN)
    }

    @Test
    fun `SSH_FXP_CLOSE is 4`() {
        assertEquals(4, SftpConstants.SSH_FXP_CLOSE)
    }

    @Test
    fun `SSH_FXP_READ is 5`() {
        assertEquals(5, SftpConstants.SSH_FXP_READ)
    }

    @Test
    fun `SSH_FXP_WRITE is 6`() {
        assertEquals(6, SftpConstants.SSH_FXP_WRITE)
    }

    @Test
    fun `SSH_FXP_LSTAT is 7`() {
        assertEquals(7, SftpConstants.SSH_FXP_LSTAT)
    }

    @Test
    fun `SSH_FXP_FSTAT is 8`() {
        assertEquals(8, SftpConstants.SSH_FXP_FSTAT)
    }

    @Test
    fun `SSH_FXP_SETSTAT is 9`() {
        assertEquals(9, SftpConstants.SSH_FXP_SETSTAT)
    }

    @Test
    fun `SSH_FXP_FSETSTAT is 10`() {
        assertEquals(10, SftpConstants.SSH_FXP_FSETSTAT)
    }

    @Test
    fun `SSH_FXP_OPENDIR is 11`() {
        assertEquals(11, SftpConstants.SSH_FXP_OPENDIR)
    }

    @Test
    fun `SSH_FXP_READDIR is 12`() {
        assertEquals(12, SftpConstants.SSH_FXP_READDIR)
    }

    @Test
    fun `SSH_FXP_REMOVE is 13`() {
        assertEquals(13, SftpConstants.SSH_FXP_REMOVE)
    }

    @Test
    fun `SSH_FXP_MKDIR is 14`() {
        assertEquals(14, SftpConstants.SSH_FXP_MKDIR)
    }

    @Test
    fun `SSH_FXP_RMDIR is 15`() {
        assertEquals(15, SftpConstants.SSH_FXP_RMDIR)
    }

    @Test
    fun `SSH_FXP_REALPATH is 16`() {
        assertEquals(16, SftpConstants.SSH_FXP_REALPATH)
    }

    @Test
    fun `SSH_FXP_STAT is 17`() {
        assertEquals(17, SftpConstants.SSH_FXP_STAT)
    }

    @Test
    fun `SSH_FXP_RENAME is 18`() {
        assertEquals(18, SftpConstants.SSH_FXP_RENAME)
    }

    @Test
    fun `SSH_FXP_READLINK is 19`() {
        assertEquals(19, SftpConstants.SSH_FXP_READLINK)
    }

    @Test
    fun `SSH_FXP_SYMLINK is 20`() {
        assertEquals(20, SftpConstants.SSH_FXP_SYMLINK)
    }

    // =========================================================================
    // Response types
    // =========================================================================

    @Test
    fun `SSH_FXP_STATUS is 101`() {
        assertEquals(101, SftpConstants.SSH_FXP_STATUS)
    }

    @Test
    fun `SSH_FXP_HANDLE is 102`() {
        assertEquals(102, SftpConstants.SSH_FXP_HANDLE)
    }

    @Test
    fun `SSH_FXP_DATA is 103`() {
        assertEquals(103, SftpConstants.SSH_FXP_DATA)
    }

    @Test
    fun `SSH_FXP_NAME is 104`() {
        assertEquals(104, SftpConstants.SSH_FXP_NAME)
    }

    @Test
    fun `SSH_FXP_ATTRS is 105`() {
        assertEquals(105, SftpConstants.SSH_FXP_ATTRS)
    }

    // =========================================================================
    // Attribute flags
    // =========================================================================

    @Test
    fun `SSH_FILEXFER_ATTR_SIZE flag value`() {
        assertEquals(0x00000001, SftpConstants.SSH_FILEXFER_ATTR_SIZE)
    }

    @Test
    fun `SSH_FILEXFER_ATTR_UIDGID flag value`() {
        assertEquals(0x00000002, SftpConstants.SSH_FILEXFER_ATTR_UIDGID)
    }

    @Test
    fun `SSH_FILEXFER_ATTR_PERMISSIONS flag value`() {
        assertEquals(0x00000004, SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS)
    }

    @Test
    fun `SSH_FILEXFER_ATTR_ACMODTIME flag value`() {
        assertEquals(0x00000008, SftpConstants.SSH_FILEXFER_ATTR_ACMODTIME)
    }

    @Test
    fun `SSH_FILEXFER_ATTR_EXTENDED flag value`() {
        assertEquals(0x80000000.toInt(), SftpConstants.SSH_FILEXFER_ATTR_EXTENDED)
    }

    @Test
    fun `attribute flags are distinct bits`() {
        val flags = listOf(
            SftpConstants.SSH_FILEXFER_ATTR_SIZE,
            SftpConstants.SSH_FILEXFER_ATTR_UIDGID,
            SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS,
            SftpConstants.SSH_FILEXFER_ATTR_ACMODTIME,
            SftpConstants.SSH_FILEXFER_ATTR_EXTENDED
        )
        // Each pair should have no overlapping bits
        for (i in flags.indices) {
            for (j in i + 1 until flags.size) {
                assertEquals("Flags $i and $j overlap", 0, flags[i] and flags[j])
            }
        }
    }

    // =========================================================================
    // Open flags
    // =========================================================================

    @Test
    fun `SSH_FXF_READ flag value`() {
        assertEquals(0x00000001, SftpConstants.SSH_FXF_READ)
    }

    @Test
    fun `SSH_FXF_WRITE flag value`() {
        assertEquals(0x00000002, SftpConstants.SSH_FXF_WRITE)
    }

    @Test
    fun `SSH_FXF_APPEND flag value`() {
        assertEquals(0x00000004, SftpConstants.SSH_FXF_APPEND)
    }

    @Test
    fun `SSH_FXF_CREAT flag value`() {
        assertEquals(0x00000008, SftpConstants.SSH_FXF_CREAT)
    }

    @Test
    fun `SSH_FXF_TRUNC flag value`() {
        assertEquals(0x00000010, SftpConstants.SSH_FXF_TRUNC)
    }

    @Test
    fun `SSH_FXF_EXCL flag value`() {
        assertEquals(0x00000020, SftpConstants.SSH_FXF_EXCL)
    }

    @Test
    fun `open flags are distinct bits`() {
        val flags = listOf(
            SftpConstants.SSH_FXF_READ,
            SftpConstants.SSH_FXF_WRITE,
            SftpConstants.SSH_FXF_APPEND,
            SftpConstants.SSH_FXF_CREAT,
            SftpConstants.SSH_FXF_TRUNC,
            SftpConstants.SSH_FXF_EXCL
        )
        for (i in flags.indices) {
            for (j in i + 1 until flags.size) {
                assertEquals("Open flags $i and $j overlap", 0, flags[i] and flags[j])
            }
        }
    }

    @Test
    fun `open flags can be combined with OR`() {
        val readWrite = SftpConstants.SSH_FXF_READ or SftpConstants.SSH_FXF_WRITE
        assertEquals(0x00000003, readWrite)
        assertTrue(readWrite and SftpConstants.SSH_FXF_READ != 0)
        assertTrue(readWrite and SftpConstants.SSH_FXF_WRITE != 0)
        assertTrue(readWrite and SftpConstants.SSH_FXF_APPEND == 0)
    }

    @Test
    fun `create and truncate combined`() {
        val flags = SftpConstants.SSH_FXF_WRITE or SftpConstants.SSH_FXF_CREAT or SftpConstants.SSH_FXF_TRUNC
        assertEquals(0x0000001A, flags)
    }

    // =========================================================================
    // Status codes
    // =========================================================================

    @Test
    fun `SSH_FX_OK is 0`() {
        assertEquals(0, SftpConstants.SSH_FX_OK)
    }

    @Test
    fun `SSH_FX_EOF is 1`() {
        assertEquals(1, SftpConstants.SSH_FX_EOF)
    }

    @Test
    fun `SSH_FX_NO_SUCH_FILE is 2`() {
        assertEquals(2, SftpConstants.SSH_FX_NO_SUCH_FILE)
    }

    @Test
    fun `SSH_FX_PERMISSION_DENIED is 3`() {
        assertEquals(3, SftpConstants.SSH_FX_PERMISSION_DENIED)
    }

    @Test
    fun `SSH_FX_FAILURE is 4`() {
        assertEquals(4, SftpConstants.SSH_FX_FAILURE)
    }

    @Test
    fun `SSH_FX_BAD_MESSAGE is 5`() {
        assertEquals(5, SftpConstants.SSH_FX_BAD_MESSAGE)
    }

    @Test
    fun `SSH_FX_NO_CONNECTION is 6`() {
        assertEquals(6, SftpConstants.SSH_FX_NO_CONNECTION)
    }

    @Test
    fun `SSH_FX_CONNECTION_LOST is 7`() {
        assertEquals(7, SftpConstants.SSH_FX_CONNECTION_LOST)
    }

    @Test
    fun `SSH_FX_OP_UNSUPPORTED is 8`() {
        assertEquals(8, SftpConstants.SSH_FX_OP_UNSUPPORTED)
    }

    // =========================================================================
    // statusMessage
    // =========================================================================

    @Test
    fun `statusMessage for SSH_FX_OK`() {
        assertEquals("OK", SftpConstants.statusMessage(SftpConstants.SSH_FX_OK))
    }

    @Test
    fun `statusMessage for SSH_FX_EOF`() {
        assertEquals("End of file", SftpConstants.statusMessage(SftpConstants.SSH_FX_EOF))
    }

    @Test
    fun `statusMessage for SSH_FX_NO_SUCH_FILE`() {
        assertEquals("No such file", SftpConstants.statusMessage(SftpConstants.SSH_FX_NO_SUCH_FILE))
    }

    @Test
    fun `statusMessage for SSH_FX_PERMISSION_DENIED`() {
        assertEquals("Permission denied", SftpConstants.statusMessage(SftpConstants.SSH_FX_PERMISSION_DENIED))
    }

    @Test
    fun `statusMessage for SSH_FX_FAILURE`() {
        assertEquals("Failure", SftpConstants.statusMessage(SftpConstants.SSH_FX_FAILURE))
    }

    @Test
    fun `statusMessage for SSH_FX_BAD_MESSAGE`() {
        assertEquals("Bad message", SftpConstants.statusMessage(SftpConstants.SSH_FX_BAD_MESSAGE))
    }

    @Test
    fun `statusMessage for SSH_FX_NO_CONNECTION`() {
        assertEquals("No connection", SftpConstants.statusMessage(SftpConstants.SSH_FX_NO_CONNECTION))
    }

    @Test
    fun `statusMessage for SSH_FX_CONNECTION_LOST`() {
        assertEquals("Connection lost", SftpConstants.statusMessage(SftpConstants.SSH_FX_CONNECTION_LOST))
    }

    @Test
    fun `statusMessage for SSH_FX_OP_UNSUPPORTED`() {
        assertEquals("Operation unsupported", SftpConstants.statusMessage(SftpConstants.SSH_FX_OP_UNSUPPORTED))
    }

    @Test
    fun `statusMessage for unknown code returns fallback`() {
        assertEquals("Unknown error (99)", SftpConstants.statusMessage(99))
    }

    @Test
    fun `statusMessage for negative code returns fallback`() {
        assertEquals("Unknown error (-1)", SftpConstants.statusMessage(-1))
    }

    @Test
    fun `statusMessage for code 100 returns fallback`() {
        assertEquals("Unknown error (100)", SftpConstants.statusMessage(100))
    }

    // =========================================================================
    // POSIX file type bits
    // =========================================================================

    @Test
    fun `S_IFMT mask value`() {
        assertEquals(0xF000, SftpConstants.S_IFMT)
    }

    @Test
    fun `S_IFREG value`() {
        assertEquals(0x8000, SftpConstants.S_IFREG)
    }

    @Test
    fun `S_IFDIR value`() {
        assertEquals(0x4000, SftpConstants.S_IFDIR)
    }

    @Test
    fun `S_IFLNK value`() {
        assertEquals(0xA000, SftpConstants.S_IFLNK)
    }

    @Test
    fun `S_IFCHR value`() {
        assertEquals(0x2000, SftpConstants.S_IFCHR)
    }

    @Test
    fun `S_IFBLK value`() {
        assertEquals(0x6000, SftpConstants.S_IFBLK)
    }

    @Test
    fun `S_IFIFO value`() {
        assertEquals(0x1000, SftpConstants.S_IFIFO)
    }

    @Test
    fun `S_IFSOCK value`() {
        assertEquals(0xC000, SftpConstants.S_IFSOCK)
    }

    @Test
    fun `file type can be extracted from permissions using S_IFMT mask`() {
        val permissions = 0x81A4 // regular file with mode 0644
        val fileType = permissions and SftpConstants.S_IFMT
        assertEquals(SftpConstants.S_IFREG, fileType)
    }

    @Test
    fun `directory type can be extracted from permissions`() {
        val permissions = 0x41ED // directory with mode 0755
        val fileType = permissions and SftpConstants.S_IFMT
        assertEquals(SftpConstants.S_IFDIR, fileType)
    }

    // =========================================================================
    // Buffer sizes
    // =========================================================================

    @Test
    fun `TRANSFER_BUFFER_SIZE is 64KB`() {
        assertEquals(65536, SftpConstants.TRANSFER_BUFFER_SIZE)
    }

    @Test
    fun `MAX_PACKET_SIZE is 256KB`() {
        assertEquals(256 * 1024, SftpConstants.MAX_PACKET_SIZE)
    }

    @Test
    fun `MAX_PACKET_SIZE is larger than TRANSFER_BUFFER_SIZE`() {
        assertTrue(SftpConstants.MAX_PACKET_SIZE > SftpConstants.TRANSFER_BUFFER_SIZE)
    }
}
