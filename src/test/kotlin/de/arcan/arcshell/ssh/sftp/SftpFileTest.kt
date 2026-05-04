package de.arcan.arcshell.ssh.sftp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SftpFileTest {

    private fun makeFile(
        filename: String = "test.txt",
        longname: String = "-rw-r--r-- 1 root root 1234 Jan 1 00:00 test.txt",
        size: Long = 1234,
        permissions: Int = 0x81A4 // S_IFREG | 0644
    ): SftpFile {
        return SftpFile(
            filename = filename,
            longname = longname,
            attrs = SftpAttributes(size = size, permissions = permissions)
        )
    }

    // --- formattedSize: bytes ---

    @Test
    fun `formattedSize returns bytes for small files`() {
        val file = makeFile(size = 0)
        assertEquals("0 B", file.formattedSize())
    }

    @Test
    fun `formattedSize returns bytes for 1 byte`() {
        val file = makeFile(size = 1)
        assertEquals("1 B", file.formattedSize())
    }

    @Test
    fun `formattedSize returns bytes up to 1023`() {
        val file = makeFile(size = 1023)
        assertEquals("1023 B", file.formattedSize())
    }

    // --- formattedSize: KB ---

    @Test
    fun `formattedSize returns KB for 1024 bytes`() {
        val file = makeFile(size = 1024)
        assertEquals("1 KB", file.formattedSize())
    }

    @Test
    fun `formattedSize returns KB for values under 1MB`() {
        val file = makeFile(size = 512 * 1024)
        assertEquals("512 KB", file.formattedSize())
    }

    @Test
    fun `formattedSize returns KB up to boundary`() {
        val file = makeFile(size = 1024 * 1024 - 1)
        assertEquals("1023 KB", file.formattedSize())
    }

    // --- formattedSize: MB ---

    @Test
    fun `formattedSize returns MB for 1MB`() {
        val file = makeFile(size = 1024L * 1024)
        assertTrue(file.formattedSize().endsWith(" MB"))
    }

    @Test
    fun `formattedSize returns MB with decimal`() {
        val file = makeFile(size = (4.2 * 1024 * 1024).toLong())
        val result = file.formattedSize()
        assertTrue("Expected MB format but got: $result", result.endsWith(" MB"))
        assertTrue("Expected around 4 MB but got: $result", result.contains("4"))
    }

    @Test
    fun `formattedSize returns MB up to boundary`() {
        val file = makeFile(size = 1024L * 1024 * 1024 - 1)
        val result = file.formattedSize()
        assertTrue("Expected MB format but got: $result", result.endsWith(" MB"))
    }

    // --- formattedSize: GB ---

    @Test
    fun `formattedSize returns GB for 1GB`() {
        val file = makeFile(size = 1024L * 1024 * 1024)
        assertTrue(file.formattedSize().endsWith(" GB"))
    }

    @Test
    fun `formattedSize returns GB for large files`() {
        val file = makeFile(size = 5L * 1024 * 1024 * 1024)
        assertTrue(file.formattedSize().endsWith(" GB"))
    }

    @Test
    fun `formattedSize returns GB with decimal`() {
        val file = makeFile(size = (2.5 * 1024 * 1024 * 1024).toLong())
        val result = file.formattedSize()
        assertTrue("Expected GB format but got: $result", result.endsWith(" GB"))
        assertTrue("Expected around 2.5 GB but got: $result", result.contains("2"))
    }

    // --- formattedSize: negative ---

    @Test
    fun `formattedSize returns empty string for negative size`() {
        val file = makeFile(size = -1)
        assertEquals("", file.formattedSize())
    }

    @Test
    fun `formattedSize returns empty string for large negative size`() {
        val file = makeFile(size = -999)
        assertEquals("", file.formattedSize())
    }

    // --- isDirectory ---

    @Test
    fun `isDirectory returns true for directory`() {
        val dir = makeFile(permissions = 0x41ED) // S_IFDIR | 0755
        assertTrue(dir.isDirectory)
    }

    @Test
    fun `isDirectory returns false for regular file`() {
        val file = makeFile(permissions = 0x81A4) // S_IFREG | 0644
        assertFalse(file.isDirectory)
    }

    @Test
    fun `isDirectory returns false for symlink`() {
        val link = makeFile(permissions = 0xA1FF) // S_IFLNK | 0777
        assertFalse(link.isDirectory)
    }

    // --- isRegularFile ---

    @Test
    fun `isRegularFile returns true for regular file`() {
        val file = makeFile(permissions = 0x81A4) // S_IFREG | 0644
        assertTrue(file.isRegularFile)
    }

    @Test
    fun `isRegularFile returns false for directory`() {
        val dir = makeFile(permissions = 0x41ED) // S_IFDIR | 0755
        assertFalse(dir.isRegularFile)
    }

    @Test
    fun `isRegularFile returns false for symlink`() {
        val link = makeFile(permissions = 0xA1FF) // S_IFLNK | 0777
        assertFalse(link.isRegularFile)
    }

    // --- isSymlink ---

    @Test
    fun `isSymlink returns true for symbolic link`() {
        val link = makeFile(permissions = 0xA1FF) // S_IFLNK | 0777
        assertTrue(link.isSymlink)
    }

    @Test
    fun `isSymlink returns false for regular file`() {
        val file = makeFile(permissions = 0x81A4) // S_IFREG | 0644
        assertFalse(file.isSymlink)
    }

    @Test
    fun `isSymlink returns false for directory`() {
        val dir = makeFile(permissions = 0x41ED) // S_IFDIR | 0755
        assertFalse(dir.isSymlink)
    }

    // --- size delegation ---

    @Test
    fun `size delegates to attrs size`() {
        val file = makeFile(size = 98765)
        assertEquals(98765L, file.size)
    }

    @Test
    fun `size returns -1 for unknown size`() {
        val file = SftpFile(
            filename = "test",
            longname = "test",
            attrs = SftpAttributes()
        )
        assertEquals(-1L, file.size)
    }

    // --- permissions delegation ---

    @Test
    fun `permissions delegates to attrs permissions`() {
        val file = makeFile(permissions = 0x81A4)
        assertEquals(0x81A4, file.permissions)
    }

    @Test
    fun `permissions returns -1 for unknown permissions`() {
        val file = SftpFile(
            filename = "test",
            longname = "test",
            attrs = SftpAttributes()
        )
        assertEquals(-1, file.permissions)
    }

    // --- data class properties ---

    @Test
    fun `filename is preserved`() {
        val file = makeFile(filename = "my_script.sh")
        assertEquals("my_script.sh", file.filename)
    }

    @Test
    fun `longname is preserved`() {
        val ln = "-rwxr-xr-x 1 user group 4096 Apr 13 12:00 script.sh"
        val file = makeFile(longname = ln)
        assertEquals(ln, file.longname)
    }

    // --- edge cases: no permissions set ---

    @Test
    fun `isDirectory returns false when permissions is -1`() {
        val file = SftpFile("f", "f", SftpAttributes())
        assertFalse(file.isDirectory)
    }

    @Test
    fun `isRegularFile returns false when permissions is -1`() {
        val file = SftpFile("f", "f", SftpAttributes())
        assertFalse(file.isRegularFile)
    }

    @Test
    fun `isSymlink returns false when permissions is -1`() {
        val file = SftpFile("f", "f", SftpAttributes())
        assertFalse(file.isSymlink)
    }
}
