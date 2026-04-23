package de.arcan.arcshell.ssh.sftp

/**
 * An SFTP directory entry as returned by SSH_FXP_READDIR (draft-ietf-secsh-filexfer-02 §6.7).
 *
 * @param filename the entry name (without path)
 * @param longname ls-style string from the server (e.g. "-rwxr-xr-x  1 root root  4096 Jan  1 00:00 file.txt")
 * @param attrs file attributes (size, permissions, timestamps, etc.)
 */
data class SftpFile(
    val filename: String,
    val longname: String,
    val attrs: SftpAttributes
) {
    val isDirectory: Boolean get() = attrs.isDirectory
    val isRegularFile: Boolean get() = attrs.isRegularFile
    val isSymlink: Boolean get() = attrs.isSymlink
    val size: Long get() = attrs.size
    val permissions: Int get() = attrs.permissions

    /** Human-readable file size (e.g. "4.2 MB"). */
    fun formattedSize(): String {
        val s = attrs.size
        if (s < 0) return ""
        if (s < 1024) return "$s B"
        if (s < 1024 * 1024) return "${s / 1024} KB"
        if (s < 1024L * 1024 * 1024) return String.format("%.1f MB", s / (1024.0 * 1024))
        return String.format("%.1f GB", s / (1024.0 * 1024 * 1024))
    }
}
