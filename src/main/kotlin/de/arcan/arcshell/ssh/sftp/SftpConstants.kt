package de.arcan.arcshell.ssh.sftp

/**
 * SFTP protocol constants per draft-ietf-secsh-filexfer-02 (SFTP v3).
 */
object SftpConstants {
    /** Protocol version we support. */
    const val SFTP_VERSION = 3

    // --- Packet types ---
    const val SSH_FXP_INIT = 1
    const val SSH_FXP_VERSION = 2
    const val SSH_FXP_OPEN = 3
    const val SSH_FXP_CLOSE = 4
    const val SSH_FXP_READ = 5
    const val SSH_FXP_WRITE = 6
    const val SSH_FXP_LSTAT = 7
    const val SSH_FXP_FSTAT = 8
    const val SSH_FXP_SETSTAT = 9
    const val SSH_FXP_FSETSTAT = 10
    const val SSH_FXP_OPENDIR = 11
    const val SSH_FXP_READDIR = 12
    const val SSH_FXP_REMOVE = 13
    const val SSH_FXP_MKDIR = 14
    const val SSH_FXP_RMDIR = 15
    const val SSH_FXP_REALPATH = 16
    const val SSH_FXP_STAT = 17
    const val SSH_FXP_RENAME = 18
    const val SSH_FXP_READLINK = 19
    const val SSH_FXP_SYMLINK = 20

    // --- Response types ---
    const val SSH_FXP_STATUS = 101
    const val SSH_FXP_HANDLE = 102
    const val SSH_FXP_DATA = 103
    const val SSH_FXP_NAME = 104
    const val SSH_FXP_ATTRS = 105

    // --- Attribute flags ---
    const val SSH_FILEXFER_ATTR_SIZE = 0x00000001
    const val SSH_FILEXFER_ATTR_UIDGID = 0x00000002
    const val SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004
    const val SSH_FILEXFER_ATTR_ACMODTIME = 0x00000008
    @Suppress("INTEGER_OVERFLOW")
    const val SSH_FILEXFER_ATTR_EXTENDED = 0x80000000.toInt()

    // --- Open flags (SSH_FXF_*) ---
    const val SSH_FXF_READ = 0x00000001
    const val SSH_FXF_WRITE = 0x00000002
    const val SSH_FXF_APPEND = 0x00000004
    const val SSH_FXF_CREAT = 0x00000008
    const val SSH_FXF_TRUNC = 0x00000010
    const val SSH_FXF_EXCL = 0x00000020

    // --- Status codes (SSH_FX_*) ---
    const val SSH_FX_OK = 0
    const val SSH_FX_EOF = 1
    const val SSH_FX_NO_SUCH_FILE = 2
    const val SSH_FX_PERMISSION_DENIED = 3
    const val SSH_FX_FAILURE = 4
    const val SSH_FX_BAD_MESSAGE = 5
    const val SSH_FX_NO_CONNECTION = 6
    const val SSH_FX_CONNECTION_LOST = 7
    const val SSH_FX_OP_UNSUPPORTED = 8

    // --- POSIX file type bits (upper 4 bits of permissions) ---
    const val S_IFMT = 0xF000
    const val S_IFREG = 0x8000
    const val S_IFDIR = 0x4000
    const val S_IFLNK = 0xA000
    const val S_IFCHR = 0x2000
    const val S_IFBLK = 0x6000
    const val S_IFIFO = 0x1000
    const val S_IFSOCK = 0xC000

    /** Max data per read/write request (64 KB). */
    const val TRANSFER_BUFFER_SIZE = 65536

    /** Max SFTP packet we'll accept (256 KB safety limit). */
    const val MAX_PACKET_SIZE = 256 * 1024

    fun statusMessage(code: Int): String = when (code) {
        SSH_FX_OK -> "OK"
        SSH_FX_EOF -> "End of file"
        SSH_FX_NO_SUCH_FILE -> "No such file"
        SSH_FX_PERMISSION_DENIED -> "Permission denied"
        SSH_FX_FAILURE -> "Failure"
        SSH_FX_BAD_MESSAGE -> "Bad message"
        SSH_FX_NO_CONNECTION -> "No connection"
        SSH_FX_CONNECTION_LOST -> "Connection lost"
        SSH_FX_OP_UNSUPPORTED -> "Operation unsupported"
        else -> "Unknown error ($code)"
    }
}
