package de.arcan.arcshell.ssh.sftp

import de.arcan.arcshell.ssh.transport.SshBufferReader
import de.arcan.arcshell.ssh.transport.SshBufferWriter

/**
 * SFTP file attributes (draft-ietf-secsh-filexfer-02 §5).
 *
 * Wire format:
 * ```
 * uint32  flags
 * [uint64 size]         if SSH_FILEXFER_ATTR_SIZE
 * [uint32 uid, gid]     if SSH_FILEXFER_ATTR_UIDGID
 * [uint32 permissions]  if SSH_FILEXFER_ATTR_PERMISSIONS
 * [uint32 atime, mtime] if SSH_FILEXFER_ATTR_ACMODTIME
 * [extended_pairs...]   if SSH_FILEXFER_ATTR_EXTENDED
 * ```
 */
data class SftpAttributes(
    val size: Long = -1,
    val uid: Int = -1,
    val gid: Int = -1,
    val permissions: Int = -1,
    val atime: Long = -1,
    val mtime: Long = -1
) {
    val isDirectory: Boolean
        get() = permissions >= 0 && (permissions and SftpConstants.S_IFMT) == SftpConstants.S_IFDIR

    val isRegularFile: Boolean
        get() = permissions >= 0 && (permissions and SftpConstants.S_IFMT) == SftpConstants.S_IFREG

    val isSymlink: Boolean
        get() = permissions >= 0 && (permissions and SftpConstants.S_IFMT) == SftpConstants.S_IFLNK

    val fileType: FileType
        get() = when {
            permissions < 0 -> FileType.UNKNOWN
            isDirectory -> FileType.DIRECTORY
            isRegularFile -> FileType.REGULAR_FILE
            isSymlink -> FileType.SYMLINK
            (permissions and SftpConstants.S_IFMT) == SftpConstants.S_IFCHR -> FileType.CHARACTER_DEVICE
            (permissions and SftpConstants.S_IFMT) == SftpConstants.S_IFBLK -> FileType.BLOCK_DEVICE
            (permissions and SftpConstants.S_IFMT) == SftpConstants.S_IFIFO -> FileType.FIFO
            (permissions and SftpConstants.S_IFMT) == SftpConstants.S_IFSOCK -> FileType.SOCKET
            else -> FileType.UNKNOWN
        }

    /** POSIX permission string like "rwxr-xr-x". */
    fun permissionString(): String {
        if (permissions < 0) return "---------"
        return buildString {
            append(if (permissions and 0x100 != 0) 'r' else '-')
            append(if (permissions and 0x080 != 0) 'w' else '-')
            append(if (permissions and 0x040 != 0) 'x' else '-')
            append(if (permissions and 0x020 != 0) 'r' else '-')
            append(if (permissions and 0x010 != 0) 'w' else '-')
            append(if (permissions and 0x008 != 0) 'x' else '-')
            append(if (permissions and 0x004 != 0) 'r' else '-')
            append(if (permissions and 0x002 != 0) 'w' else '-')
            append(if (permissions and 0x001 != 0) 'x' else '-')
        }
    }

    /** File type prefix character for ls-style display. */
    fun typeChar(): Char = when (fileType) {
        FileType.DIRECTORY -> 'd'
        FileType.SYMLINK -> 'l'
        FileType.CHARACTER_DEVICE -> 'c'
        FileType.BLOCK_DEVICE -> 'b'
        FileType.FIFO -> 'p'
        FileType.SOCKET -> 's'
        else -> '-'
    }

    /** Encode to SFTP wire format. */
    fun encode(writer: SshBufferWriter): SshBufferWriter {
        var flags = 0
        if (size >= 0) flags = flags or SftpConstants.SSH_FILEXFER_ATTR_SIZE
        if (uid >= 0 && gid >= 0) flags = flags or SftpConstants.SSH_FILEXFER_ATTR_UIDGID
        if (permissions >= 0) flags = flags or SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS
        if (atime >= 0 && mtime >= 0) flags = flags or SftpConstants.SSH_FILEXFER_ATTR_ACMODTIME

        writer.writeUint32(flags)
        if (size >= 0) writer.writeUint64(size)
        if (uid >= 0 && gid >= 0) {
            writer.writeUint32(uid)
            writer.writeUint32(gid)
        }
        if (permissions >= 0) writer.writeUint32(permissions)
        if (atime >= 0 && mtime >= 0) {
            writer.writeUint32(atime.toInt())
            writer.writeUint32(mtime.toInt())
        }
        return writer
    }

    enum class FileType {
        REGULAR_FILE, DIRECTORY, SYMLINK,
        CHARACTER_DEVICE, BLOCK_DEVICE, FIFO, SOCKET, UNKNOWN
    }

    companion object {
        val EMPTY = SftpAttributes()

        /** Decode from SFTP wire format. */
        fun decode(reader: SshBufferReader): SftpAttributes {
            val flags = reader.readUint32().toInt()

            val size = if (flags and SftpConstants.SSH_FILEXFER_ATTR_SIZE != 0)
                reader.readUint64() else -1L

            var uid = -1
            var gid = -1
            if (flags and SftpConstants.SSH_FILEXFER_ATTR_UIDGID != 0) {
                uid = reader.readUint32().toInt()
                gid = reader.readUint32().toInt()
            }

            val permissions = if (flags and SftpConstants.SSH_FILEXFER_ATTR_PERMISSIONS != 0)
                reader.readUint32().toInt() else -1

            var atime = -1L
            var mtime = -1L
            if (flags and SftpConstants.SSH_FILEXFER_ATTR_ACMODTIME != 0) {
                atime = reader.readUint32()
                mtime = reader.readUint32()
            }

            if (flags and SftpConstants.SSH_FILEXFER_ATTR_EXTENDED != 0) {
                val count = reader.readUint32().toInt()
                repeat(count) {
                    reader.readString() // type
                    reader.readString() // data
                }
            }

            return SftpAttributes(size, uid, gid, permissions, atime, mtime)
        }
    }
}
