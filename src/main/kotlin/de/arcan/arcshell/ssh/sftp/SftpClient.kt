package de.arcan.arcshell.ssh.sftp

import de.arcan.arcshell.ssh.nio.AsyncSessionChannel
import de.arcan.arcshell.ssh.transport.SshBufferReader
import de.arcan.arcshell.ssh.transport.SshBufferWriter
import kotlinx.coroutines.runBlocking
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicInteger

/**
 * SFTP v3 client (draft-ietf-secsh-filexfer-02).
 *
 * Wraps an [AsyncSessionChannel] after `requestSubsystem("sftp")`. All
 * public operations are blocking — call from a background thread
 * (e.g. Dispatchers.IO). Internally bridges to the async channel via
 * [runBlocking].
 *
 * SFTP framing: each message is `uint32 length | byte type | payload`.
 * The channel's raw I/O carries the SFTP byte stream; chunks from
 * [AsyncSessionChannel.read] may not align with packet boundaries, so we
 * buffer internally.
 */
class SftpClient(private val channel: AsyncSessionChannel) {

    private val nextRequestId = AtomicInteger(1)
    private var pendingData = ByteArray(0)
    private var _serverVersion = 0
    val serverVersion: Int get() = _serverVersion

    /**
     * Initialize the SFTP session. Must be called before any other operation.
     * Sends SSH_FXP_INIT(version=3), expects SSH_FXP_VERSION.
     * @return the negotiated SFTP version (server's version)
     */
    fun init(): Int {
        val payload = SshBufferWriter()
            .writeUint32(SftpConstants.SFTP_VERSION)
            .toByteArray()
        sendPacket(SftpConstants.SSH_FXP_INIT, payload)

        val (type, reader) = receivePacket()
        if (type != SftpConstants.SSH_FXP_VERSION) {
            throw SftpException(SftpConstants.SSH_FX_BAD_MESSAGE, "Expected VERSION, got $type")
        }
        _serverVersion = reader.readUint32().toInt()
        // Drain any server extensions
        while (reader.remaining > 0) {
            try { reader.readUtf8(); reader.readUtf8() } catch (_: Exception) { break }
        }
        return _serverVersion
    }

    /** Canonicalize a path (resolve ".", "..", symlinks). */
    fun realpath(path: String): String {
        val id = nextRequestId.getAndIncrement()
        sendRequest(SftpConstants.SSH_FXP_REALPATH, id) { writeUtf8(path) }
        return expectName(id)
    }

    /** Stat a path, following symlinks. */
    fun stat(path: String): SftpAttributes {
        val id = nextRequestId.getAndIncrement()
        sendRequest(SftpConstants.SSH_FXP_STAT, id) { writeUtf8(path) }
        return expectAttrs()
    }

    /** Stat a path without following symlinks. */
    fun lstat(path: String): SftpAttributes {
        val id = nextRequestId.getAndIncrement()
        sendRequest(SftpConstants.SSH_FXP_LSTAT, id) { writeUtf8(path) }
        return expectAttrs()
    }

    /** Stat an open file handle. */
    fun fstat(handle: ByteArray): SftpAttributes {
        val id = nextRequestId.getAndIncrement()
        sendRequest(SftpConstants.SSH_FXP_FSTAT, id) { writeString(handle) }
        return expectAttrs()
    }

    /** Set attributes on a path. */
    fun setstat(path: String, attrs: SftpAttributes) {
        val id = nextRequestId.getAndIncrement()
        sendRequest(SftpConstants.SSH_FXP_SETSTAT, id) {
            writeUtf8(path)
            attrs.encode(this)
        }
        expectOkStatus()
    }

    /** Open a directory for reading. Returns a handle. */
    fun openDir(path: String): ByteArray {
        val id = nextRequestId.getAndIncrement()
        sendRequest(SftpConstants.SSH_FXP_OPENDIR, id) { writeUtf8(path) }
        return expectHandle()
    }

    /**
     * Read directory entries from an open handle. Returns an empty list on EOF.
     * Call repeatedly until empty list is returned.
     */
    fun readDir(handle: ByteArray): List<SftpFile> {
        val id = nextRequestId.getAndIncrement()
        sendRequest(SftpConstants.SSH_FXP_READDIR, id) { writeString(handle) }

        val (type, reader) = receivePacket()
        return when (type) {
            SftpConstants.SSH_FXP_NAME -> parseNameList(reader)
            SftpConstants.SSH_FXP_STATUS -> {
                reader.readUint32() // request-id
                val code = reader.readUint32().toInt()
                if (code == SftpConstants.SSH_FX_EOF) return emptyList()
                throw SftpException(code, readStatusMessage(reader))
            }
            else -> throw unexpectedPacket(type)
        }
    }

    /** Close a file or directory handle. */
    fun closeHandle(handle: ByteArray) {
        val id = nextRequestId.getAndIncrement()
        sendRequest(SftpConstants.SSH_FXP_CLOSE, id) { writeString(handle) }
        expectOkStatus()
    }

    /**
     * List all entries in a directory (excluding "." and "..").
     * Handles openDir/readDir loop/closeHandle internally.
     */
    fun listDirectory(path: String): List<SftpFile> {
        val handle = openDir(path)
        val entries = mutableListOf<SftpFile>()
        try {
            while (true) {
                val batch = readDir(handle)
                if (batch.isEmpty()) break
                entries.addAll(batch)
            }
        } finally {
            closeHandle(handle)
        }
        return entries.filter { it.filename != "." && it.filename != ".." }
    }

    /** Open a file. Returns a handle for subsequent read/write/close. */
    fun openFile(path: String, flags: Int, attrs: SftpAttributes = SftpAttributes.EMPTY): ByteArray {
        val id = nextRequestId.getAndIncrement()
        sendRequest(SftpConstants.SSH_FXP_OPEN, id) {
            writeUtf8(path)
            writeUint32(flags)
            attrs.encode(this)
        }
        return expectHandle()
    }

    /** Read up to [length] bytes from a file at [offset]. Empty on EOF. */
    fun readFile(handle: ByteArray, offset: Long, length: Int): ByteArray {
        val id = nextRequestId.getAndIncrement()
        sendRequest(SftpConstants.SSH_FXP_READ, id) {
            writeString(handle)
            writeUint64(offset)
            writeUint32(length)
        }

        val (type, reader) = receivePacket()
        return when (type) {
            SftpConstants.SSH_FXP_DATA -> {
                reader.readUint32() // request-id
                reader.readString()
            }
            SftpConstants.SSH_FXP_STATUS -> {
                reader.readUint32()
                val code = reader.readUint32().toInt()
                if (code == SftpConstants.SSH_FX_EOF) return ByteArray(0)
                throw SftpException(code, readStatusMessage(reader))
            }
            else -> throw unexpectedPacket(type)
        }
    }

    /** Write data to a file at [offset]. */
    fun writeFile(handle: ByteArray, offset: Long, data: ByteArray) {
        val id = nextRequestId.getAndIncrement()
        sendRequest(SftpConstants.SSH_FXP_WRITE, id) {
            writeString(handle)
            writeUint64(offset)
            writeString(data)
        }
        expectOkStatus()
    }

    /** Create a directory. Default permissions 0755. */
    fun mkdir(path: String, attrs: SftpAttributes = SftpAttributes(permissions = 0x1ED)) {
        val id = nextRequestId.getAndIncrement()
        sendRequest(SftpConstants.SSH_FXP_MKDIR, id) {
            writeUtf8(path)
            attrs.encode(this)
        }
        expectOkStatus()
    }

    /** Remove an empty directory. */
    fun rmdir(path: String) {
        val id = nextRequestId.getAndIncrement()
        sendRequest(SftpConstants.SSH_FXP_RMDIR, id) { writeUtf8(path) }
        expectOkStatus()
    }

    /** Delete a file. */
    fun remove(path: String) {
        val id = nextRequestId.getAndIncrement()
        sendRequest(SftpConstants.SSH_FXP_REMOVE, id) { writeUtf8(path) }
        expectOkStatus()
    }

    /** Rename a file or directory. */
    fun rename(oldPath: String, newPath: String) {
        val id = nextRequestId.getAndIncrement()
        sendRequest(SftpConstants.SSH_FXP_RENAME, id) {
            writeUtf8(oldPath)
            writeUtf8(newPath)
        }
        expectOkStatus()
    }

    /** Read the target of a symbolic link. */
    fun readlink(path: String): String {
        val id = nextRequestId.getAndIncrement()
        sendRequest(SftpConstants.SSH_FXP_READLINK, id) { writeUtf8(path) }
        return expectName(id)
    }

    /** Create a symbolic link (OpenSSH argument order: targetPath, linkPath). */
    fun symlink(targetPath: String, linkPath: String) {
        val id = nextRequestId.getAndIncrement()
        sendRequest(SftpConstants.SSH_FXP_SYMLINK, id) {
            writeUtf8(targetPath)
            writeUtf8(linkPath)
        }
        expectOkStatus()
    }

    /**
     * Download a remote file to a local output stream.
     * @param onProgress callback(bytesTransferred, totalSize). totalSize is -1 if unknown.
     */
    fun downloadFile(
        remotePath: String,
        output: OutputStream,
        onProgress: ((Long, Long) -> Unit)? = null
    ) {
        val fileAttrs = stat(remotePath)
        val totalSize = fileAttrs.size
        val handle = openFile(remotePath, SftpConstants.SSH_FXF_READ)
        try {
            var offset = 0L
            while (true) {
                val data = readFile(handle, offset, SftpConstants.TRANSFER_BUFFER_SIZE)
                if (data.isEmpty()) break
                output.write(data)
                offset += data.size
                onProgress?.invoke(offset, totalSize)
            }
        } finally {
            closeHandle(handle)
        }
    }

    /**
     * Upload a local input stream to a remote file.
     * @param size total byte count for progress reporting (-1 if unknown)
     * @param onProgress callback(bytesTransferred, totalSize)
     */
    fun uploadFile(
        input: InputStream,
        remotePath: String,
        size: Long = -1,
        onProgress: ((Long, Long) -> Unit)? = null
    ) {
        val handle = openFile(
            remotePath,
            SftpConstants.SSH_FXF_WRITE or SftpConstants.SSH_FXF_CREAT or SftpConstants.SSH_FXF_TRUNC,
            SftpAttributes(permissions = 0x81A4) // S_IFREG | 0644
        )
        try {
            var offset = 0L
            val buffer = ByteArray(SftpConstants.TRANSFER_BUFFER_SIZE)
            while (true) {
                val bytesRead = input.read(buffer)
                if (bytesRead <= 0) break
                writeFile(handle, offset, buffer.copyOf(bytesRead))
                offset += bytesRead
                onProgress?.invoke(offset, size)
            }
        } finally {
            closeHandle(handle)
        }
    }

    /** Close the SFTP session and the underlying channel. */
    fun close() {
        try { runBlocking { channel.sendEof() } } catch (_: Exception) {}
        try { runBlocking { channel.close() } } catch (_: Exception) {}
    }

    // ---- Wire format helpers ----

    private fun sendRequest(
        type: Int,
        requestId: Int,
        block: SshBufferWriter.() -> Unit
    ) {
        val writer = SshBufferWriter()
        writer.writeUint32(requestId)
        writer.block()
        sendPacket(type, writer.toByteArray())
    }

    private fun sendPacket(type: Int, payload: ByteArray) {
        val length = 1 + payload.size
        val packet = SshBufferWriter(4 + length)
            .writeUint32(length)
            .writeByte(type)
            .writeBytes(payload)
            .toByteArray()
        runBlocking { channel.write(packet) }
    }

    private fun receivePacket(): Pair<Int, SshBufferReader> {
        val lengthBytes = readExact(4)
        val length = SshBufferReader(lengthBytes).readUint32().toInt()
        if (length <= 0 || length > SftpConstants.MAX_PACKET_SIZE) {
            throw SftpException(SftpConstants.SSH_FX_BAD_MESSAGE, "Invalid packet length: $length")
        }
        val data = readExact(length)
        val type = data[0].toInt() and 0xFF
        return type to SshBufferReader(data, 1)
    }

    /** Accumulate channel chunks until [count] bytes are available. */
    private fun readExact(count: Int): ByteArray {
        while (pendingData.size < count) {
            val chunk = runBlocking { channel.read() }
            if (chunk.isEmpty()) throw IOException("SFTP channel closed")
            pendingData = pendingData + chunk
        }
        val result = pendingData.copyOfRange(0, count)
        pendingData = pendingData.copyOfRange(count, pendingData.size)
        return result
    }

    private fun expectHandle(): ByteArray {
        val (type, reader) = receivePacket()
        return when (type) {
            SftpConstants.SSH_FXP_HANDLE -> {
                reader.readUint32() // request-id
                reader.readString()
            }
            SftpConstants.SSH_FXP_STATUS -> {
                reader.readUint32()
                val code = reader.readUint32().toInt()
                throw SftpException(code, readStatusMessage(reader))
            }
            else -> throw unexpectedPacket(type)
        }
    }

    private fun expectAttrs(): SftpAttributes {
        val (type, reader) = receivePacket()
        return when (type) {
            SftpConstants.SSH_FXP_ATTRS -> {
                reader.readUint32() // request-id
                SftpAttributes.decode(reader)
            }
            SftpConstants.SSH_FXP_STATUS -> {
                reader.readUint32()
                val code = reader.readUint32().toInt()
                throw SftpException(code, readStatusMessage(reader))
            }
            else -> throw unexpectedPacket(type)
        }
    }

    private fun expectName(@Suppress("UNUSED_PARAMETER") requestId: Int): String {
        val (type, reader) = receivePacket()
        return when (type) {
            SftpConstants.SSH_FXP_NAME -> {
                reader.readUint32() // request-id
                val count = reader.readUint32().toInt()
                if (count < 1) throw SftpException(SftpConstants.SSH_FX_NO_SUCH_FILE)
                reader.readUtf8()
            }
            SftpConstants.SSH_FXP_STATUS -> {
                reader.readUint32()
                val code = reader.readUint32().toInt()
                throw SftpException(code, readStatusMessage(reader))
            }
            else -> throw unexpectedPacket(type)
        }
    }

    private fun expectOkStatus() {
        val (type, reader) = receivePacket()
        if (type != SftpConstants.SSH_FXP_STATUS) throw unexpectedPacket(type)
        reader.readUint32() // request-id
        val code = reader.readUint32().toInt()
        if (code != SftpConstants.SSH_FX_OK) {
            throw SftpException(code, readStatusMessage(reader))
        }
    }

    private fun parseNameList(reader: SshBufferReader): List<SftpFile> {
        reader.readUint32() // request-id
        val count = reader.readUint32().toInt()
        return List(count) {
            val filename = reader.readUtf8()
            val longname = reader.readUtf8()
            val attrs = SftpAttributes.decode(reader)
            SftpFile(filename, longname, attrs)
        }
    }

    private fun readStatusMessage(reader: SshBufferReader): String =
        if (reader.remaining > 0) try { reader.readUtf8() } catch (_: Exception) { "" } else ""

    private fun unexpectedPacket(type: Int) =
        SftpException(SftpConstants.SSH_FX_BAD_MESSAGE, "Unexpected packet type: $type")
}
