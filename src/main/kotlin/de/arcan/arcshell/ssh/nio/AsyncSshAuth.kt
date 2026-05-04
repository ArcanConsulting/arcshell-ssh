package de.arcan.arcshell.ssh.nio

import de.arcan.arcshell.ssh.SshMsgType
import de.arcan.arcshell.ssh.SshService
import de.arcan.arcshell.ssh.auth.AuthResult
import de.arcan.arcshell.ssh.auth.Prompt
import de.arcan.arcshell.ssh.transport.SshBufferReader
import de.arcan.arcshell.ssh.transport.SshBufferWriter
import de.arcan.arcshell.ssh.transport.SshProtocolException

/**
 * Async SSH user authentication dispatcher (RFC 4252).
 *
 * Non-blocking port of [de.arcan.arcshell.ssh.auth.SshAuthenticator].
 * Uses [AsyncSshTransport] for packet I/O, with all methods being
 * suspend functions suitable for coroutine-based callers.
 */
class AsyncSshAuthenticator(private val transport: AsyncSshTransport) {

    /** Request the ssh-userauth service. Must be called before any auth method. */
    suspend fun requestAuthService() {
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.SERVICE_REQUEST)
            .writeUtf8(SshService.USERAUTH)
            .toByteArray()
        transport.sendPacket(payload)

        // Server may send EXT_INFO (7), GLOBAL_REQUEST, etc. before SERVICE_ACCEPT
        while (true) {
            val response = transport.receivePacket()
            when (response[0].toInt()) {
                SshMsgType.SERVICE_ACCEPT -> return
                7 -> {} // EXT_INFO (RFC 8308) -- skip
                SshMsgType.GLOBAL_REQUEST -> {} // e.g. hostkeys-00@openssh.com -- skip
                else -> throw SshProtocolException(
                    "Service request for ${SshService.USERAUTH} rejected: got ${response[0]}"
                )
            }
        }
    }

    /** Try password authentication. */
    suspend fun authPassword(username: String, password: String): AuthResult {
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.USERAUTH_REQUEST)
            .writeUtf8(username)
            .writeUtf8(SshService.CONNECTION)
            .writeUtf8("password")
            .writeBoolean(false) // not changing password
            .writeUtf8(password)
            .toByteArray()
        transport.sendPacket(payload)
        return readAuthResponse()
    }

    /**
     * Try public key authentication.
     * @param username SSH username
     * @param keyType e.g. "ssh-ed25519", "rsa-sha2-256"
     * @param publicKeyBlob the public key in SSH wire format
     * @param signer callback that signs the auth data with the private key
     */
    suspend fun authPublicKey(
        username: String,
        keyType: String,
        publicKeyBlob: ByteArray,
        signer: (ByteArray) -> ByteArray
    ): AuthResult {
        // RFC 8332: use rsa-sha2-256 algorithm name for RSA keys (ssh-rsa SHA-1 disabled in OpenSSH 8.8+)
        val sigAlgorithm = if (keyType == "ssh-rsa") "rsa-sha2-256" else keyType

        // Step 1: Query if key is acceptable (without signature)
        val queryPayload = SshBufferWriter()
            .writeByte(SshMsgType.USERAUTH_REQUEST)
            .writeUtf8(username)
            .writeUtf8(SshService.CONNECTION)
            .writeUtf8("publickey")
            .writeBoolean(false) // no signature yet
            .writeUtf8(sigAlgorithm)
            .writeString(publicKeyBlob)
            .toByteArray()
        transport.sendPacket(queryPayload)

        // Message 60 = PK_OK in pubkey context (not INFO_REQUEST)
        val queryResult = readAuthResponse(expectPkOk = true)
        if (queryResult is AuthResult.Failure) return queryResult
        // PK_OK means we can send the real request with signature

        // Step 2: Build the data to sign (RFC 4252 S7)
        val signData = SshBufferWriter()
            .writeString(transport.sessionId)
            .writeByte(SshMsgType.USERAUTH_REQUEST)
            .writeUtf8(username)
            .writeUtf8(SshService.CONNECTION)
            .writeUtf8("publickey")
            .writeBoolean(true)
            .writeUtf8(sigAlgorithm)
            .writeString(publicKeyBlob)
            .toByteArray()

        val signature = signer(signData)

        // Step 3: Send real auth request with signature
        val authPayload = SshBufferWriter()
            .writeByte(SshMsgType.USERAUTH_REQUEST)
            .writeUtf8(username)
            .writeUtf8(SshService.CONNECTION)
            .writeUtf8("publickey")
            .writeBoolean(true)
            .writeUtf8(sigAlgorithm)
            .writeString(publicKeyBlob)
            .writeString(signature)
            .toByteArray()
        transport.sendPacket(authPayload)
        return readAuthResponse()
    }

    /**
     * Try keyboard-interactive authentication.
     * @param username SSH username
     * @param responder suspend callback that receives prompts and returns answers
     */
    suspend fun authKeyboardInteractive(
        username: String,
        responder: suspend (name: String, instruction: String, prompts: List<Prompt>) -> List<String>
    ): AuthResult {
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.USERAUTH_REQUEST)
            .writeUtf8(username)
            .writeUtf8(SshService.CONNECTION)
            .writeUtf8("keyboard-interactive")
            .writeUtf8("") // language tag
            .writeUtf8("") // submethods
            .toByteArray()
        transport.sendPacket(payload)

        while (true) {
            val result = readAuthResponse()
            when (result) {
                is AuthResult.Success -> return result
                is AuthResult.Failure -> return result
                is AuthResult.Banner -> continue // banners can appear between prompts
                is AuthResult.InfoRequest -> {
                    val answers = responder(result.name, result.instruction, result.prompts)
                    sendInfoResponse(answers)
                }
            }
        }
    }

    /** Try "none" authentication to learn available methods. */
    suspend fun authNone(username: String): AuthResult {
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.USERAUTH_REQUEST)
            .writeUtf8(username)
            .writeUtf8(SshService.CONNECTION)
            .writeUtf8("none")
            .toByteArray()
        transport.sendPacket(payload)
        return readAuthResponse()
    }

    /**
     * Read auth response, skipping banners.
     * @param expectPkOk if true, message 60 is PK_OK (pubkey query); otherwise INFO_REQUEST (kbd-interactive)
     */
    private suspend fun readAuthResponse(expectPkOk: Boolean = false): AuthResult {
        while (true) {
            val response = transport.receivePacket()
            val msgType = response[0].toInt()
            val reader = SshBufferReader(response, 1)

            when (msgType) {
                SshMsgType.USERAUTH_SUCCESS -> return AuthResult.Success

                SshMsgType.USERAUTH_FAILURE -> {
                    val methods = reader.readNameList()
                    val partial = reader.readBoolean()
                    return AuthResult.Failure(methods, partial)
                }

                SshMsgType.USERAUTH_BANNER -> {
                    reader.readUtf8() // banner text -- skip, keep reading
                }

                // Message 60: PK_OK (pubkey) or INFO_REQUEST (keyboard-interactive)
                60 -> {
                    if (expectPkOk) {
                        // PK_OK: key is acceptable, proceed to signed request
                        return AuthResult.Success
                    } else {
                        // INFO_REQUEST: keyboard-interactive prompts
                        val name = reader.readUtf8()
                        val instruction = reader.readUtf8()
                        reader.readUtf8() // language tag (ignored)
                        val numPrompts = reader.readUint32().toInt()
                        val prompts = (0 until numPrompts).map {
                            val text = reader.readUtf8()
                            val echo = reader.readBoolean()
                            Prompt(text, echo)
                        }
                        return AuthResult.InfoRequest(name, instruction, prompts)
                    }
                }

                else -> {
                    // Skip unknown messages during auth (EXT_INFO type 7, GLOBAL_REQUEST, etc.)
                }
            }
        }
    }

    private suspend fun sendInfoResponse(answers: List<String>) {
        val buf = SshBufferWriter()
            .writeByte(SshMsgType.USERAUTH_INFO_RESPONSE)
            .writeUint32(answers.size)
        answers.forEach { buf.writeUtf8(it) }
        transport.sendPacket(buf.toByteArray())
    }
}
