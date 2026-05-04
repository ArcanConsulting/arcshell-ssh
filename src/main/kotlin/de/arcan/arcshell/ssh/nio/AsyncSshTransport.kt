package de.arcan.arcshell.ssh.nio

import de.arcan.arcshell.ssh.SSH_VERSION_STRING
import de.arcan.arcshell.ssh.SshMsgType
import de.arcan.arcshell.ssh.transport.CipherRegistry
import de.arcan.arcshell.ssh.transport.CryptoState
import de.arcan.arcshell.ssh.transport.KexInit
import de.arcan.arcshell.ssh.transport.KeyDerivation
import de.arcan.arcshell.ssh.transport.KeyExchangeAlgorithm
import de.arcan.arcshell.ssh.transport.KeyExchangeRegistry
import de.arcan.arcshell.ssh.transport.MacRegistry
import de.arcan.arcshell.ssh.transport.NegotiatedAlgorithms
import de.arcan.arcshell.ssh.transport.SshBufferReader
import de.arcan.arcshell.ssh.transport.SshBufferWriter
import de.arcan.arcshell.ssh.transport.SshProtocolException
import de.arcan.arcshell.ssh.transport.negotiateAlgorithms
import java.math.BigInteger
import java.nio.ByteBuffer

/**
 * Suspend-based SSH transport layer (RFC 4253). Async port of [SshTransport]
 * that uses NIO channels via [AsyncPacketIO] and [AsyncDataSource] instead
 * of blocking streams.
 *
 * Handles:
 * - Version exchange
 * - KEXINIT algorithm negotiation
 * - Key exchange (DH/ECDH)
 * - NEWKEYS activation (encryption begins)
 *
 * After [performHandshake], the underlying [AsyncPacketIO] is encrypted and
 * authenticated. Higher layers (auth, connection) use [sendPacket] and
 * [receivePacket] which go through the encrypted channel.
 */
class AsyncSshTransport(
    private val source: AsyncDataSource,
    private val packetIO: AsyncPacketIO,
    private val hostKeyVerifier: suspend (String, ByteArray) -> Boolean,
    private val legacyAlgorithmApprover: (suspend (List<String>) -> Boolean)? = null
) {
    /** The server's version string (set during handshake). */
    var serverVersion: String = ""
        private set

    /** The session ID (first exchange hash H, never changes). */
    var sessionId: ByteArray = ByteArray(0)
        private set

    /** The negotiated algorithms (set after KEXINIT). */
    var negotiated: NegotiatedAlgorithms? = null
        private set

    /** The negotiated KEX algorithm name (for display). */
    val kexAlgorithmName: String get() = negotiated?.kex ?: "none"
    val negotiatedAlgorithms: NegotiatedAlgorithms? get() = negotiated

    /** Raw bytes of our KEXINIT (needed for exchange hash computation). */
    private var clientKexInitPayload: ByteArray = ByteArray(0)
    /** Raw bytes of server's KEXINIT. */
    private var serverKexInitPayload: ByteArray = ByteArray(0)

    /**
     * Perform the full SSH handshake: version exchange, KEXINIT, key exchange,
     * NEWKEYS. After this returns, the connection is encrypted.
     *
     * @throws SshProtocolException on protocol errors
     */
    suspend fun performHandshake() {
        // Step 1: Version exchange (RFC 4253 section 4.2)
        exchangeVersions()

        // Step 2: KEXINIT exchange
        val clientKexInit = KexInit.createClient()
        clientKexInitPayload = clientKexInit.encode()
        packetIO.writePacket(clientKexInitPayload)

        serverKexInitPayload = packetIO.readPacket()
        if (serverKexInitPayload.isEmpty() || serverKexInitPayload[0].toInt() != SshMsgType.KEXINIT) {
            throw SshProtocolException(
                "Expected KEXINIT, got message type ${if (serverKexInitPayload.isNotEmpty()) serverKexInitPayload[0].toInt() else -1}"
            )
        }
        val serverKexInit = KexInit.decode(serverKexInitPayload)

        // Step 3: Negotiate algorithms
        negotiated = negotiateAlgorithms(clientKexInit, serverKexInit)
        val alg = negotiated!!

        // Step 3b: Check for legacy algorithms and prompt user
        val legacyUsed = collectLegacyAlgorithms(alg)
        if (legacyUsed.isNotEmpty()) {
            val approved = legacyAlgorithmApprover?.invoke(legacyUsed) ?: true
            if (!approved) {
                throw SshProtocolException("Connection rejected: server requires legacy algorithms")
            }
        }

        // Step 4: Run key exchange
        val kexAlgo = KeyExchangeRegistry.byName(alg.kex)
            ?: throw SshProtocolException("Negotiated unknown KEX: ${alg.kex}")

        val (sharedSecret, exchangeHash, hostKeyBlob) = performKeyExchange(kexAlgo)

        // Step 5: Verify host key
        val hostKeyReader = SshBufferReader(hostKeyBlob)
        val hostKeyType = hostKeyReader.readUtf8()
        if (!hostKeyVerifier(hostKeyType, hostKeyBlob)) {
            throw SshProtocolException("Host key verification failed for $hostKeyType")
        }

        // Step 6: Set session ID (first exchange hash, never changes)
        if (sessionId.isEmpty()) {
            sessionId = exchangeHash.copyOf()
        }

        // Step 7: Check for strict KEX (Terrapin mitigation)
        val strictKex = serverKexInit.kexAlgorithms.contains("kex-strict-s-v00@openssh.com")

        // Step 8: Send NEWKEYS (plaintext, last unencrypted packet)
        packetIO.writePacket(byteArrayOf(SshMsgType.NEWKEYS.toByte()))
        // Strict KEX: reset send sequence AFTER send+increment (matches OpenSSH)
        if (strictKex) packetIO.resetSendSequence()

        // Step 9: Receive NEWKEYS (plaintext)
        val newKeysPayload = packetIO.readPacket()
        if (newKeysPayload.isEmpty() || newKeysPayload[0].toInt() != SshMsgType.NEWKEYS) {
            throw SshProtocolException("Expected NEWKEYS, got ${newKeysPayload.firstOrNull()?.toInt()}")
        }
        // Strict KEX: reset recv sequence AFTER recv+increment (matches OpenSSH)
        if (strictKex) packetIO.resetRecvSequence()

        // Step 10: Activate encryption (AFTER sequence reset, matching OpenSSH ordering)
        activateEncryption(alg, kexAlgo.hashAlgorithm, sharedSecret, exchangeHash)
    }

    /** Send a packet through the (possibly encrypted) transport. */
    suspend fun sendPacket(payload: ByteArray) {
        packetIO.writePacket(payload)
    }

    /** Receive a packet from the (possibly encrypted) transport. Returns payload. */
    suspend fun receivePacket(): ByteArray {
        while (true) {
            val payload = packetIO.readPacket()
            if (payload.isEmpty()) throw SshProtocolException("Empty packet received")

            return when (payload[0].toInt()) {
                SshMsgType.IGNORE -> continue // silently drop
                SshMsgType.DEBUG -> continue  // silently drop
                SshMsgType.DISCONNECT -> {
                    val reader = SshBufferReader(payload, 1)
                    val reasonCode = reader.readUint32().toInt()
                    val description = if (reader.remaining > 4) reader.readUtf8() else ""
                    throw SshProtocolException("Server disconnected: reason=$reasonCode $description")
                }
                else -> payload
            }
        }
    }

    /**
     * Send a packet from a non-suspend context (e.g. channel callbacks like onRequest).
     * Enqueues the write via runBlocking on a confined scope. Use sparingly — prefer
     * the suspend [sendPacket] whenever possible.
     */
    fun sendPacketBlocking(payload: ByteArray) {
        kotlinx.coroutines.runBlocking {
            packetIO.writePacket(payload)
        }
    }

    /** Send SSH_MSG_DISCONNECT and close. */
    suspend fun disconnect(reason: Int = 11, description: String = "Bye") {
        val payload = SshBufferWriter()
            .writeByte(SshMsgType.DISCONNECT)
            .writeUint32(reason)
            .writeUtf8(description)
            .writeUtf8("") // language tag
            .toByteArray()
        try {
            packetIO.writePacket(payload)
        } catch (_: Exception) {
            // Connection might already be dead
        }
        packetIO.close()
    }

    private fun collectLegacyAlgorithms(alg: NegotiatedAlgorithms): List<String> {
        val legacy = mutableListOf<String>()
        if (alg.kex in KeyExchangeRegistry.LEGACY_ALGORITHMS) legacy.add(alg.kex)
        if (alg.macC2S in MacRegistry.LEGACY_ALGORITHMS) legacy.add(alg.macC2S)
        if (alg.macS2C in MacRegistry.LEGACY_ALGORITHMS && alg.macS2C != alg.macC2S) legacy.add(alg.macS2C)
        return legacy
    }

    // --- Version exchange ---

    private suspend fun exchangeVersions() {
        // Send our version
        val versionLine = "$SSH_VERSION_STRING\r\n"
        source.write(ByteBuffer.wrap(versionLine.toByteArray(Charsets.US_ASCII)))

        // Read server version (may be preceded by banner lines)
        serverVersion = readVersionLine()
        if (!serverVersion.startsWith("SSH-2.0-") && !serverVersion.startsWith("SSH-1.99-")) {
            throw SshProtocolException("Unsupported server version: $serverVersion")
        }
    }

    private suspend fun readVersionLine(): String {
        val sb = StringBuilder()
        var foundVersion = false
        while (!foundVersion) {
            val line = readLine()
            if (line.startsWith("SSH-")) {
                foundVersion = true
                return line
            }
            // Non-SSH lines are banner (RFC 4253 section 4.2), ignore them
            if (sb.length > 32 * 1024) {
                throw SshProtocolException("Server banner too long")
            }
        }
        throw SshProtocolException("No SSH version line received")
    }

    private suspend fun readLine(): String {
        val sb = StringBuilder()
        while (true) {
            val byte = packetIO.readExact(1)
            val b = byte[0].toInt() and 0xFF
            if (b == '\n'.code) {
                val line = sb.toString().trimEnd('\r')
                return line
            }
            sb.append(b.toChar())
            if (sb.length > 1024) {
                val hex = sb.substring(0, 64.coerceAtMost(sb.length))
                    .map { "%02x".format(it.code) }.joinToString(" ")
                throw SshProtocolException(
                    "Version line too long (${sb.length} bytes, no newline). First 64 bytes: $hex"
                )
            }
        }
    }

    // --- Key exchange ---

    private data class KexResult(
        val sharedSecret: BigInteger,
        val exchangeHash: ByteArray,
        val hostKeyBlob: ByteArray
    )

    private suspend fun performKeyExchange(kexAlgo: KeyExchangeAlgorithm): KexResult {
        // Generate ephemeral key pair
        val clientPubKey = kexAlgo.generateClientKey()

        // Send KEX_DH_INIT / KEX_ECDH_INIT (message type 30)
        val initPayload = SshBufferWriter()
            .writeByte(SshMsgType.KEXDH_INIT)
            .writeString(clientPubKey)
            .toByteArray()
        packetIO.writePacket(initPayload)

        // Receive KEX_DH_REPLY / KEX_ECDH_REPLY (message type 31)
        val replyPayload = packetIO.readPacket()
        if (replyPayload.isEmpty() || replyPayload[0].toInt() != SshMsgType.KEXDH_REPLY) {
            throw SshProtocolException("Expected KEX_REPLY (31), got ${replyPayload.firstOrNull()?.toInt()}")
        }

        val reader = SshBufferReader(replyPayload, 1)
        val hostKeyBlob = reader.readString()
        val serverPubKey = reader.readString()
        val signature = reader.readString()

        // Compute shared secret
        val sharedSecret = kexAlgo.computeSharedSecret(serverPubKey)

        // Compute exchange hash
        val exchangeHash = kexAlgo.computeExchangeHash(
            clientVersion = SSH_VERSION_STRING,
            serverVersion = serverVersion,
            clientKexInit = clientKexInitPayload,
            serverKexInit = serverKexInitPayload,
            hostKeyBlob = hostKeyBlob,
            clientPublicKey = clientPubKey,
            serverPublicKey = serverPubKey,
            sharedSecret = sharedSecret
        )

        // Verify server's signature over the exchange hash
        verifyHostKeySignature(hostKeyBlob, exchangeHash, signature)

        return KexResult(sharedSecret, exchangeHash, hostKeyBlob)
    }

    private fun verifyHostKeySignature(hostKeyBlob: ByteArray, hash: ByteArray, signature: ByteArray) {
        val keyReader = SshBufferReader(hostKeyBlob)
        val keyType = keyReader.readUtf8()

        val sigReader = SshBufferReader(signature)
        val sigType = sigReader.readUtf8()
        val sigData = sigReader.readString()

        val verified = when (keyType) {
            "ssh-ed25519" -> verifyEd25519(hostKeyBlob, hash, sigData)
            "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa" -> verifyRsa(keyType, sigType, hostKeyBlob, hash, sigData)
            "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521" ->
                verifyEcdsa(keyType, hostKeyBlob, hash, sigData)
            else -> throw SshProtocolException("Unsupported host key type: $keyType")
        }

        if (!verified) {
            throw SshProtocolException("Host key signature verification failed ($keyType)")
        }
    }

    private fun verifyEd25519(hostKeyBlob: ByteArray, hash: ByteArray, sigData: ByteArray): Boolean {
        val keyReader = SshBufferReader(hostKeyBlob)
        keyReader.readUtf8() // skip key type
        val pubKeyBytes = keyReader.readString()

        val pubKey = org.bouncycastle.crypto.params.Ed25519PublicKeyParameters(pubKeyBytes, 0)
        val verifier = org.bouncycastle.crypto.signers.Ed25519Signer()
        verifier.init(false, pubKey)
        verifier.update(hash, 0, hash.size)
        return verifier.verifySignature(sigData)
    }

    private fun verifyRsa(keyType: String, sigType: String, hostKeyBlob: ByteArray, hash: ByteArray, sigData: ByteArray): Boolean {
        val keyReader = SshBufferReader(hostKeyBlob)
        keyReader.readUtf8() // skip key type
        val e = keyReader.readMpint()
        val n = keyReader.readMpint()

        val rsaPubKey = java.security.KeyFactory.getInstance("RSA").generatePublic(
            java.security.spec.RSAPublicKeySpec(n, e)
        )
        val hashAlgo = when (sigType) {
            "rsa-sha2-512" -> "SHA512withRSA"
            "rsa-sha2-256" -> "SHA256withRSA"
            else -> "SHA1withRSA"
        }
        val sig = java.security.Signature.getInstance(hashAlgo)
        sig.initVerify(rsaPubKey)
        sig.update(hash)
        return sig.verify(sigData)
    }

    private fun verifyEcdsa(keyType: String, hostKeyBlob: ByteArray, hash: ByteArray, sigData: ByteArray): Boolean {
        val keyReader = SshBufferReader(hostKeyBlob)
        keyReader.readUtf8() // skip key type
        val curveName = keyReader.readUtf8()
        val pointBytes = keyReader.readString()

        val jcaCurve = when (curveName) {
            "nistp256" -> "secp256r1"
            "nistp384" -> "secp384r1"
            "nistp521" -> "secp521r1"
            else -> throw SshProtocolException("Unknown ECDSA curve: $curveName")
        }
        val hashAlgo = when (curveName) {
            "nistp256" -> "SHA256withECDSA"
            "nistp384" -> "SHA384withECDSA"
            "nistp521" -> "SHA512withECDSA"
            else -> throw SshProtocolException("Unknown ECDSA curve: $curveName")
        }

        // Decode uncompressed EC point
        if (pointBytes[0].toInt() != 0x04) throw SshProtocolException("Expected uncompressed EC point")
        val coordLen = (pointBytes.size - 1) / 2
        if (pointBytes.size != 1 + 2 * coordLen)
            throw SshProtocolException("Invalid EC point size: ${pointBytes.size} (expected ${1 + 2 * coordLen})")
        val x = BigInteger(1, pointBytes.copyOfRange(1, 1 + coordLen))
        val y = BigInteger(1, pointBytes.copyOfRange(1 + coordLen, pointBytes.size))

        val params = (java.security.KeyPairGenerator.getInstance("EC").apply {
            initialize(java.security.spec.ECGenParameterSpec(jcaCurve))
        }.generateKeyPair().public as java.security.interfaces.ECPublicKey).params

        val pubKey = java.security.KeyFactory.getInstance("EC").generatePublic(
            java.security.spec.ECPublicKeySpec(java.security.spec.ECPoint(x, y), params)
        )

        // Convert SSH ECDSA signature (two mpints) to DER format for JCA
        val sigReader = SshBufferReader(sigData)
        val r = sigReader.readMpint()
        val s = sigReader.readMpint()
        val derSig = encodeEcdsaDer(r, s)

        val sig = java.security.Signature.getInstance(hashAlgo)
        sig.initVerify(pubKey)
        sig.update(hash)
        return sig.verify(derSig)
    }

    private fun encodeEcdsaDer(r: BigInteger, s: BigInteger): ByteArray {
        val rBytes = r.toByteArray()
        val sBytes = s.toByteArray()
        val totalLen = 2 + rBytes.size + 2 + sBytes.size
        return byteArrayOf(0x30, totalLen.toByte(),
            0x02, rBytes.size.toByte()) + rBytes +
            byteArrayOf(0x02, sBytes.size.toByte()) + sBytes
    }

    // --- Encryption activation ---

    private fun activateEncryption(
        alg: NegotiatedAlgorithms,
        hashAlgorithm: String,
        sharedSecret: BigInteger,
        exchangeHash: ByteArray
    ) {
        val cipherC2S = CipherRegistry.byName(alg.cipherC2S)
            ?: throw SshProtocolException("Unknown cipher: ${alg.cipherC2S}")
        val cipherS2C = CipherRegistry.byName(alg.cipherS2C)
            ?: throw SshProtocolException("Unknown cipher: ${alg.cipherS2C}")

        val isChaChaC2S = CipherRegistry.isChaCha(alg.cipherC2S)
        val isChaChaS2C = CipherRegistry.isChaCha(alg.cipherS2C)

        // ChaCha20-Poly1305 uses 64-byte keys (K1=first 32, K2=last 32), no IV, no MAC
        if (isChaChaC2S && isChaChaS2C) {
            // Derive 64-byte keys for each direction
            val keyC2S = KeyDerivation.deriveKey(hashAlgorithm, sharedSecret, exchangeHash, 'C', sessionId, 64)
            val keyS2C = KeyDerivation.deriveKey(hashAlgorithm, sharedSecret, exchangeHash, 'D', sessionId, 64)

            // Dummy cipher (ChaCha20 is handled directly via BouncyCastle, not JCA)
            val dummyCipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding")
            val dummyKey = javax.crypto.spec.SecretKeySpec(ByteArray(16), "AES")
            dummyCipher.init(javax.crypto.Cipher.ENCRYPT_MODE, dummyKey, javax.crypto.spec.IvParameterSpec(ByteArray(16)))

            packetIO.sendCipher = CryptoState(
                cipher = dummyCipher, mac = null, macLength = 0,
                isAead = true, isChaCha = true,
                chaChaK1 = keyC2S.copyOfRange(0, 32),
                chaChaK2 = keyC2S.copyOfRange(32, 64)
            )
            packetIO.recvCipher = CryptoState(
                cipher = dummyCipher, mac = null, macLength = 0,
                isAead = true, isChaCha = true,
                chaChaK1 = keyS2C.copyOfRange(0, 32),
                chaChaK2 = keyS2C.copyOfRange(32, 64)
            )
            return
        }

        // Standard key derivation for non-ChaCha ciphers
        val ivC2S = KeyDerivation.deriveKey(hashAlgorithm, sharedSecret, exchangeHash, 'A', sessionId, cipherC2S.ivSize)
        val ivS2C = KeyDerivation.deriveKey(hashAlgorithm, sharedSecret, exchangeHash, 'B', sessionId, cipherS2C.ivSize)
        val keyC2S = KeyDerivation.deriveKey(hashAlgorithm, sharedSecret, exchangeHash, 'C', sessionId, cipherC2S.keySize)
        val keyS2C = KeyDerivation.deriveKey(hashAlgorithm, sharedSecret, exchangeHash, 'D', sessionId, cipherS2C.keySize)

        // Create ciphers
        val sendCipher = KeyDerivation.createCipher(cipherC2S, keyC2S, ivC2S, encrypt = true)
        val recvCipher = KeyDerivation.createCipher(cipherS2C, keyS2C, ivS2C, encrypt = false)

        // Create MACs (only for non-AEAD ciphers)
        val sendMac: javax.crypto.Mac?
        val sendMacLen: Int
        if (!cipherC2S.isAead && alg.macC2S != "none") {
            val macAlgo = MacRegistry.byName(alg.macC2S)
                ?: throw SshProtocolException("Unknown MAC: ${alg.macC2S}")
            val macKey = KeyDerivation.deriveKey(hashAlgorithm, sharedSecret, exchangeHash, 'E', sessionId, macAlgo.keySize)
            sendMac = KeyDerivation.createMac(macAlgo, macKey)
            sendMacLen = macAlgo.macLength
        } else {
            sendMac = null
            sendMacLen = 0
        }

        val recvMac: javax.crypto.Mac?
        val recvMacLen: Int
        if (!cipherS2C.isAead && alg.macS2C != "none") {
            val macAlgo = MacRegistry.byName(alg.macS2C)
                ?: throw SshProtocolException("Unknown MAC: ${alg.macS2C}")
            val macKey = KeyDerivation.deriveKey(hashAlgorithm, sharedSecret, exchangeHash, 'F', sessionId, macAlgo.keySize)
            recvMac = KeyDerivation.createMac(macAlgo, macKey)
            recvMacLen = macAlgo.macLength
        } else {
            recvMac = null
            recvMacLen = 0
        }

        // Determine ETM mode (CBC ciphers always use Encrypt-and-MAC, never ETM)
        val sendEtm = if (!cipherC2S.isAead && alg.macC2S != "none" && !CipherRegistry.isCbc(alg.cipherC2S)) {
            MacRegistry.byName(alg.macC2S)?.etm ?: false
        } else false
        val recvEtm = if (!cipherS2C.isAead && alg.macS2C != "none" && !CipherRegistry.isCbc(alg.cipherS2C)) {
            MacRegistry.byName(alg.macS2C)?.etm ?: false
        } else false

        // Activate
        packetIO.sendCipher = CryptoState(
            sendCipher, sendMac, sendMacLen,
            isAead = cipherC2S.isAead,
            etm = sendEtm,
            aesKey = if (cipherC2S.isAead) javax.crypto.spec.SecretKeySpec(keyC2S, "AES") else null,
            baseIv = if (cipherC2S.isAead) ivC2S else null
        )
        packetIO.recvCipher = CryptoState(
            recvCipher, recvMac, recvMacLen,
            isAead = cipherS2C.isAead,
            etm = recvEtm,
            aesKey = if (cipherS2C.isAead) javax.crypto.spec.SecretKeySpec(keyS2C, "AES") else null,
            baseIv = if (cipherS2C.isAead) ivS2C else null
        )
    }
}
