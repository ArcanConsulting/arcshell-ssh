package de.arcan.arcshell.ssh.transport

import org.bouncycastle.crypto.engines.ChaChaEngine
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac

/**
 * SSH Binary Packet Protocol (RFC 4253 §6).
 *
 * Handles reading and writing of SSH packets with optional encryption and MAC.
 * Supports both Encrypt-and-MAC (E&M) and Encrypt-then-MAC (ETM) modes.
 */
class PacketIO(
    private val input: InputStream,
    private val output: OutputStream
) {
    private val random = SecureRandom()

    private var sendSequence: Long = 0
    private var recvSequence: Long = 0

    var sendCipher: CryptoState? = null
    var recvCipher: CryptoState? = null

    fun readPacket(): ByteArray {
        synchronized(input) {
            val crypto = recvCipher
            if (crypto == null) return readPlaintextPacket()
            return if (crypto.isChaCha) readChaChaPacket(crypto)
            else if (crypto.isAead) readAeadPacket(crypto)
            else if (crypto.etm) readEtmPacket(crypto)
            else readCtrPacket(crypto)
        }
    }

    fun writePacket(payload: ByteArray) {
        synchronized(output) {
            val crypto = sendCipher
            if (crypto == null) writePlaintextPacket(payload)
            else if (crypto.isChaCha) writeChaChaPacket(payload, crypto)
            else if (crypto.isAead) writeAeadPacket(payload, crypto)
            else if (crypto.etm) writeEtmPacket(payload, crypto)
            else writeCtrPacket(payload, crypto)
            sendSequence++
        }
    }

    // ---- Plaintext ----

    private fun readPlaintextPacket(): ByteArray {
        val header = readExact(4)
        val packetLength = decodeUint32(header)
        if (packetLength < 2 || packetLength > MAX_PACKET_LENGTH)
            throw SshProtocolException("Invalid packet length: $packetLength")
        val rest = readExact(packetLength)
        val paddingLength = rest[0].toInt() and 0xFF
        val payloadLength = packetLength - paddingLength - 1
        if (payloadLength < 0)
            throw SshProtocolException("Invalid padding length: $paddingLength for packet $packetLength")
        recvSequence++
        return rest.copyOfRange(1, 1 + payloadLength)
    }

    private fun writePlaintextPacket(payload: ByteArray) {
        val paddingLength = computePaddingLength(payload.size, 8)
        val packetLength = 1 + payload.size + paddingLength
        val padding = ByteArray(paddingLength).also { random.nextBytes(it) }
        val packet = SshBufferWriter(4 + packetLength)
            .writeUint32(packetLength).writeByte(paddingLength)
            .writeBytes(payload).writeBytes(padding).toByteArray()
        output.write(packet); output.flush()
    }

    // ---- Encrypt-then-MAC (ETM) ----

    private fun readEtmPacket(crypto: CryptoState): ByteArray {
        val macLength = crypto.macLength

        // In ETM: packet_length is PLAINTEXT (not encrypted), rest is encrypted
        val lengthBytes = readExact(4)
        val packetLength = decodeUint32(lengthBytes)
        if (packetLength < 2 || packetLength > MAX_PACKET_LENGTH)
            throw SshProtocolException("Invalid ETM packet length: $packetLength")

        // Read encrypted content + MAC
        val ciphertext = readExact(packetLength)
        val mac = if (macLength > 0) readExact(macLength) else ByteArray(0)

        // Verify MAC over sequence + plaintext_length + ciphertext
        if (crypto.mac != null && macLength > 0) {
            val macInput = SshBufferWriter(4 + 4 + ciphertext.size)
                .writeUint32(recvSequence.toInt())
                .writeBytes(lengthBytes)
                .writeBytes(ciphertext)
                .toByteArray()
            crypto.mac.reset()
            crypto.mac.update(macInput)
            val expected = crypto.mac.doFinal()
            if (!mac.contentEquals(expected.copyOf(macLength)))
                throw SshProtocolException("ETM MAC verification failed at sequence $recvSequence")
        }

        // Decrypt
        val decrypted = crypto.cipher.update(ciphertext)
            ?: throw SshProtocolException("Cipher returned null in ETM decrypt")

        val paddingLength = decrypted[0].toInt() and 0xFF
        val payloadLength = packetLength - paddingLength - 1
        if (payloadLength < 0)
            throw SshProtocolException("Invalid padding in ETM packet")

        recvSequence++
        return decrypted.copyOfRange(1, 1 + payloadLength)
    }

    private fun writeEtmPacket(payload: ByteArray, crypto: CryptoState) {
        val blockSize = maxOf(crypto.cipher.blockSize, 8)
        val paddingLength = computePaddingLength(payload.size, blockSize, etm = true)
        val packetLength = 1 + payload.size + paddingLength
        val padding = ByteArray(paddingLength).also { random.nextBytes(it) }

        // packet_length in plaintext
        val lengthBytes = SshBufferWriter(4).writeUint32(packetLength).toByteArray()

        // Encrypt content (without packet_length)
        val plainContent = SshBufferWriter(packetLength)
            .writeByte(paddingLength).writeBytes(payload).writeBytes(padding).toByteArray()
        val ciphertext = crypto.cipher.update(plainContent)
            ?: throw SshProtocolException("Cipher returned null in ETM encrypt")

        // MAC over sequence + plaintext_length + ciphertext
        val macBytes = if (crypto.mac != null) {
            val macInput = SshBufferWriter(4 + 4 + ciphertext.size)
                .writeUint32(sendSequence.toInt())
                .writeBytes(lengthBytes)
                .writeBytes(ciphertext)
                .toByteArray()
            crypto.mac.reset()
            crypto.mac.update(macInput)
            crypto.mac.doFinal().copyOf(crypto.macLength)
        } else ByteArray(0)

        output.write(lengthBytes)
        output.write(ciphertext)
        output.write(macBytes)
        output.flush()
    }

    // ---- Encrypt-and-MAC (standard, non-ETM) ----

    private fun readCtrPacket(crypto: CryptoState): ByteArray {
        val blockSize = maxOf(crypto.cipher.blockSize, 8)
        val macLength = crypto.macLength
        val firstBlock = readExact(blockSize)
        val decryptedFirst = crypto.cipher.update(firstBlock)
            ?: throw SshProtocolException("Cipher returned null on first block")
        val packetLength = decodeUint32(decryptedFirst)
        if (packetLength < 2 || packetLength > MAX_PACKET_LENGTH)
            throw SshProtocolException("Invalid encrypted packet length: $packetLength")
        val totalEncrypted = 4 + packetLength
        val remainingEncrypted = totalEncrypted - blockSize
        val remainingData = if (remainingEncrypted > 0) {
            crypto.cipher.update(readExact(remainingEncrypted))
                ?: throw SshProtocolException("Cipher returned null on remaining blocks")
        } else ByteArray(0)
        val mac = if (macLength > 0) readExact(macLength) else ByteArray(0)
        if (crypto.mac != null && macLength > 0) {
            val macInput = SshBufferWriter(4 + totalEncrypted)
                .writeUint32(recvSequence.toInt())
                .writeBytes(decryptedFirst).writeBytes(remainingData).toByteArray()
            crypto.mac.reset()
            crypto.mac.update(macInput)
            val expected = crypto.mac.doFinal()
            if (!mac.contentEquals(expected.copyOf(macLength)))
                throw SshProtocolException("MAC verification failed at sequence $recvSequence")
        }
        val fullDecrypted = decryptedFirst + remainingData
        val paddingLength = fullDecrypted[4].toInt() and 0xFF
        val payloadLength = packetLength - paddingLength - 1
        if (payloadLength < 0) throw SshProtocolException("Invalid padding in encrypted packet")
        recvSequence++
        return fullDecrypted.copyOfRange(5, 5 + payloadLength)
    }

    private fun writeCtrPacket(payload: ByteArray, crypto: CryptoState) {
        val blockSize = maxOf(crypto.cipher.blockSize, 8)
        val paddingLength = computePaddingLength(payload.size, blockSize)
        val packetLength = 1 + payload.size + paddingLength
        val padding = ByteArray(paddingLength).also { random.nextBytes(it) }
        val plainPacket = SshBufferWriter(4 + packetLength)
            .writeUint32(packetLength).writeByte(paddingLength)
            .writeBytes(payload).writeBytes(padding).toByteArray()
        val macBytes = if (crypto.mac != null) {
            val macInput = SshBufferWriter(4 + plainPacket.size)
                .writeUint32(sendSequence.toInt()).writeBytes(plainPacket).toByteArray()
            crypto.mac.reset()
            crypto.mac.update(macInput)
            crypto.mac.doFinal().copyOf(crypto.macLength)
        } else ByteArray(0)
        val encrypted = crypto.cipher.update(plainPacket)
            ?: throw SshProtocolException("Cipher returned null during encryption")
        output.write(encrypted)
        output.write(macBytes)
        output.flush()
    }

    // ---- AEAD (GCM) ----

    private fun readAeadPacket(crypto: CryptoState): ByteArray {
        val tagLength = 16
        val lengthBytes = readExact(4)
        val packetLength = decodeUint32(lengthBytes)
        if (packetLength < 2 || packetLength > MAX_PACKET_LENGTH)
            throw SshProtocolException("Invalid AEAD packet length: $packetLength")
        val ciphertextAndTag = readExact(packetLength + tagLength)
        val nonce = crypto.buildNonce(recvSequence)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, crypto.aesKey!!, javax.crypto.spec.GCMParameterSpec(128, nonce))
        cipher.updateAAD(lengthBytes)
        val decrypted = cipher.doFinal(ciphertextAndTag)
        val paddingLength = decrypted[0].toInt() and 0xFF
        val payloadLength = packetLength - paddingLength - 1
        if (payloadLength < 0) throw SshProtocolException("Invalid padding in AEAD packet")
        recvSequence++
        return decrypted.copyOfRange(1, 1 + payloadLength)
    }

    private fun writeAeadPacket(payload: ByteArray, crypto: CryptoState) {
        val blockSize = 16
        val paddingLength = computePaddingLength(payload.size, blockSize, etm = true)
        val packetLength = 1 + payload.size + paddingLength
        val padding = ByteArray(paddingLength).also { random.nextBytes(it) }
        val lengthBytes = SshBufferWriter(4).writeUint32(packetLength).toByteArray()
        val plainContent = SshBufferWriter(packetLength)
            .writeByte(paddingLength).writeBytes(payload).writeBytes(padding).toByteArray()
        val nonce = crypto.buildNonce(sendSequence)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, crypto.aesKey!!, javax.crypto.spec.GCMParameterSpec(128, nonce))
        cipher.updateAAD(lengthBytes)
        val ciphertextAndTag = cipher.doFinal(plainContent)
        output.write(lengthBytes)
        output.write(ciphertextAndTag)
        output.flush()
    }

    // ---- ChaCha20-Poly1305@openssh.com ----

    private fun readChaChaPacket(crypto: CryptoState): ByteArray {
        // Step 1: Read and decrypt the 4-byte packet length using K2
        val encryptedLength = readExact(4)
        val lengthNonce = buildChaChaNonce(recvSequence)
        val lengthCipher = ChaChaEngine()
        lengthCipher.init(false, ParametersWithIV(KeyParameter(crypto.chaChaK2!!), lengthNonce))
        val decryptedLength = ByteArray(4)
        lengthCipher.processBytes(encryptedLength, 0, 4, decryptedLength, 0)
        val packetLength = decodeUint32(decryptedLength)
        if (packetLength < 2 || packetLength > MAX_PACKET_LENGTH)
            throw SshProtocolException("Invalid ChaCha packet length: $packetLength")

        // Step 2: Read encrypted payload + 16-byte Poly1305 tag
        val encryptedPayload = readExact(packetLength)
        val tag = readExact(16)

        // Step 3: Verify Poly1305 MAC over (encrypted_length || encrypted_payload)
        val payloadNonce = buildChaChaNonce(recvSequence)
        val polyKeyCipher = ChaChaEngine()
        polyKeyCipher.init(true, ParametersWithIV(KeyParameter(crypto.chaChaK1!!), payloadNonce))
        val polyBlock = ByteArray(64)
        polyKeyCipher.processBytes(ByteArray(64), 0, 64, polyBlock, 0)
        val polyKey = polyBlock.copyOfRange(0, 32)

        val macData = encryptedLength + encryptedPayload
        val expectedTag = poly1305Tag(polyKey, macData)
        polyKey.fill(0); polyBlock.fill(0)

        if (!constantTimeEq(tag, expectedTag))
            throw SshProtocolException("ChaCha20-Poly1305 MAC verification failed at sequence $recvSequence")

        // Step 4: Decrypt payload using K1 (counter starts at 1, poly key used counter 0)
        val payloadCipher = ChaChaEngine()
        payloadCipher.init(false, ParametersWithIV(KeyParameter(crypto.chaChaK1!!), payloadNonce))
        // Skip block 0 (used for Poly1305 key derivation)
        val skip = ByteArray(64)
        payloadCipher.processBytes(ByteArray(64), 0, 64, skip, 0)

        val decryptedPayload = ByteArray(packetLength)
        payloadCipher.processBytes(encryptedPayload, 0, packetLength, decryptedPayload, 0)

        val paddingLength = decryptedPayload[0].toInt() and 0xFF
        val payloadLength = packetLength - paddingLength - 1
        if (payloadLength < 0)
            throw SshProtocolException("Invalid padding in ChaCha packet")

        recvSequence++
        return decryptedPayload.copyOfRange(1, 1 + payloadLength)
    }

    private fun writeChaChaPacket(payload: ByteArray, crypto: CryptoState) {
        val blockSize = 8 // ChaCha20-Poly1305 uses 8-byte block alignment
        val paddingLength = computePaddingLength(payload.size, blockSize, etm = true)
        val packetLength = 1 + payload.size + paddingLength
        val padding = ByteArray(paddingLength).also { random.nextBytes(it) }

        // Step 1: Build plaintext content (padding_length || payload || padding)
        val plainContent = SshBufferWriter(packetLength)
            .writeByte(paddingLength).writeBytes(payload).writeBytes(padding).toByteArray()

        // Step 2: Encrypt packet length (4 bytes) using K2
        val lengthBytes = SshBufferWriter(4).writeUint32(packetLength).toByteArray()
        val lengthNonce = buildChaChaNonce(sendSequence)
        val lengthCipher = ChaChaEngine()
        lengthCipher.init(true, ParametersWithIV(KeyParameter(crypto.chaChaK2!!), lengthNonce))
        val encryptedLength = ByteArray(4)
        lengthCipher.processBytes(lengthBytes, 0, 4, encryptedLength, 0)

        // Step 3: Encrypt payload using K1 (counter starts at 1)
        val payloadNonce = buildChaChaNonce(sendSequence)
        val payloadCipher = ChaChaEngine()
        payloadCipher.init(true, ParametersWithIV(KeyParameter(crypto.chaChaK1!!), payloadNonce))
        // Derive Poly1305 key from block 0
        val polyBlock = ByteArray(64)
        payloadCipher.processBytes(ByteArray(64), 0, 64, polyBlock, 0)
        val polyKey = polyBlock.copyOfRange(0, 32)

        val encryptedPayload = ByteArray(packetLength)
        payloadCipher.processBytes(plainContent, 0, packetLength, encryptedPayload, 0)

        // Step 4: Compute Poly1305 MAC over (encrypted_length || encrypted_payload)
        val macData = encryptedLength + encryptedPayload
        val tag = poly1305Tag(polyKey, macData)
        polyKey.fill(0); polyBlock.fill(0)

        // Step 5: Write: encrypted_length || encrypted_payload || tag
        output.write(encryptedLength)
        output.write(encryptedPayload)
        output.write(tag)
        output.flush()
    }

    private fun buildChaChaNonce(sequenceNumber: Long): ByteArray {
        val nonce = ByteArray(8)
        for (i in 0 until 8) {
            nonce[7 - i] = ((sequenceNumber shr (i * 8)) and 0xFF).toByte()
        }
        return nonce
    }

    /**
     * Compute Poly1305 tag over data. Unlike RFC 8439 AEAD construction,
     * SSH chacha20-poly1305 MACs the raw data directly (no AAD/length padding).
     */
    private fun poly1305Tag(polyKey: ByteArray, data: ByteArray): ByteArray {
        val poly = Poly1305()
        poly.init(KeyParameter(polyKey))
        poly.update(data, 0, data.size)
        val tag = ByteArray(16)
        poly.doFinal(tag, 0)
        return tag
    }

    private fun constantTimeEq(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    // ---- Helpers ----

    private fun computePaddingLength(payloadSize: Int, blockSize: Int, etm: Boolean = false): Int {
        // ETM: packet_length is NOT encrypted, so only (1 + payload + padding) must be block-aligned
        // E&M: entire packet (4 + 1 + payload + padding) must be block-aligned
        val unpadded = if (etm) 1 + payloadSize else 5 + payloadSize
        var padding = blockSize - (unpadded % blockSize)
        if (padding < 4) padding += blockSize
        return padding
    }

    private fun readExact(count: Int): ByteArray {
        val buf = ByteArray(count)
        var read = 0
        while (read < count) {
            val n = input.read(buf, read, count - read)
            if (n < 0) throw SshProtocolException("Connection closed (expected $count bytes, got $read)")
            read += n
        }
        return buf
    }

    private fun decodeUint32(data: ByteArray): Int {
        return ((data[0].toInt() and 0xFF) shl 24) or
                ((data[1].toInt() and 0xFF) shl 16) or
                ((data[2].toInt() and 0xFF) shl 8) or
                (data[3].toInt() and 0xFF)
    }

    fun resetSequenceNumbers() { sendSequence = 0; recvSequence = 0 }
    fun resetSendSequence() { sendSequence = 0 }
    fun resetRecvSequence() { recvSequence = 0 }

    fun close() { input.close(); output.close() }

    companion object {
        const val MAX_PACKET_LENGTH = 256 * 1024
    }
}

/**
 * Holds the active cipher and MAC for one direction.
 */
data class CryptoState(
    val cipher: Cipher,
    val mac: Mac?,
    val macLength: Int,
    val isAead: Boolean = false,
    val etm: Boolean = false,
    val aesKey: javax.crypto.spec.SecretKeySpec? = null,
    val baseIv: ByteArray? = null,
    val isChaCha: Boolean = false,
    val chaChaK1: ByteArray? = null, // main cipher key (first 32 bytes)
    val chaChaK2: ByteArray? = null  // length cipher key (last 32 bytes)
) {
    fun buildNonce(sequenceNumber: Long): ByteArray {
        val iv = baseIv?.copyOf() ?: throw IllegalStateException("No base IV for AEAD")
        var carry = sequenceNumber
        for (i in 0 until 8) {
            val pos = iv.size - 1 - i
            val sum = (iv[pos].toLong() and 0xFF) + (carry and 0xFF)
            iv[pos] = sum.toByte()
            carry = (carry ushr 8) + (sum ushr 8)
        }
        return iv
    }

    override fun equals(other: Any?): Boolean = this === other
    override fun hashCode(): Int = System.identityHashCode(this)
}

class SshProtocolException(message: String, cause: Throwable? = null) :
    Exception(message, cause)
