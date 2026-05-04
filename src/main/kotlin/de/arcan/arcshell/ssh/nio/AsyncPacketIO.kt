package de.arcan.arcshell.ssh.nio

import de.arcan.arcshell.ssh.transport.CryptoState
import de.arcan.arcshell.ssh.transport.SshBufferWriter
import de.arcan.arcshell.ssh.transport.SshProtocolException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import de.arcan.arcshell.crypto.bc.crypto.engines.ChaChaEngine
import de.arcan.arcshell.crypto.bc.crypto.macs.Poly1305
import de.arcan.arcshell.crypto.bc.crypto.params.KeyParameter
import de.arcan.arcshell.crypto.bc.crypto.params.ParametersWithIV
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher

class AsyncPacketIO(private val source: AsyncDataSource) {

    private val random = de.arcan.arcshell.ssh.SshRandom.instance
    private var sendSequence: Long = 0
    private var recvSequence: Long = 0
    private val writeMutex = Mutex()

    var sendCipher: CryptoState? = null
    var recvCipher: CryptoState? = null

    suspend fun readPacket(): ByteArray {
        val crypto = recvCipher
        return if (crypto == null) readPlaintextPacket()
        else if (crypto.isChaCha) readChaChaPacket(crypto)
        else if (crypto.isAead) readAeadPacket(crypto)
        else if (crypto.etm) readEtmPacket(crypto)
        else readCtrPacket(crypto)
    }

    suspend fun writePacket(payload: ByteArray) = writeMutex.withLock {
        val crypto = sendCipher
        if (crypto == null) writePlaintextPacket(payload)
        else if (crypto.isChaCha) writeChaChaPacket(payload, crypto)
        else if (crypto.isAead) writeAeadPacket(payload, crypto)
        else if (crypto.etm) writeEtmPacket(payload, crypto)
        else writeCtrPacket(payload, crypto)
        sendSequence++
    }

    private suspend fun readPlaintextPacket(): ByteArray {
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

    private suspend fun writePlaintextPacket(payload: ByteArray) {
        val paddingLength = computePaddingLength(payload.size, 8)
        val packetLength = 1 + payload.size + paddingLength
        val padding = ByteArray(paddingLength).also { random.nextBytes(it) }
        val packet = SshBufferWriter(4 + packetLength)
            .writeUint32(packetLength).writeByte(paddingLength)
            .writeBytes(payload).writeBytes(padding).toByteArray()
        source.write(ByteBuffer.wrap(packet))
    }

    private suspend fun readEtmPacket(crypto: CryptoState): ByteArray {
        val macLength = crypto.macLength
        val lengthBytes = readExact(4)
        val packetLength = decodeUint32(lengthBytes)
        if (packetLength < 2 || packetLength > MAX_PACKET_LENGTH)
            throw SshProtocolException("Invalid ETM packet length: $packetLength")
        val ciphertext = readExact(packetLength)
        val mac = if (macLength > 0) readExact(macLength) else ByteArray(0)
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
        val decrypted = crypto.cipher.update(ciphertext)
            ?: throw SshProtocolException("Cipher returned null in ETM decrypt")
        val paddingLength = decrypted[0].toInt() and 0xFF
        val payloadLength = packetLength - paddingLength - 1
        if (payloadLength < 0)
            throw SshProtocolException("Invalid padding in ETM packet")
        recvSequence++
        return decrypted.copyOfRange(1, 1 + payloadLength)
    }

    private suspend fun writeEtmPacket(payload: ByteArray, crypto: CryptoState) {
        val blockSize = maxOf(crypto.cipher.blockSize, 8)
        val paddingLength = computePaddingLength(payload.size, blockSize, etm = true)
        val packetLength = 1 + payload.size + paddingLength
        val padding = ByteArray(paddingLength).also { random.nextBytes(it) }
        val lengthBytes = SshBufferWriter(4).writeUint32(packetLength).toByteArray()
        val plainContent = SshBufferWriter(packetLength)
            .writeByte(paddingLength).writeBytes(payload).writeBytes(padding).toByteArray()
        val ciphertext = crypto.cipher.update(plainContent)
            ?: throw SshProtocolException("Cipher returned null in ETM encrypt")
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
        val out = ByteBuffer.allocate(4 + ciphertext.size + macBytes.size)
        out.put(lengthBytes); out.put(ciphertext); out.put(macBytes); out.flip()
        source.write(out)
    }

    private suspend fun readCtrPacket(crypto: CryptoState): ByteArray {
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

    private suspend fun writeCtrPacket(payload: ByteArray, crypto: CryptoState) {
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
        val out = ByteBuffer.allocate(encrypted.size + macBytes.size)
        out.put(encrypted); out.put(macBytes); out.flip()
        source.write(out)
    }

    private suspend fun readAeadPacket(crypto: CryptoState): ByteArray {
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

    private suspend fun writeAeadPacket(payload: ByteArray, crypto: CryptoState) {
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
        val out = ByteBuffer.allocate(4 + ciphertextAndTag.size)
        out.put(lengthBytes); out.put(ciphertextAndTag); out.flip()
        source.write(out)
    }

    private suspend fun readChaChaPacket(crypto: CryptoState): ByteArray {
        val encryptedLength = readExact(4)
        val lengthNonce = buildChaChaNonce(recvSequence)
        val lengthCipher = ChaChaEngine()
        lengthCipher.init(false, ParametersWithIV(KeyParameter(crypto.chaChaK2!!), lengthNonce))
        val decryptedLength = ByteArray(4)
        lengthCipher.processBytes(encryptedLength, 0, 4, decryptedLength, 0)
        val packetLength = decodeUint32(decryptedLength)
        if (packetLength < 2 || packetLength > MAX_PACKET_LENGTH)
            throw SshProtocolException("Invalid ChaCha packet length: $packetLength")
        val encryptedPayload = readExact(packetLength)
        val tag = readExact(16)
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
        val payloadCipher = ChaChaEngine()
        payloadCipher.init(false, ParametersWithIV(KeyParameter(crypto.chaChaK1!!), payloadNonce))
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

    private suspend fun writeChaChaPacket(payload: ByteArray, crypto: CryptoState) {
        val blockSize = 8
        val paddingLength = computePaddingLength(payload.size, blockSize, etm = true)
        val packetLength = 1 + payload.size + paddingLength
        val padding = ByteArray(paddingLength).also { random.nextBytes(it) }
        val plainContent = SshBufferWriter(packetLength)
            .writeByte(paddingLength).writeBytes(payload).writeBytes(padding).toByteArray()
        val lengthBytes = SshBufferWriter(4).writeUint32(packetLength).toByteArray()
        val lengthNonce = buildChaChaNonce(sendSequence)
        val lengthCipher = ChaChaEngine()
        lengthCipher.init(true, ParametersWithIV(KeyParameter(crypto.chaChaK2!!), lengthNonce))
        val encryptedLength = ByteArray(4)
        lengthCipher.processBytes(lengthBytes, 0, 4, encryptedLength, 0)
        val payloadNonce = buildChaChaNonce(sendSequence)
        val payloadCipher = ChaChaEngine()
        payloadCipher.init(true, ParametersWithIV(KeyParameter(crypto.chaChaK1!!), payloadNonce))
        val polyBlock = ByteArray(64)
        payloadCipher.processBytes(ByteArray(64), 0, 64, polyBlock, 0)
        val polyKey = polyBlock.copyOfRange(0, 32)
        val encryptedPayload = ByteArray(packetLength)
        payloadCipher.processBytes(plainContent, 0, packetLength, encryptedPayload, 0)
        val macData = encryptedLength + encryptedPayload
        val tagBytes = poly1305Tag(polyKey, macData)
        polyKey.fill(0); polyBlock.fill(0)
        val out = ByteBuffer.allocate(4 + packetLength + 16)
        out.put(encryptedLength); out.put(encryptedPayload); out.put(tagBytes); out.flip()
        source.write(out)
    }

    suspend fun readExact(count: Int): ByteArray {
        val buf = ByteArray(count)
        val dst = ByteBuffer.wrap(buf)
        while (dst.hasRemaining()) {
            val n = source.read(dst)
            if (n < 0) throw SshProtocolException("Connection closed (expected $count bytes, got ${dst.position()})")
        }
        return buf
    }

    fun resetSequenceNumbers() { sendSequence = 0; recvSequence = 0 }
    fun resetSendSequence() { sendSequence = 0 }
    fun resetRecvSequence() { recvSequence = 0 }

    fun close() { source.close() }

    private fun buildChaChaNonce(sequenceNumber: Long): ByteArray {
        val nonce = ByteArray(8)
        for (i in 0 until 8) { nonce[7 - i] = ((sequenceNumber shr (i * 8)) and 0xFF).toByte() }
        return nonce
    }

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

    private fun computePaddingLength(payloadSize: Int, blockSize: Int, etm: Boolean = false): Int {
        val unpadded = if (etm) 1 + payloadSize else 5 + payloadSize
        var padding = blockSize - (unpadded % blockSize)
        if (padding < 4) padding += blockSize
        return padding
    }

    private fun decodeUint32(data: ByteArray): Int {
        return ((data[0].toInt() and 0xFF) shl 24) or
                ((data[1].toInt() and 0xFF) shl 16) or
                ((data[2].toInt() and 0xFF) shl 8) or
                (data[3].toInt() and 0xFF)
    }

    companion object {
        const val MAX_PACKET_LENGTH = 256 * 1024
    }
}
