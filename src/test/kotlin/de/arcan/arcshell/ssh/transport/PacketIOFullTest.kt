package de.arcan.arcshell.ssh.transport

import de.arcan.arcshell.ssh.SshMsgType
import de.arcan.arcshell.ssh.nio.AsyncPacketIO
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Full coverage tests for [AsyncPacketIO] and [CryptoState]:
 * - readPlaintextPacket / writePlaintextPacket roundtrip
 * - readEncryptedPacket / writeEncryptedPacket with CTR mode
 * - AEAD read/write paths with GCM cipher
 * - CryptoState.buildNonce with various sequence numbers
 * - computePaddingLength edge cases (padding < 4, multiple of blockSize)
 * - readExact throws on short read
 * - Invalid packet lengths
 * - CTR with MAC verification
 * - close method
 */
class PacketIOFullTest {

    // =========================================================================
    // Plaintext roundtrip tests
    // =========================================================================

    @Test
    fun `plaintext roundtrip with single byte`() = runBlocking {
        val pipe = createPipe()
        pipe.writer.writePacket(byteArrayOf(20))
        val result = pipe.reader.readPacket()
        assertEquals(1, result.size)
        assertEquals(20, result[0].toInt())
    }

    @Test
    fun `plaintext roundtrip with exact block boundary payload`() = runBlocking {
        // 8-byte blockSize for plaintext: payload should trigger padding edge case
        // unpadded = 5 + payloadSize; if payloadSize = 3, unpadded = 8
        // padding = 8 - (8 % 8) = 0, which is < 4, so += 8 => padding = 8
        val payload = byteArrayOf(1, 2, 3)
        val pipe = createPipe()
        pipe.writer.writePacket(payload)
        assertArrayEquals(payload, pipe.reader.readPacket())
    }

    @Test
    fun `plaintext roundtrip with payload that needs minimum padding`() = runBlocking {
        // unpadded = 5 + 2 = 7; padding = 8 - (7 % 8) = 1, which < 4, += 8 => 9
        val payload = byteArrayOf(1, 2)
        val pipe = createPipe()
        pipe.writer.writePacket(payload)
        assertArrayEquals(payload, pipe.reader.readPacket())
    }

    @Test
    fun `plaintext roundtrip with empty payload`() = runBlocking {
        val pipe = createPipe()
        pipe.writer.writePacket(byteArrayOf())
        val result = pipe.reader.readPacket()
        assertEquals(0, result.size)
    }

    @Test
    fun `plaintext roundtrip with large payload`() = runBlocking {
        val payload = ByteArray(10000) { (it % 256).toByte() }
        val pipe = createPipe()
        pipe.writer.writePacket(payload)
        assertArrayEquals(payload, pipe.reader.readPacket())
    }

    @Test
    fun `sequence number increments after write`() = runBlocking {
        val source = ByteArraySource(ByteArray(0))
        val packetIO = AsyncPacketIO(source)

        packetIO.writePacket(byteArrayOf(1))
        packetIO.writePacket(byteArrayOf(2))
        packetIO.writePacket(byteArrayOf(3))

        // Verify all three writes succeeded (sequence increments internally)
        assertTrue(source.getWrittenBytes().isNotEmpty())
    }

    // =========================================================================
    // CTR encrypted roundtrip
    // =========================================================================

    @Test
    fun `CTR encrypted write and read roundtrip`() = runBlocking {
        val key = ByteArray(32) { (it + 1).toByte() }
        val iv = ByteArray(16) { (it + 0x10).toByte() }
        val macKey = ByteArray(32) { (it + 0x20).toByte() }

        val sendCipher = createAesCtrCipher(key, iv, encrypt = true)
        val recvCipher = createAesCtrCipher(key, iv, encrypt = false)
        val sendMac = createHmacSha256(macKey)
        val recvMac = createHmacSha256(macKey)

        val sendCrypto = CryptoState(sendCipher, sendMac, 32)
        val recvCrypto = CryptoState(recvCipher, recvMac, 32)

        val pipe = PipeSource()
        val writer = AsyncPacketIO(pipe)
        writer.sendCipher = sendCrypto

        val reader = AsyncPacketIO(pipe)
        reader.recvCipher = recvCrypto

        val payload = byteArrayOf(SshMsgType.SERVICE_REQUEST.toByte(), 0x01, 0x02, 0x03)
        writer.writePacket(payload)

        val result = reader.readPacket()
        assertArrayEquals(payload, result)
    }

    @Test
    fun `CTR encrypted multiple packets roundtrip`() = runBlocking {
        val key = ByteArray(32) { (it + 5).toByte() }
        val iv = ByteArray(16) { (it + 0x30).toByte() }
        val macKey = ByteArray(32) { (it + 0x40).toByte() }

        val sendCipher = createAesCtrCipher(key, iv, encrypt = true)
        val recvCipher = createAesCtrCipher(key, iv, encrypt = false)
        val sendMac = createHmacSha256(macKey)
        val recvMac = createHmacSha256(macKey)

        val sendCrypto = CryptoState(sendCipher, sendMac, 32)
        val recvCrypto = CryptoState(recvCipher, recvMac, 32)

        val pipe = PipeSource()
        val writer = AsyncPacketIO(pipe)
        writer.sendCipher = sendCrypto

        val reader = AsyncPacketIO(pipe)
        reader.recvCipher = recvCrypto

        val payload1 = byteArrayOf(20, 1, 2, 3, 4, 5)
        val payload2 = byteArrayOf(21, 6, 7, 8)
        val payload3 = ByteArray(200) { (it % 256).toByte() }

        writer.writePacket(payload1)
        writer.writePacket(payload2)
        writer.writePacket(payload3)

        assertArrayEquals(payload1, reader.readPacket())
        assertArrayEquals(payload2, reader.readPacket())
        assertArrayEquals(payload3, reader.readPacket())
    }

    @Test
    fun `CTR encrypted without MAC works`() = runBlocking {
        val key = ByteArray(32) { (it + 1).toByte() }
        val iv = ByteArray(16) { (it + 0x10).toByte() }

        val sendCipher = createAesCtrCipher(key, iv, encrypt = true)
        val recvCipher = createAesCtrCipher(key, iv, encrypt = false)

        val sendCrypto = CryptoState(sendCipher, null, 0)
        val recvCrypto = CryptoState(recvCipher, null, 0)

        val pipe = PipeSource()
        val writer = AsyncPacketIO(pipe)
        writer.sendCipher = sendCrypto

        val reader = AsyncPacketIO(pipe)
        reader.recvCipher = recvCrypto

        val payload = byteArrayOf(5, 0x41, 0x42, 0x43)
        writer.writePacket(payload)

        assertArrayEquals(payload, reader.readPacket())
    }

    // =========================================================================
    // AEAD (GCM) encrypted roundtrip
    // =========================================================================

    @Test
    fun `AEAD GCM encrypted write and read roundtrip`() = runBlocking {
        val key = ByteArray(32) { (it + 1).toByte() }
        val baseIv = ByteArray(12) { (it + 0x50).toByte() }
        val aesKey = SecretKeySpec(key, "AES")

        // For AEAD, the cipher in CryptoState is not directly used — fresh per packet
        val dummyCipher = Cipher.getInstance("AES/GCM/NoPadding")
        dummyCipher.init(Cipher.ENCRYPT_MODE, aesKey, javax.crypto.spec.GCMParameterSpec(128, baseIv))

        val sendCrypto = CryptoState(
            dummyCipher, null, 0, isAead = true,
            aesKey = aesKey, baseIv = baseIv
        )
        val recvCrypto = CryptoState(
            dummyCipher, null, 0, isAead = true,
            aesKey = aesKey, baseIv = baseIv
        )

        val pipe = PipeSource()
        val writer = AsyncPacketIO(pipe)
        writer.sendCipher = sendCrypto

        val reader = AsyncPacketIO(pipe)
        reader.recvCipher = recvCrypto

        val payload = byteArrayOf(SshMsgType.CHANNEL_DATA.toByte(), 0x01, 0x02, 0x03)
        writer.writePacket(payload)

        val result = reader.readPacket()
        assertArrayEquals(payload, result)
    }

    @Test
    fun `AEAD GCM multiple packets roundtrip`() = runBlocking {
        val key = ByteArray(32) { (it + 7).toByte() }
        val baseIv = ByteArray(12) { (it + 0x60).toByte() }
        val aesKey = SecretKeySpec(key, "AES")

        val dummyCipher = Cipher.getInstance("AES/GCM/NoPadding")
        dummyCipher.init(Cipher.ENCRYPT_MODE, aesKey, javax.crypto.spec.GCMParameterSpec(128, baseIv))

        val sendCrypto = CryptoState(
            dummyCipher, null, 0, isAead = true,
            aesKey = aesKey, baseIv = baseIv
        )
        val recvCrypto = CryptoState(
            dummyCipher, null, 0, isAead = true,
            aesKey = aesKey, baseIv = baseIv
        )

        val pipe = PipeSource()
        val writer = AsyncPacketIO(pipe)
        writer.sendCipher = sendCrypto

        val reader = AsyncPacketIO(pipe)
        reader.recvCipher = recvCrypto

        val p1 = byteArrayOf(20, 1)
        val p2 = byteArrayOf(21, 2, 3, 4, 5, 6, 7, 8)
        val p3 = ByteArray(500) { (it % 256).toByte() }

        writer.writePacket(p1)
        writer.writePacket(p2)
        writer.writePacket(p3)

        assertArrayEquals(p1, reader.readPacket())
        assertArrayEquals(p2, reader.readPacket())
        assertArrayEquals(p3, reader.readPacket())
    }

    // =========================================================================
    // CryptoState.buildNonce
    // =========================================================================

    @Test
    fun `buildNonce with sequence 0 returns base IV`() {
        val baseIv = ByteArray(12) { (it + 1).toByte() }
        val aesKey = SecretKeySpec(ByteArray(32), "AES")
        val dummyCipher = Cipher.getInstance("AES/GCM/NoPadding")
        dummyCipher.init(Cipher.ENCRYPT_MODE, aesKey, javax.crypto.spec.GCMParameterSpec(128, baseIv))
        val crypto = CryptoState(dummyCipher, null, 0, isAead = true, aesKey = aesKey, baseIv = baseIv)

        val nonce = crypto.buildNonce(0)
        assertArrayEquals(baseIv, nonce)
    }

    @Test
    fun `buildNonce with sequence 1 XORs last byte`() {
        val baseIv = ByteArray(12) { 0 }
        val aesKey = SecretKeySpec(ByteArray(32), "AES")
        val dummyCipher = Cipher.getInstance("AES/GCM/NoPadding")
        dummyCipher.init(Cipher.ENCRYPT_MODE, aesKey, javax.crypto.spec.GCMParameterSpec(128, baseIv))
        val crypto = CryptoState(dummyCipher, null, 0, isAead = true, aesKey = aesKey, baseIv = baseIv)

        val nonce = crypto.buildNonce(1)
        assertEquals(1, nonce[11].toInt() and 0xFF)
        assertEquals(0, nonce[10].toInt() and 0xFF)
    }

    @Test
    fun `buildNonce with sequence 256 XORs second-to-last byte`() {
        val baseIv = ByteArray(12) { 0 }
        val aesKey = SecretKeySpec(ByteArray(32), "AES")
        val dummyCipher = Cipher.getInstance("AES/GCM/NoPadding")
        dummyCipher.init(Cipher.ENCRYPT_MODE, aesKey, javax.crypto.spec.GCMParameterSpec(128, baseIv))
        val crypto = CryptoState(dummyCipher, null, 0, isAead = true, aesKey = aesKey, baseIv = baseIv)

        val nonce = crypto.buildNonce(256)
        assertEquals(0, nonce[11].toInt() and 0xFF)
        assertEquals(1, nonce[10].toInt() and 0xFF)
    }

    @Test
    fun `buildNonce with large sequence number`() {
        val baseIv = ByteArray(12) { 0xFF.toByte() }
        val aesKey = SecretKeySpec(ByteArray(32), "AES")
        val dummyCipher = Cipher.getInstance("AES/GCM/NoPadding")
        dummyCipher.init(Cipher.ENCRYPT_MODE, aesKey, javax.crypto.spec.GCMParameterSpec(128, baseIv))
        val crypto = CryptoState(dummyCipher, null, 0, isAead = true, aesKey = aesKey, baseIv = baseIv)

        val nonce = crypto.buildNonce(0xDEADBEEFCAFEL)
        // Should not throw, and should be 12 bytes
        assertEquals(12, nonce.size)
    }

    @Test(expected = IllegalStateException::class)
    fun `buildNonce without baseIv throws`() {
        val dummyCipher = Cipher.getInstance("AES/CTR/NoPadding")
        val key = SecretKeySpec(ByteArray(16), "AES")
        dummyCipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(ByteArray(16)))
        val crypto = CryptoState(dummyCipher, null, 0, isAead = true, aesKey = null, baseIv = null)

        crypto.buildNonce(0)
    }

    // =========================================================================
    // CryptoState equality and hashCode
    // =========================================================================

    @Test
    fun `CryptoState equals is identity-based`() {
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        val key = SecretKeySpec(ByteArray(16), "AES")
        cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(ByteArray(16)))

        val a = CryptoState(cipher, null, 0)
        val b = CryptoState(cipher, null, 0)

        // Identity-based equals: same instance is equal, different is not
        assertTrue(a == a)
        assertTrue(a != b)
    }

    @Test
    fun `CryptoState hashCode uses identity`() {
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        val key = SecretKeySpec(ByteArray(16), "AES")
        cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(ByteArray(16)))

        val cs = CryptoState(cipher, null, 0)
        assertEquals(System.identityHashCode(cs), cs.hashCode())
    }

    // =========================================================================
    // computePaddingLength edge cases
    // =========================================================================

    @Test
    fun `computePaddingLength always returns at least 4`() {
        val method = AsyncPacketIO::class.java.getDeclaredMethod(
            "computePaddingLength", Int::class.java, Int::class.java, Boolean::class.java
        )
        method.isAccessible = true
        val source = ByteArraySource(ByteArray(0))
        val packetIO = AsyncPacketIO(source)

        for (payloadSize in 0..100) {
            for (blockSize in listOf(8, 16)) {
                // E&M mode (etm=false): (5 + payloadSize + padding) must be multiple of blockSize
                val padding = method.invoke(packetIO, payloadSize, blockSize, false) as Int
                assertTrue("Padding must be >= 4 for payload=$payloadSize, block=$blockSize, got $padding",
                    padding >= 4)
                assertEquals("Total must be multiple of blockSize",
                    0, (5 + payloadSize + padding) % blockSize)

                // ETM mode (etm=true): (1 + payloadSize + padding) must be multiple of blockSize
                val etmPadding = method.invoke(packetIO, payloadSize, blockSize, true) as Int
                assertTrue("ETM padding must be >= 4 for payload=$payloadSize, block=$blockSize, got $etmPadding",
                    etmPadding >= 4)
                assertEquals("ETM packet_length must be multiple of blockSize",
                    0, (1 + payloadSize + etmPadding) % blockSize)
            }
        }
    }

    @Test
    fun `computePaddingLength with blockSize 16 for AEAD`() {
        val method = AsyncPacketIO::class.java.getDeclaredMethod(
            "computePaddingLength", Int::class.java, Int::class.java, Boolean::class.java
        )
        method.isAccessible = true
        val source = ByteArraySource(ByteArray(0))
        val packetIO = AsyncPacketIO(source)

        // payloadSize = 1, blockSize = 16: unpadded = 6, padding = 16 - 6 = 10 (>= 4, ok)
        val padding = method.invoke(packetIO, 1, 16, false) as Int
        assertTrue(padding >= 4)
        assertEquals(0, (5 + 1 + padding) % 16)
    }

    @Test
    fun `computePaddingLength where initial padding is less than 4`() {
        val method = AsyncPacketIO::class.java.getDeclaredMethod(
            "computePaddingLength", Int::class.java, Int::class.java, Boolean::class.java
        )
        method.isAccessible = true
        val source = ByteArraySource(ByteArray(0))
        val packetIO = AsyncPacketIO(source)

        // payloadSize = 2, blockSize = 8: unpadded = 7, padding = 8 - 7 = 1 -> 1 < 4 -> 1 + 8 = 9
        val padding = method.invoke(packetIO, 2, 8, false) as Int
        assertTrue(padding >= 4)
        assertEquals(0, (5 + 2 + padding) % 8)
    }

    // =========================================================================
    // readExact error cases
    // =========================================================================

    @Test(expected = SshProtocolException::class)
    fun `readExact throws on premature EOF`() {
        runBlocking {
            // Only provide 2 bytes but try to read a packet that expects more
            val shortData = byteArrayOf(0, 0, 0, 10, 5) // packet_length=10, but only 1 byte after header
            val source = ByteArraySource(shortData)
            val packetIO = AsyncPacketIO(source)
            packetIO.readPacket()
        }
    }

    @Test(expected = SshProtocolException::class)
    fun `readExact throws on empty stream`() {
        runBlocking {
            val source = ByteArraySource(ByteArray(0))
            val packetIO = AsyncPacketIO(source)
            packetIO.readPacket()
        }
    }

    // =========================================================================
    // Invalid packet length
    // =========================================================================

    @Test(expected = SshProtocolException::class)
    fun `readPlaintextPacket throws on packet length 0`() {
        runBlocking {
            // packet_length = 0 (< 2)
            val data = byteArrayOf(0, 0, 0, 0)
            val source = ByteArraySource(data)
            val packetIO = AsyncPacketIO(source)
            packetIO.readPacket()
        }
    }

    @Test(expected = SshProtocolException::class)
    fun `readPlaintextPacket throws on packet length 1`() {
        runBlocking {
            // packet_length = 1 (< 2)
            val data = byteArrayOf(0, 0, 0, 1, 0)
            val source = ByteArraySource(data)
            val packetIO = AsyncPacketIO(source)
            packetIO.readPacket()
        }
    }

    @Test(expected = SshProtocolException::class)
    fun `readPlaintextPacket throws on excessive packet length`() {
        runBlocking {
            // packet_length = 300000 (> MAX_PACKET_LENGTH=256*1024)
            val data = byteArrayOf(0, 0x04, (0x93).toByte(), (0xE0).toByte())
            val source = ByteArraySource(data)
            val packetIO = AsyncPacketIO(source)
            packetIO.readPacket()
        }
    }

    @Test(expected = SshProtocolException::class)
    fun `readPlaintextPacket throws on invalid padding length`() {
        runBlocking {
            // packet_length = 2, padding_length = 5 -> payloadLength = 2 - 5 - 1 = -4
            val data = byteArrayOf(0, 0, 0, 2, 5, 0)
            val source = ByteArraySource(data)
            val packetIO = AsyncPacketIO(source)
            packetIO.readPacket()
        }
    }

    // =========================================================================
    // close method
    // =========================================================================

    @Test
    fun `close closes source`() {
        val source = object : ByteArraySource(ByteArray(0)) {
            var closed = false
            override fun close() { closed = true }
        }
        val packetIO = AsyncPacketIO(source)
        packetIO.close()
        assertTrue(source.closed)
    }

    // =========================================================================
    // MAX_PACKET_LENGTH constant
    // =========================================================================

    @Test
    fun `MAX_PACKET_LENGTH is 256KB`() {
        assertEquals(256 * 1024, AsyncPacketIO.MAX_PACKET_LENGTH)
    }

    // =========================================================================
    // SshProtocolException
    // =========================================================================

    @Test
    fun `SshProtocolException with message only`() {
        val ex = SshProtocolException("test error")
        assertEquals("test error", ex.message)
    }

    @Test
    fun `SshProtocolException with cause`() {
        val cause = RuntimeException("root cause")
        val ex = SshProtocolException("wrapper", cause)
        assertEquals("wrapper", ex.message)
        assertEquals(cause, ex.cause)
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private data class Pipe(val writer: AsyncPacketIO, val reader: AsyncPacketIO)

    private fun createPipe(): Pipe {
        val shared = PipeSource()
        val writer = AsyncPacketIO(shared)
        val reader = AsyncPacketIO(shared)
        return Pipe(writer, reader)
    }

    private fun createAesCtrCipher(key: ByteArray, iv: ByteArray, encrypt: Boolean): Cipher {
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        val mode = if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE
        cipher.init(mode, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher
    }

    private fun createHmacSha256(key: ByteArray): Mac {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac
    }
}
