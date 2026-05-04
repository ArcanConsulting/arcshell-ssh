package de.arcan.arcshell.ssh.transport

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

class CipherRegistryTest {

    @Test
    fun `preferred ciphers start with ChaCha20-Poly1305`() {
        val first = CipherRegistry.getPreferred()[0]
        assertTrue("First cipher should be AEAD (ChaCha20-Poly1305)", first.isAead)
        assertEquals("chacha20-poly1305@openssh.com", first.name)
    }

    @Test
    fun `all ciphers have correct key sizes`() {
        CipherRegistry.getPreferred().forEach { cipher ->
            assertTrue("Key size must be positive: ${cipher.name}", cipher.keySize > 0)
            if (!CipherRegistry.isChaCha(cipher.name)) {
                assertTrue("IV size must be positive: ${cipher.name}", cipher.ivSize > 0)
            }
        }
    }

    @Test
    fun `lookup by name`() {
        assertNotNull(CipherRegistry.byName("aes256-ctr"))
        assertNotNull(CipherRegistry.byName("aes256-gcm@openssh.com"))
        assertNotNull(CipherRegistry.byName("chacha20-poly1305@openssh.com"))
        assertEquals(null, CipherRegistry.byName("nonexistent"))
    }

    @Test
    fun `chacha20 is identified as AEAD`() {
        val chacha = CipherRegistry.byName("chacha20-poly1305@openssh.com")!!
        assertTrue("ChaCha20-Poly1305 must be AEAD", chacha.isAead)
        assertEquals(64, chacha.keySize) // 32 bytes K1 + 32 bytes K2
        assertEquals(8, chacha.blockSize) // 8-byte block alignment
        assertTrue("isChaCha helper", CipherRegistry.isChaCha(chacha.name))
    }
}

class MacRegistryTest {

    @Test
    fun `etm MACs come first`() {
        val first = MacRegistry.getPreferred()[0]
        assertTrue("First MAC should be ETM", first.etm)
    }

    @Test
    fun `lookup by name`() {
        assertNotNull(MacRegistry.byName("hmac-sha2-256"))
        assertNotNull(MacRegistry.byName("hmac-sha2-256-etm@openssh.com"))
    }
}

class KeyDerivationTest {

    @Test
    fun `derived key has correct length`() {
        val k = BigInteger.valueOf(123456789)
        val h = ByteArray(32) { it.toByte() }

        for (neededLen in listOf(16, 24, 32, 48, 64)) {
            val key = KeyDerivation.deriveKey("SHA-256", k, h, 'C', h, neededLen)
            assertEquals(neededLen, key.size)
        }
    }

    @Test
    fun `different key IDs produce different keys`() {
        val k = BigInteger.valueOf(999)
        val h = ByteArray(32) { (it * 7).toByte() }

        val keyC = KeyDerivation.deriveKey("SHA-256", k, h, 'C', h, 32)
        val keyD = KeyDerivation.deriveKey("SHA-256", k, h, 'D', h, 32)
        assertTrue("Different key IDs must produce different keys", !keyC.contentEquals(keyD))
    }

    @Test
    fun `same inputs produce same output (deterministic)`() {
        val k = BigInteger.valueOf(42)
        val h = ByteArray(32)

        val key1 = KeyDerivation.deriveKey("SHA-256", k, h, 'A', h, 16)
        val key2 = KeyDerivation.deriveKey("SHA-256", k, h, 'A', h, 16)
        assertTrue(key1.contentEquals(key2))
    }

    @Test
    fun `createCipher produces working AES-CTR cipher`() {
        val key = ByteArray(32) { it.toByte() }
        val iv = ByteArray(16) { (it + 42).toByte() }
        val enc = KeyDerivation.createCipher(CipherRegistry.AES256_CTR, key, iv, encrypt = true)
        val dec = KeyDerivation.createCipher(CipherRegistry.AES256_CTR, key, iv, encrypt = false)

        val plaintext = "Hello SSH World!".toByteArray()
        val encrypted = enc.update(plaintext)
        val decrypted = dec.update(encrypted)
        assertTrue(plaintext.contentEquals(decrypted))
    }

    @Test
    fun `createMac produces working HMAC`() {
        val key = ByteArray(32) { it.toByte() }
        val mac = KeyDerivation.createMac(MacRegistry.HMAC_SHA2_256, key)
        mac.update("test data".toByteArray())
        val result = mac.doFinal()
        assertEquals(32, result.size)
    }
}
