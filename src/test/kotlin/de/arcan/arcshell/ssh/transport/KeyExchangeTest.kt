package de.arcan.arcshell.ssh.transport

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger

class Curve25519Sha256Test {

    @Test
    fun `generates 32-byte client public key`() {
        val kex = Curve25519Sha256()
        val pubKey = kex.generateClientKey()
        assertEquals(32, pubKey.size)
    }

    @Test
    fun `two instances produce different keys`() {
        val kex1 = Curve25519Sha256()
        val kex2 = Curve25519Sha256()
        val key1 = kex1.generateClientKey()
        val key2 = kex2.generateClientKey()
        assertNotEquals(key1.toList(), key2.toList())
    }

    @Test
    fun `shared secret is computed from partner key`() {
        // Simulate both sides of the exchange
        val client = Curve25519Sha256()
        val server = Curve25519Sha256()
        val clientPub = client.generateClientKey()
        val serverPub = server.generateClientKey()

        val clientSecret = client.computeSharedSecret(serverPub)
        val serverSecret = server.computeSharedSecret(clientPub)

        assertEquals(clientSecret, serverSecret)
        assertTrue(clientSecret > BigInteger.ZERO)
    }

    @Test
    fun `exchange hash produces 32 bytes (SHA-256)`() {
        val kex = Curve25519Sha256()
        val pubKey = kex.generateClientKey()
        val hash = kex.computeExchangeHash(
            clientVersion = "SSH-2.0-ArcShell_1.0",
            serverVersion = "SSH-2.0-OpenSSH_9.6",
            clientKexInit = byteArrayOf(20, 1, 2, 3),
            serverKexInit = byteArrayOf(20, 4, 5, 6),
            hostKeyBlob = byteArrayOf(0, 0, 0, 11) + "ssh-ed25519".toByteArray(),
            clientPublicKey = pubKey,
            serverPublicKey = ByteArray(32) { it.toByte() },
            sharedSecret = BigInteger.valueOf(42)
        )
        assertEquals(32, hash.size)
    }

    @Test
    fun `libssh variant has correct name`() {
        val kex = Curve25519Sha256LibSsh()
        assertEquals("curve25519-sha256@libssh.org", kex.name)
    }
}

class EcdhSha2Test {

    @Test
    fun `nistp256 generates valid key pair`() {
        val kex = EcdhSha2("nistp256", "SHA-256")
        val pubKey = kex.generateClientKey()
        assertEquals(0x04, pubKey[0].toInt()) // uncompressed point
        assertEquals(65, pubKey.size) // 1 + 32 + 32
    }

    @Test
    fun `nistp256 shared secret agreement`() {
        val client = EcdhSha2("nistp256", "SHA-256")
        val server = EcdhSha2("nistp256", "SHA-256")
        val clientPub = client.generateClientKey()
        val serverPub = server.generateClientKey()

        val clientSecret = client.computeSharedSecret(serverPub)
        val serverSecret = server.computeSharedSecret(clientPub)

        assertEquals(clientSecret, serverSecret)
        assertTrue(clientSecret > BigInteger.ZERO)
    }

    @Test
    fun `nistp384 key is 97 bytes`() {
        val kex = EcdhSha2("nistp384", "SHA-384")
        val pubKey = kex.generateClientKey()
        assertEquals(97, pubKey.size) // 1 + 48 + 48
    }

    @Test
    fun `algorithm name includes curve`() {
        assertEquals("ecdh-sha2-nistp256", EcdhSha2("nistp256", "SHA-256").name)
        assertEquals("ecdh-sha2-nistp384", EcdhSha2("nistp384", "SHA-384").name)
    }
}

class DhGroup14Sha256Test {

    @Test
    fun `generates public key`() {
        val kex = DhGroup14Sha256()
        val pubKey = kex.generateClientKey()
        val value = BigInteger(pubKey)
        assertTrue(value > BigInteger.ONE)
        assertTrue(value < DhGroup14Sha256.DH_GROUP14_P)
    }

    @Test
    fun `shared secret agreement`() {
        val client = DhGroup14Sha256()
        val server = DhGroup14Sha256()
        val clientPub = client.generateClientKey()
        val serverPub = server.generateClientKey()

        val clientSecret = client.computeSharedSecret(serverPub)
        val serverSecret = server.computeSharedSecret(clientPub)

        assertEquals(clientSecret, serverSecret)
    }

    @Test
    fun `name is correct`() {
        assertEquals("diffie-hellman-group14-sha256", DhGroup14Sha256().name)
    }
}

class KeyExchangeRegistryTest {

    @Test
    fun `registry returns all algorithms`() {
        val algos = KeyExchangeRegistry.getPreferred()
        assertTrue(algos.size >= 6)
    }

    @Test
    fun `post-quantum hybrid is first preference`() {
        assertEquals("mlkem768x25519-sha512", KeyExchangeRegistry.getPreferred()[0].name)
    }

    @Test
    fun `curve25519 is second preference`() {
        assertEquals("curve25519-sha256", KeyExchangeRegistry.getPreferred()[1].name)
    }

    @Test
    fun `lookup by name works`() {
        assertNotNull(KeyExchangeRegistry.byName("curve25519-sha256"))
        assertNotNull(KeyExchangeRegistry.byName("ecdh-sha2-nistp256"))
        assertNotNull(KeyExchangeRegistry.byName("diffie-hellman-group14-sha256"))
        assertEquals(null, KeyExchangeRegistry.byName("nonexistent"))
    }

    @Test
    fun `name list matches algorithm count`() {
        assertEquals(
            KeyExchangeRegistry.getPreferred().size,
            KeyExchangeRegistry.nameList().size
        )
    }
}
