package de.arcan.arcshell.ssh.transport

import de.arcan.arcshell.ssh.SshMsgType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KexInitTest {

    @Test
    fun `createClient has 16-byte cookie`() {
        val kexInit = KexInit.createClient()
        assertEquals(16, kexInit.cookie.size)
    }

    @Test
    fun `createClient includes all algorithm categories`() {
        val kexInit = KexInit.createClient()
        assertTrue(kexInit.kexAlgorithms.isNotEmpty())
        assertTrue(kexInit.serverHostKeyAlgorithms.isNotEmpty())
        assertTrue(kexInit.encryptionClientToServer.isNotEmpty())
        assertTrue(kexInit.encryptionServerToClient.isNotEmpty())
        assertTrue(kexInit.macClientToServer.isNotEmpty())
        assertTrue(kexInit.macServerToClient.isNotEmpty())
        assertTrue(kexInit.compressionClientToServer.contains("none"))
        assertFalse(kexInit.firstKexPacketFollows)
    }

    @Test
    fun `encode starts with KEXINIT message type`() {
        val kexInit = KexInit.createClient()
        val encoded = kexInit.encode()
        assertEquals(SshMsgType.KEXINIT, encoded[0].toInt())
    }

    @Test
    fun `encode-decode round-trip preserves algorithms`() {
        val original = KexInit.createClient()
        val encoded = original.encode()
        val decoded = KexInit.decode(encoded)

        assertEquals(original.kexAlgorithms, decoded.kexAlgorithms)
        assertEquals(original.serverHostKeyAlgorithms, decoded.serverHostKeyAlgorithms)
        assertEquals(original.encryptionClientToServer, decoded.encryptionClientToServer)
        assertEquals(original.encryptionServerToClient, decoded.encryptionServerToClient)
        assertEquals(original.macClientToServer, decoded.macClientToServer)
        assertEquals(original.macServerToClient, decoded.macServerToClient)
        assertEquals(original.compressionClientToServer, decoded.compressionClientToServer)
        assertEquals(original.firstKexPacketFollows, decoded.firstKexPacketFollows)
    }

    @Test
    fun `two createClient calls have different cookies`() {
        val a = KexInit.createClient()
        val b = KexInit.createClient()
        assertFalse(a.cookie.contentEquals(b.cookie))
    }
}

class NegotiationTest {

    @Test
    fun `matching algorithms are negotiated`() {
        val client = KexInit.createClient()
        // Server offers subset of what we support
        val server = client.copy(
            kexAlgorithms = listOf("curve25519-sha256", "diffie-hellman-group14-sha256"),
            serverHostKeyAlgorithms = listOf("ssh-ed25519", "rsa-sha2-256"),
            encryptionClientToServer = listOf("aes256-ctr", "aes128-ctr"),
            encryptionServerToClient = listOf("aes256-ctr", "aes128-ctr"),
            macClientToServer = listOf("hmac-sha2-256"),
            macServerToClient = listOf("hmac-sha2-256"),
            compressionClientToServer = listOf("none"),
            compressionServerToClient = listOf("none")
        )

        val result = negotiateAlgorithms(client, server)
        assertEquals("curve25519-sha256", result.kex)
        assertEquals("ssh-ed25519", result.hostKey)
        assertEquals("aes256-ctr", result.cipherC2S)
        assertEquals("hmac-sha2-256", result.macC2S)
        assertEquals("none", result.compressionC2S)
    }

    @Test
    fun `AEAD cipher skips MAC negotiation`() {
        val client = KexInit.createClient()
        val server = client.copy(
            kexAlgorithms = listOf("curve25519-sha256"),
            serverHostKeyAlgorithms = listOf("ssh-ed25519"),
            encryptionClientToServer = listOf("aes256-gcm@openssh.com"),
            encryptionServerToClient = listOf("aes256-gcm@openssh.com"),
            macClientToServer = emptyList(), // no MACs offered
            macServerToClient = emptyList(),
            compressionClientToServer = listOf("none"),
            compressionServerToClient = listOf("none")
        )

        val result = negotiateAlgorithms(client, server)
        assertEquals("aes256-gcm@openssh.com", result.cipherC2S)
        assertEquals("none", result.macC2S) // no MAC needed for AEAD
    }

    @Test(expected = SshProtocolException::class)
    fun `no common KEX algorithm throws`() {
        val client = KexInit.createClient()
        val server = client.copy(kexAlgorithms = listOf("nonexistent-kex"))
        negotiateAlgorithms(client, server)
    }

    @Test(expected = SshProtocolException::class)
    fun `no common cipher throws`() {
        val client = KexInit.createClient()
        val server = client.copy(
            encryptionClientToServer = listOf("3des-cbc"),
            encryptionServerToClient = listOf("3des-cbc")
        )
        negotiateAlgorithms(client, server)
    }

    @Test
    fun `client preference wins`() {
        val client = KexInit.createClient()
        // Server offers everything but in different order — client's first match wins
        val serverAlgos = client.kexAlgorithms.reversed()
        val server = client.copy(kexAlgorithms = serverAlgos)

        val result = negotiateAlgorithms(client, server)
        assertEquals(client.kexAlgorithms[0], result.kex) // client's preference
    }
}
