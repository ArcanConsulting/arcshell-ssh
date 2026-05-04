package de.arcan.arcshell.ssh

import de.arcan.arcshell.ssh.nio.AsyncSshClient
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SshClientTest {

    // =========================================================================
    // SshConfig data class tests
    // =========================================================================

    @Test
    fun `SshConfig defaults port to 22`() {
        val config = SshConfig(hostname = "example.com", username = "user")
        assertEquals(22, config.port)
    }

    @Test
    fun `SshConfig defaults connectTimeoutMs to 10000`() {
        val config = SshConfig(hostname = "example.com", username = "user")
        assertEquals(10_000, config.connectTimeoutMs)
    }

    @Test
    fun `SshConfig defaults keepAliveIntervalMs to 0`() {
        val config = SshConfig(hostname = "example.com", username = "user")
        assertEquals(0, config.keepAliveIntervalMs)
    }

    @Test
    fun `SshConfig stores custom values`() {
        val config = SshConfig(
            hostname = "server.example.com",
            port = 2222,
            username = "admin",
            connectTimeoutMs = 5_000,
            keepAliveIntervalMs = 30_000
        )
        assertEquals("server.example.com", config.hostname)
        assertEquals(2222, config.port)
        assertEquals("admin", config.username)
        assertEquals(5_000, config.connectTimeoutMs)
        assertEquals(30_000, config.keepAliveIntervalMs)
    }

    @Test
    fun `SshConfig equality`() {
        val a = SshConfig(hostname = "host", username = "user")
        val b = SshConfig(hostname = "host", username = "user")
        assertEquals(a, b)
    }

    @Test
    fun `SshConfig inequality on different port`() {
        val a = SshConfig(hostname = "host", username = "user", port = 22)
        val b = SshConfig(hostname = "host", username = "user", port = 2222)
        assertFalse(a == b)
    }

    @Test
    fun `SshConfig inequality on different hostname`() {
        val a = SshConfig(hostname = "host1", username = "user")
        val b = SshConfig(hostname = "host2", username = "user")
        assertFalse(a == b)
    }

    @Test
    fun `SshConfig copy works`() {
        val original = SshConfig(hostname = "host", username = "user")
        val copy = original.copy(port = 443)
        assertEquals(443, copy.port)
        assertEquals("host", copy.hostname)
        assertEquals("user", copy.username)
    }

    @Test
    fun `SshConfig with all non-defaults`() {
        val config = SshConfig(
            hostname = "192.168.1.100",
            port = 8022,
            username = "root",
            connectTimeoutMs = 30_000,
            keepAliveIntervalMs = 60_000
        )
        assertEquals("192.168.1.100", config.hostname)
        assertEquals(8022, config.port)
        assertEquals("root", config.username)
        assertEquals(30_000, config.connectTimeoutMs)
        assertEquals(60_000, config.keepAliveIntervalMs)
    }

    // =========================================================================
    // AsyncSshClient state tests (no real network)
    // =========================================================================

    private val dummyVerifier: suspend (String, ByteArray) -> Boolean = { _, _ -> true }

    @Test
    fun `isConnected returns false initially`() {
        val config = SshConfig(hostname = "localhost", username = "user")
        val client = AsyncSshClient(config, dummyVerifier)
        assertFalse(client.isConnected)
    }

    @Test
    fun `transportLayer is null initially`() {
        val config = SshConfig(hostname = "localhost", username = "user")
        val client = AsyncSshClient(config, dummyVerifier)
        assertTrue(client.transportLayer == null)
    }

    @Test
    fun `kexAlgorithm returns none when not connected`() {
        val config = SshConfig(hostname = "localhost", username = "user")
        val client = AsyncSshClient(config, dummyVerifier)
        assertEquals("none", client.kexAlgorithm)
    }

    @Test
    fun `serverVersion returns empty when not connected`() {
        val config = SshConfig(hostname = "localhost", username = "user")
        val client = AsyncSshClient(config, dummyVerifier)
        assertEquals("", client.serverVersion)
    }

    // --- Error cases for methods called before connect ---

    @Test(expected = IllegalStateException::class)
    fun `authPassword throws when not connected`() { runBlocking {
        val config = SshConfig(hostname = "localhost", username = "user")
        val client = AsyncSshClient(config, dummyVerifier)
        client.authPassword("password")
    } }

    @Test(expected = IllegalStateException::class)
    fun `authPublicKey throws when not connected`() { runBlocking {
        val config = SshConfig(hostname = "localhost", username = "user")
        val client = AsyncSshClient(config, dummyVerifier)
        client.authPublicKey("ssh-ed25519", byteArrayOf(1), { it })
    } }

    @Test(expected = IllegalStateException::class)
    fun `authKeyboardInteractive throws when not connected`() { runBlocking {
        val config = SshConfig(hostname = "localhost", username = "user")
        val client = AsyncSshClient(config, dummyVerifier)
        client.authKeyboardInteractive { _, _, _ -> emptyList() }
    } }

    @Test(expected = IllegalStateException::class)
    fun `queryAuthMethods throws when not connected`() { runBlocking {
        val config = SshConfig(hostname = "localhost", username = "user")
        val client = AsyncSshClient(config, dummyVerifier)
        client.queryAuthMethods()
    } }

    @Test(expected = IllegalStateException::class)
    fun `openSession throws when not connected`() { runBlocking {
        val config = SshConfig(hostname = "localhost", username = "user")
        val client = AsyncSshClient(config, dummyVerifier)
        client.openSession()
    } }

    @Test(expected = IllegalStateException::class)
    fun `openDirectTcp throws when not connected`() { runBlocking {
        val config = SshConfig(hostname = "localhost", username = "user")
        val client = AsyncSshClient(config, dummyVerifier)
        client.openDirectTcp("remote.host", 8080)
    } }

    // --- disconnect clears state ---

    @Test
    fun `disconnect on not-connected client does not throw`() {
        val config = SshConfig(hostname = "localhost", username = "user")
        val client = AsyncSshClient(config, dummyVerifier)
        // Should not throw
        client.disconnect()
        assertFalse(client.isConnected)
    }

    @Test
    fun `disconnect clears state`() {
        val config = SshConfig(hostname = "localhost", username = "user")
        val client = AsyncSshClient(config, dummyVerifier)
        client.disconnect()

        assertFalse(client.isConnected)
        assertTrue(client.transportLayer == null)
        assertEquals("none", client.kexAlgorithm)
        assertEquals("", client.serverVersion)
    }

    @Test
    fun `multiple disconnects are safe`() {
        val config = SshConfig(hostname = "localhost", username = "user")
        val client = AsyncSshClient(config, dummyVerifier)
        client.disconnect()
        client.disconnect()
        client.disconnect()
        assertFalse(client.isConnected)
    }
}
