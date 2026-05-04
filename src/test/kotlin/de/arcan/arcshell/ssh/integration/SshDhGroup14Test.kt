package de.arcan.arcshell.integration

import de.arcan.arcshell.ssh.SshConfig
import de.arcan.arcshell.ssh.auth.AuthResult
import de.arcan.arcshell.ssh.nio.AsyncSshClient
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.net.Socket

/**
 * Tests SSH with diffie-hellman-group14-sha256 KEX.
 * Requires a SEPARATE Docker sshd on port 2223 configured with DH14 only:
 * docker run -d --name arcshell-sshd-dh14 -p 2223:22 arcshell-test-ssh bash -c \
 *   'echo "KexAlgorithms diffie-hellman-group14-sha256" >> /etc/ssh/sshd_config && \
 *    echo "Ciphers aes256-ctr,aes128-ctr" >> /etc/ssh/sshd_config && \
 *    echo "MACs hmac-sha2-256" >> /etc/ssh/sshd_config && /usr/sbin/sshd -D -e'
 */
class SshDhGroup14Test {

    private val host = "127.0.0.1"
    private val port = 2223 // DH14-only server
    private var client: AsyncSshClient? = null

    @Before
    fun checkServer() {
        val available = try { Socket(host, port).use { true } } catch (_: Exception) { false }
        assertTrue("DH14 SSH server REQUIRED on $host:$port. See class docs.", available)
    }

    @After
    fun cleanup() {
        try { client?.disconnect() } catch (_: Exception) {}
    }

    @Test
    fun `connect with DH group14 KEX succeeds`() = runBlocking {
        val config = SshConfig(host, port, "testuser", connectTimeoutMs = 10000)
        client = AsyncSshClient(config, hostKeyVerifier = { _, _ -> true })
        client!!.connect()
        assertTrue(client!!.isConnected)
        assertEquals("diffie-hellman-group14-sha256", client!!.kexAlgorithm)

        val result = client!!.authPassword("testpass123")
        assertTrue(result is AuthResult.Success)
    }

    @Test
    fun `exec over DH group14 connection works`() = runBlocking {
        val config = SshConfig(host, port, "testuser", connectTimeoutMs = 10000)
        client = AsyncSshClient(config, hostKeyVerifier = { _, _ -> true })
        client!!.connect()
        client!!.authPassword("testpass123")
        val session = client!!.openSession()

        session.requestExec("echo DH14_WORKS")
        val buf = ByteArrayOutputStream()
        while (true) { val d = session.read(); if (d.isEmpty()) break; buf.write(d) }
        assertTrue(buf.toString().contains("DH14_WORKS"))
    }
}
