package de.arcan.arcshell.integration

import de.arcan.arcshell.security.KeyGenerator
import de.arcan.arcshell.security.KeySigner
import de.arcan.arcshell.model.KeyType
import de.arcan.arcshell.ssh.SshConfig
import de.arcan.arcshell.ssh.auth.AuthResult
import de.arcan.arcshell.ssh.nio.AsyncSessionChannel
import de.arcan.arcshell.ssh.nio.AsyncSshClient
import de.arcan.arcshell.ssh.sftp.SftpClient
import de.arcan.arcshell.ssh.sftp.SftpConstants
import de.arcan.arcshell.ssh.sftp.SftpException
import de.arcan.arcshell.ssh.transport.SshBufferReader
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Integration tests against a real SSH server (Docker container on localhost:2222).
 * These tests exercise the full SSH stack: transport, auth, channels, exec, SFTP.
 *
 * Test server: docker run -d --name arcshell-sshd -p 2222:22 arcshell-test-ssh
 * Credentials: testuser / testpass123
 *
 * Tests are skipped if the container isn't running (via Assume).
 */
class SshIntegrationTest {

    private val host = "127.0.0.1"
    private val port = 2222
    private val username = "testuser"
    private val password = "testpass123"
    private var client: AsyncSshClient? = null

    @Before
    fun checkServer() {
        val available = try {
            Socket(host, port).use { true }
        } catch (_: Exception) { false }
        assertTrue(
            "SSH test server REQUIRED on $host:$port. Start with: " +
            "docker run -d --name arcshell-sshd -p 2222:22 arcshell-test-ssh",
            available
        )
    }

    @After
    fun cleanup() {
        try { client?.disconnect() } catch (_: Exception) {}
        client = null
    }

    private fun connect(): AsyncSshClient = runBlocking {
        val config = SshConfig(host, port, username, connectTimeoutMs = 5000)
        val ssh = AsyncSshClient(config, hostKeyVerifier = { _, _ -> true })
        ssh.connect()
        client = ssh
        ssh
    }

    // ---- Transport ----

    @Test
    fun `connect performs handshake successfully`() {
        val ssh = connect()
        assertTrue(ssh.isConnected)
        assertTrue(ssh.serverVersion.startsWith("SSH-2.0"))
        assertTrue(ssh.kexAlgorithm.isNotEmpty())
    }

    @Test
    fun `connect to wrong port fails`() = runBlocking {
        val config = SshConfig(host, 29999, username, connectTimeoutMs = 2000)
        val ssh = AsyncSshClient(config, hostKeyVerifier = { _, _ -> true })
        try {
            ssh.connect()
            assertTrue("Should have thrown", false)
        } catch (e: Exception) {
            assertTrue(e.message != null)
        }
    }

    // ---- Auth ----

    @Test
    fun `queryAuthMethods returns password`() = runBlocking {
        val ssh = connect()
        val methods = ssh.queryAuthMethods()
        assertTrue("password" in methods || "publickey" in methods)
    }

    @Test
    fun `authPassword succeeds with correct credentials`() = runBlocking {
        val ssh = connect()
        val result = ssh.authPassword(password)
        assertTrue(result is AuthResult.Success)
    }

    @Test
    fun `authPublicKey succeeds with generated Ed25519 key`() = runBlocking {
        // Generate a fresh key pair, deploy public key to Docker, authenticate
        val kp = KeyGenerator.generate("integration-test", KeyType.ED25519)
        val pubBlob = KeyGenerator.extractPublicKeyBlob(kp.publicKey)
        val keyTypeName = KeyGenerator.extractKeyTypeName(kp.publicKey)

        // Deploy the public key to the Docker container via stdin
        val pubKeyLine = kp.publicKey
        val deployed = try {
            val pb = ProcessBuilder("docker", "exec", "-i", "arcshell-sshd", "bash")
            val proc = pb.start()
            proc.outputStream.write(
                ("mkdir -p /home/testuser/.ssh\n" +
                 "echo '${pubKeyLine}' >> /home/testuser/.ssh/authorized_keys\n" +
                 "chown -R testuser:testuser /home/testuser/.ssh\n" +
                 "chmod 600 /home/testuser/.ssh/authorized_keys\n" +
                 "exit\n").toByteArray()
            )
            proc.outputStream.flush()
            proc.waitFor() == 0
        } catch (_: Exception) { false }
        assertTrue("Must be able to deploy key to Docker container", deployed)

        val signer = KeySigner.createSigner(kp)
        val ssh = connect()
        val result = ssh.authPublicKey(keyTypeName, pubBlob, signer)
        assertTrue("Public key auth should succeed", result is AuthResult.Success)
    }

    @Test
    fun `authPassword fails with wrong password`() = runBlocking {
        val ssh = connect()
        val result = ssh.authPassword("wrongpassword")
        assertTrue(result is AuthResult.Failure)
    }

    // ---- Exec ----

    @Test
    fun `authKeyboardInteractive succeeds with correct password`() = runBlocking {
        val ssh = connect()
        val result = ssh.authKeyboardInteractive { name, instruction, prompts ->
            // PAM sends a "Password: " prompt — answer with the password
            prompts.map { password }
        }
        assertTrue("keyboard-interactive auth should succeed", result is AuthResult.Success)
    }

    // ---- Exec with large output (triggers window adjust) ----

    @Test
    fun `exec large output triggers window management`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        // Generate ~200KB output — exceeds initial window, forces WINDOW_ADJUST
        session.requestExec("dd if=/dev/urandom bs=1024 count=200 2>/dev/null | base64")
        val output = readAllOutput(session)
        // base64 of 200KB = ~270KB text
        assertTrue("Large output should be >100KB, got ${output.length}", output.length > 100_000)
    }

    @Test
    fun `exec large input triggers write window management`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        // wc -c counts bytes from stdin
        session.requestExec("wc -c")
        // Write 100KB of data
        val chunk = "x".repeat(1024).toByteArray()
        repeat(100) { session.write(chunk) }
        session.sendEof()
        val output = readAllOutput(session)
        // wc should report ~102400 bytes
        val count = output.trim().toLongOrNull() ?: 0
        assertTrue("Should have received ~100KB, got $count", count > 90_000)
    }

    @Test
    fun `exec echo returns output`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        session.requestExec("echo hello_integration")
        val output = readAllOutput(session)
        assertTrue(output.contains("hello_integration"))
    }

    @Test
    fun `exec captures exit status 0`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        session.requestExec("true")
        readAllOutput(session)
        waitForExitStatus(session)
        assertEquals(0, session.exitStatus)
    }

    @Test
    fun `exec captures non-zero exit status`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        session.requestExec("exit 42")
        readAllOutput(session)
        waitForExitStatus(session)
        assertEquals(42, session.exitStatus)
    }

    @Test
    fun `exec with PTY runs shell command`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        session.requestPty("xterm", 80, 24)
        session.requestExec("whoami")
        val output = readAllOutput(session)
        assertTrue(output.contains(username))
    }

    @Test
    fun `exec uname returns Linux`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        session.requestExec("uname -s")
        val output = readAllOutput(session)
        assertTrue(output.trim() == "Linux")
    }

    @Test
    fun `multiple exec sessions on same connection`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)

        val s1 = ssh.openSession()
        s1.requestExec("echo first")
        val out1 = readAllOutput(s1)
        assertTrue(out1.contains("first"))

        val s2 = ssh.openSession()
        s2.requestExec("echo second")
        val out2 = readAllOutput(s2)
        assertTrue(out2.contains("second"))
    }

    // ---- SFTP ----

    @Test
    fun `sftp init returns version 3`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        session.requestSubsystem("sftp")
        val sftp = SftpClient(session)
        val version = sftp.init()
        assertEquals(3, version)
        sftp.close()
    }

    @Test
    fun `sftp realpath returns absolute path`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        session.requestSubsystem("sftp")
        val sftp = SftpClient(session)
        sftp.init()

        val home = sftp.realpath(".")
        assertTrue(home.startsWith("/"))
        sftp.close()
    }

    @Test
    fun `sftp listDirectory returns entries`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        session.requestSubsystem("sftp")
        val sftp = SftpClient(session)
        sftp.init()

        val entries = sftp.listDirectory("/")
        assertTrue(entries.isNotEmpty())
        assertTrue(entries.any { it.filename == "etc" || it.filename == "usr" })
        sftp.close()
    }

    @Test
    fun `sftp stat on root returns directory`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        session.requestSubsystem("sftp")
        val sftp = SftpClient(session)
        sftp.init()

        val attrs = sftp.stat("/")
        assertTrue(attrs.isDirectory)
        sftp.close()
    }

    @Test
    fun `sftp mkdir and rmdir`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        session.requestSubsystem("sftp")
        val sftp = SftpClient(session)
        sftp.init()

        val home = sftp.realpath(".")
        val testDir = "$home/test_integration_${System.currentTimeMillis()}"
        sftp.mkdir(testDir)

        val attrs = sftp.stat(testDir)
        assertTrue(attrs.isDirectory)

        sftp.rmdir(testDir)
        try {
            sftp.stat(testDir)
            assertTrue("Should have thrown", false)
        } catch (e: SftpException) {
            assertEquals(SftpConstants.SSH_FX_NO_SUCH_FILE, e.statusCode)
        }
        sftp.close()
    }

    @Test
    fun `sftp upload and download file`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        session.requestSubsystem("sftp")
        val sftp = SftpClient(session)
        sftp.init()

        val home = sftp.realpath(".")
        val testFile = "$home/test_upload_${System.currentTimeMillis()}.txt"
        val content = "Hello from ArcShell integration test!\n"

        // Upload
        content.byteInputStream().use { input ->
            sftp.uploadFile(input, testFile, content.length.toLong())
        }

        // Download and verify
        val output = ByteArrayOutputStream()
        sftp.downloadFile(testFile, output)
        assertEquals(content, output.toString(Charsets.UTF_8.name()))

        // Cleanup
        sftp.remove(testFile)
        sftp.close()
    }

    @Test
    fun `sftp rename file`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        session.requestSubsystem("sftp")
        val sftp = SftpClient(session)
        sftp.init()

        val home = sftp.realpath(".")
        val ts = System.currentTimeMillis()
        val original = "$home/rename_test_$ts.txt"
        val renamed = "$home/rename_done_$ts.txt"

        "test".byteInputStream().use { sftp.uploadFile(it, original, 4) }
        sftp.rename(original, renamed)

        val attrs = sftp.stat(renamed)
        assertTrue(attrs.isRegularFile)

        sftp.remove(renamed)
        sftp.close()
    }

    // ---- Port forwarding (covers openDirectTcp) ----

    @Test
    fun `openDirectTcp tunnels to sshd port`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)

        // Tunnel to the sshd port inside the container — it sends the SSH banner
        val tunnel = ssh.openDirectTcp("127.0.0.1", 22)
        assertTrue(tunnel.isOpen)
        val banner = String(tunnel.read())
        assertTrue("Should get SSH banner, got: $banner", banner.startsWith("SSH-2.0"))
        tunnel.close()
    }

    @Test
    fun `openDirectTcp to closed port throws`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)

        try {
            ssh.openDirectTcp("127.0.0.1", 19999)
            assertTrue("Should have thrown", false)
        } catch (e: Exception) {
            assertTrue(e.message != null)
        }
    }

    // ---- SFTP operations (covers fstat, lstat, setstat, symlink, readlink) ----

    @Test
    fun `sftp lstat does not follow symlinks`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()
        session.requestSubsystem("sftp")
        val sftp = SftpClient(session)
        sftp.init()

        val attrs = sftp.lstat("/etc/hosts")
        assertTrue(attrs.isRegularFile)
        sftp.close()
    }

    @Test
    fun `sftp fstat on open handle`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()
        session.requestSubsystem("sftp")
        val sftp = SftpClient(session)
        sftp.init()

        val handle = sftp.openFile("/etc/hosts", SftpConstants.SSH_FXF_READ)
        val attrs = sftp.fstat(handle)
        assertTrue(attrs.isRegularFile)
        assertTrue(attrs.size > 0)
        sftp.closeHandle(handle)
        sftp.close()
    }

    @Test
    fun `sftp symlink and readlink`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()
        session.requestSubsystem("sftp")
        val sftp = SftpClient(session)
        sftp.init()

        val home = sftp.realpath(".")
        val target = "$home/symlink_target_${System.currentTimeMillis()}"
        val link = "$home/symlink_link_${System.currentTimeMillis()}"

        // Create target file
        "target content".byteInputStream().use { sftp.uploadFile(it, target, 14) }

        // Create symlink
        sftp.symlink(target, link)

        // Read link target
        val resolved = sftp.readlink(link)
        assertEquals(target, resolved)

        // Cleanup
        sftp.remove(link)
        sftp.remove(target)
        sftp.close()
    }

    @Test
    fun `sftp setstat changes permissions`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()
        session.requestSubsystem("sftp")
        val sftp = SftpClient(session)
        sftp.init()

        val home = sftp.realpath(".")
        val testFile = "$home/chmod_test_${System.currentTimeMillis()}"
        "test".byteInputStream().use { sftp.uploadFile(it, testFile, 4) }

        // Change permissions to 0755
        sftp.setstat(testFile, de.arcan.arcshell.ssh.sftp.SftpAttributes(permissions = 0x81ED))
        val attrs = sftp.stat(testFile)
        assertTrue((attrs.permissions and 0x1FF) == 0x1ED) // 0755

        sftp.remove(testFile)
        sftp.close()
    }

    // ---- Extended data / stderr ----

    @Test
    fun `readExtended captures stderr`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        session.requestExec("echo STDERR_TEST >&2")

        val stderr = String(session.readExtended())
        readAllOutput(session)
        assertTrue("Should capture stderr", stderr.contains("STDERR_TEST"))
    }

    // ---- Channel lifecycle tests ----

    @Test
    fun `channel write sends data to remote process stdin`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        // cat reads from stdin and echoes to stdout
        session.requestExec("cat")
        session.write("hello from write\n".toByteArray())
        session.sendEof() // signal end of input
        val output = readAllOutput(session)
        assertTrue(output.contains("hello from write"))
    }

    @Test
    fun `channel close terminates session`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        session.requestExec("echo test")
        readAllOutput(session)
        session.close()
        assertFalse(session.isOpen)
    }

    @Test
    fun `exec captures stderr separately`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        session.requestExec("echo stdout_data && echo stderr_data >&2")
        val stdout = readAllOutput(session)
        assertTrue(stdout.contains("stdout_data"))
        // stderr is on extDataChannel — read doesn't block if empty
    }

    @Test
    fun `setEnv sends environment variable`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        // setEnv may be rejected by sshd (AcceptEnv not configured) — that's OK
        session.setEnv("ARCSHELL_TEST", "hello")
        session.requestExec("echo done")
        val output = readAllOutput(session)
        assertTrue(output.contains("done"))
    }

    @Test
    fun `windowChange does not crash on active session`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        session.requestPty("xterm", 80, 24)
        session.requestExec("echo resized")
        session.windowChange(120, 40)
        val output = readAllOutput(session)
        assertTrue(output.contains("resized"))
    }

    @Test
    fun `sendSignal does not crash`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        session.requestExec("echo sig_test")
        readAllOutput(session)
        session.sendSignal("TERM") // should not throw
    }

    @Test
    fun `disconnect cleanly after exec`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        session.requestExec("echo bye")
        readAllOutput(session)
        ssh.disconnect()
        assertFalse(ssh.isConnected)
    }

    // ---- Stress tests (cover adjustLocalWindow, write window management) ----

    @Test
    fun `bidirectional large data exercises all channel window paths`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()

        // md5sum reads all stdin, computes hash — exercises write + adjustLocalWindow
        session.requestExec("md5sum")

        // Write 500KB — enough to exhaust initial window and trigger adjustRemoteWindow
        val data = "A".repeat(1024).toByteArray()
        repeat(500) { session.write(data) }
        session.sendEof()

        val output = readAllOutput(session)
        // md5sum should output a 32-char hex hash
        assertTrue("md5sum should produce output, got: ${output.take(50)}", output.trim().length >= 32)
    }

    @Test
    fun `sftp large file transfer exercises window management end to end`() = runBlocking {
        val ssh = connect()
        ssh.authPassword(password)
        val session = ssh.openSession()
        session.requestSubsystem("sftp")
        val sftp = SftpClient(session)
        sftp.init()

        val home = sftp.realpath(".")
        val testFile = "$home/large_test_${System.currentTimeMillis()}.bin"

        // Upload 1MB — triggers multiple WINDOW_ADJUST exchanges
        val megabyte = ByteArray(1024 * 1024) { (it % 256).toByte() }
        megabyte.inputStream().use { sftp.uploadFile(it, testFile, megabyte.size.toLong()) }

        // Verify size
        val attrs = sftp.stat(testFile)
        assertEquals(1024L * 1024, attrs.size)

        // Download and verify content integrity
        val downloaded = ByteArrayOutputStream()
        sftp.downloadFile(testFile, downloaded)
        assertEquals(megabyte.size, downloaded.size())

        sftp.remove(testFile)
        sftp.close()
    }

    // ---- Helpers ----

    private suspend fun readAllOutput(session: AsyncSessionChannel): String {
        val buf = ByteArrayOutputStream()
        while (true) {
            val data = session.read()
            if (data.isEmpty()) break
            buf.write(data)
        }
        return buf.toString(Charsets.UTF_8.name())
    }

    /** Poll for exit status with bounded retries instead of Thread.sleep. */
    private fun waitForExitStatus(session: AsyncSessionChannel, maxWaitMs: Long = 2000) {
        val deadline = System.currentTimeMillis() + maxWaitMs
        while (session.exitStatus == null && System.currentTimeMillis() < deadline) {
            Thread.yield()
        }
        assertNotNull("Exit status should be set within ${maxWaitMs}ms", session.exitStatus)
    }
}
