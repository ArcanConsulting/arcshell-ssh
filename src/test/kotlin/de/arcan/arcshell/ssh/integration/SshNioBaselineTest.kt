package de.arcan.arcshell.integration

import de.arcan.arcshell.ssh.SshConfig
import de.arcan.arcshell.ssh.auth.AuthResult
import de.arcan.arcshell.ssh.nio.AsyncSessionChannel
import de.arcan.arcshell.ssh.nio.AsyncSshClient
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.net.Socket
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * NIO Phase 0 — Baseline tests for behaviors that the NIO migration will change.
 *
 * Every test in this class exercises a code path that transitions from blocking
 * java.net.Socket I/O to non-blocking Java NIO (SocketChannel + Selector) in
 * Phases 1-8. If any test regresses after an NIO phase, the migration broke
 * observable behavior.
 *
 * Requires Docker SSH containers: docker compose -f test-ssh/compose.yml up -d
 */
class SshNioBaselineTest {

    private val host = "127.0.0.1"
    private val port = 2222
    private val username = "testuser"
    private val password = "testpass123"
    private val clients = ConcurrentLinkedQueue<AsyncSshClient>()

    @Before
    fun checkServer() {
        val available = try {
            Socket(host, port).use { true }
        } catch (_: Exception) { false }
        assertTrue(
            "SSH test server REQUIRED on $host:$port. " +
            "Start with: docker compose -f test-ssh/compose.yml up -d",
            available
        )
    }

    @After
    fun cleanup() {
        for (c in clients) {
            try { c.disconnect() } catch (_: Exception) {}
        }
        clients.clear()
    }

    private suspend fun connectAndAuth(): AsyncSshClient {
        val config = SshConfig(host, port, username, connectTimeoutMs = 5000)
        val ssh = AsyncSshClient(config, hostKeyVerifier = { _, _ -> true })
        ssh.connect()
        val result = ssh.authPassword(password)
        assertTrue("Auth must succeed", result is AuthResult.Success)
        clients.add(ssh)
        return ssh
    }

    // ---- 1. Concurrent multi-channel: multiple exec sessions active simultaneously ----

    @Test(timeout = 30_000)
    fun `five concurrent exec sessions on one connection`() = runBlocking {
        val ssh = connectAndAuth()

        val channelCount = 5
        val results = ConcurrentLinkedQueue<Pair<Int, String>>()
        val errors = ConcurrentLinkedQueue<Throwable>()

        val jobs = (0 until channelCount).map { idx ->
            async {
                try {
                    val session = ssh.openSession()
                    session.requestExec("echo channel_$idx && sleep 0.1")
                    val output = drainOutput(session)
                    results.add(idx to output)
                } catch (e: Throwable) {
                    errors.add(e)
                }
            }
        }
        jobs.awaitAll()

        assertTrue("No errors: ${errors.firstOrNull()}", errors.isEmpty())
        assertEquals(channelCount, results.size)

        for ((idx, output) in results) {
            assertTrue(
                "Channel $idx must contain its marker, got: ${output.take(40)}",
                output.contains("channel_$idx")
            )
        }
    }

    @Test(timeout = 30_000)
    fun `concurrent exec sessions produce isolated output`() = runBlocking {
        val ssh = connectAndAuth()

        val channelCount = 3
        val outputs = ConcurrentLinkedQueue<Pair<Int, String>>()

        val jobs = (0 until channelCount).map { idx ->
            async {
                try {
                    val session = ssh.openSession()
                    val marker = "UNIQUE_${idx}_${System.nanoTime()}"
                    session.requestExec("echo $marker")
                    val output = drainOutput(session)
                    outputs.add(idx to output)
                } catch (_: Exception) {
                }
            }
        }
        jobs.awaitAll()

        assertEquals(channelCount, outputs.size)

        for ((_, output) in outputs) {
            assertTrue("Each output must contain exactly one UNIQUE_ marker",
                output.lines().count { it.contains("UNIQUE_") } == 1)
        }
    }

    // ---- 2. Interactive shell I/O: write->read->write->read like a terminal ----

    @Test(timeout = 15_000)
    fun `interactive shell write-read-write-read pattern`() = runBlocking {
        val ssh = connectAndAuth()

        val session = ssh.openSession()
        assertTrue(session.requestPty("xterm", 80, 24))
        assertTrue(session.requestShell())

        session.write("echo MARKER_ONE\n".toByteArray())
        val out1 = readUntilMarker(session, "MARKER_ONE", 5000)
        assertTrue("First marker must appear, got: ${out1.take(80)}", out1.contains("MARKER_ONE"))

        session.write("echo MARKER_TWO\n".toByteArray())
        val out2 = readUntilMarker(session, "MARKER_TWO", 5000)
        assertTrue("Second marker must appear, got: ${out2.take(80)}", out2.contains("MARKER_TWO"))

        session.write("exit\n".toByteArray())
    }

    @Test(timeout = 15_000)
    fun `shell session handles rapid successive commands`() = runBlocking {
        val ssh = connectAndAuth()

        val session = ssh.openSession()
        assertTrue(session.requestPty("xterm", 80, 24))
        assertTrue(session.requestShell())

        val commandCount = 10
        for (i in 0 until commandCount) {
            session.write("echo RAPID_$i\n".toByteArray())
        }

        val allOutput = readUntilMarker(session, "RAPID_${commandCount - 1}", 8000)
        for (i in 0 until commandCount) {
            assertTrue("Must contain RAPID_$i", allOutput.contains("RAPID_$i"))
        }

        session.write("exit\n".toByteArray())
    }

    // ---- 3. Async channel I/O: read/write directly on the channel (used by jumphost) ----

    @Test(timeout = 15_000)
    fun `channel read captures exec output correctly`() = runBlocking {
        val ssh = connectAndAuth()

        val session = ssh.openSession()
        session.requestExec("echo AsyncChannel_Read_Test")

        val output = drainOutput(session)
        assertTrue("Must contain marker", output.contains("AsyncChannel_Read_Test"))
    }

    @Test(timeout = 15_000)
    fun `channel write sends stdin data correctly`() = runBlocking {
        val ssh = connectAndAuth()

        val session = ssh.openSession()
        session.requestExec("cat")

        val message = "AsyncChannel_Write_Test\n"
        session.write(message.toByteArray())
        session.sendEof()

        val output = drainOutput(session)
        assertTrue("Must echo back via cat", output.contains("AsyncChannel_Write_Test"))
    }

    @Test(timeout = 15_000)
    fun `channel handles large bidirectional transfer`() = runBlocking {
        val ssh = connectAndAuth()

        val session = ssh.openSession()
        session.requestExec("md5sum")

        val chunk = "B".repeat(1024).toByteArray()
        repeat(200) { session.write(chunk) }
        session.sendEof()

        val output = drainOutput(session).trim()
        assertTrue("md5sum must produce a hash, got: ${output.take(50)}", output.length >= 32)
    }

    @Test(timeout = 15_000)
    fun `channel read returns data byte by byte`() = runBlocking {
        val ssh = connectAndAuth()

        val session = ssh.openSession()
        session.requestExec("echo AB")

        val data = session.read()
        assertTrue("First read must contain 'A' (65)", data.isNotEmpty() && data[0] == 65.toByte())
    }

    // ---- 4. Disconnect under load: graceful teardown with active channels ----

    @Test(timeout = 15_000)
    fun `disconnect during active shell does not hang`() = runBlocking {
        val ssh = connectAndAuth()

        val session = ssh.openSession()
        session.requestPty("xterm", 80, 24)
        session.requestShell()

        session.write("yes | head -1000\n".toByteArray())
        kotlinx.coroutines.delay(100)

        ssh.disconnect()
        assertFalse(ssh.isConnected)
    }

    @Test(timeout = 15_000)
    fun `disconnect during large exec output does not hang`() = runBlocking {
        val ssh = connectAndAuth()

        val session = ssh.openSession()
        session.requestExec("dd if=/dev/urandom bs=1024 count=500 2>/dev/null | base64")

        kotlinx.coroutines.delay(200)

        ssh.disconnect()
        assertFalse(ssh.isConnected)
    }

    @Test(timeout = 15_000)
    fun `disconnect with multiple open channels cleans up`() = runBlocking {
        val ssh = connectAndAuth()

        val sessions = (0 until 3).map { ssh.openSession() }
        sessions.forEachIndexed { idx, s -> s.requestExec("sleep 5 && echo done_$idx") }

        kotlinx.coroutines.delay(200)

        ssh.disconnect()
        assertFalse(ssh.isConnected)
    }

    // ---- 5. Rapid channel lifecycle: open/use/close quickly ----

    @Test(timeout = 30_000)
    fun `sequential rapid channel open-exec-close cycles`() = runBlocking {
        val ssh = connectAndAuth()

        val cycleCount = 10
        for (i in 0 until cycleCount) {
            val session = ssh.openSession()
            session.requestExec("echo cycle_$i")
            val output = drainOutput(session)
            assertTrue("Cycle $i must produce output", output.contains("cycle_$i"))
            session.close()
        }
    }

    @Test(timeout = 30_000)
    fun `channel reuse after close on same connection`() = runBlocking {
        val ssh = connectAndAuth()

        val s1 = ssh.openSession()
        s1.requestExec("echo first_session")
        val out1 = drainOutput(s1)
        assertTrue(out1.contains("first_session"))
        s1.close()

        val s2 = ssh.openSession()
        s2.requestExec("echo second_session")
        val out2 = drainOutput(s2)
        assertTrue(out2.contains("second_session"))
        s2.close()

        val s3 = ssh.openSession()
        s3.requestExec("echo third_session")
        val out3 = drainOutput(s3)
        assertTrue(out3.contains("third_session"))
        s3.close()
    }

    // ---- 6. Throughput baseline: measurable transfer for NIO comparison ----

    @Test(timeout = 30_000)
    fun `download throughput baseline 1MB`() = runBlocking {
        val ssh = connectAndAuth()

        val session = ssh.openSession()
        session.requestExec("dd if=/dev/zero bs=1024 count=1024 2>/dev/null")

        val start = System.nanoTime()
        var totalBytes = 0L
        while (true) {
            val data = session.read()
            if (data.isEmpty()) break
            totalBytes += data.size
        }
        val elapsed = (System.nanoTime() - start) / 1_000_000.0

        assertTrue("Must transfer at least 900KB, got ${totalBytes / 1024}KB", totalBytes > 900_000)
        val throughputMBps = (totalBytes / 1_000_000.0) / (elapsed / 1000.0)
        println("[NIO Baseline] Download: ${totalBytes / 1024}KB in ${elapsed.toLong()}ms = ${"%.1f".format(throughputMBps)} MB/s")
    }

    @Test(timeout = 30_000)
    fun `upload throughput baseline 1MB`() = runBlocking {
        val ssh = connectAndAuth()

        val session = ssh.openSession()
        session.requestExec("wc -c")

        val chunk = ByteArray(32768)
        val totalTarget = 1024 * 1024
        var written = 0

        val start = System.nanoTime()
        while (written < totalTarget) {
            val toWrite = minOf(chunk.size, totalTarget - written)
            session.write(chunk.copyOf(toWrite))
            written += toWrite
        }
        session.sendEof()
        val output = drainOutput(session)
        val elapsed = (System.nanoTime() - start) / 1_000_000.0

        val reported = output.trim().toLongOrNull() ?: 0
        assertTrue("Server must report ~1MB received, got $reported", reported > 900_000)
        val throughputMBps = (written / 1_000_000.0) / (elapsed / 1000.0)
        println("[NIO Baseline] Upload: ${written / 1024}KB in ${elapsed.toLong()}ms = ${"%.1f".format(throughputMBps)} MB/s")
    }

    // ---- 7. Message loop: auto-started by openSession, idempotent ----

    @Test(timeout = 10_000)
    fun `openSession auto-starts message loop`() = runBlocking {
        val ssh = connectAndAuth()

        val session = ssh.openSession()
        session.requestExec("echo auto_loop_ok")
        val output = drainOutput(session)
        assertTrue(output.contains("auto_loop_ok"))
    }

    @Test(timeout = 10_000)
    fun `multiple openSession calls are safe`() = runBlocking {
        val ssh = connectAndAuth()

        val s1 = ssh.openSession()
        s1.requestExec("echo first_ok")
        val out1 = drainOutput(s1)
        assertTrue(out1.contains("first_ok"))

        val s2 = ssh.openSession()
        s2.requestExec("echo second_ok")
        val out2 = drainOutput(s2)
        assertTrue(out2.contains("second_ok"))
    }

    // ---- 8. Keep-alive: verifies the keep-alive does not break data flow ----

    @Test(timeout = 15_000)
    fun `keep-alive does not interfere with exec`() = runBlocking {
        val config = SshConfig(host, port, username, connectTimeoutMs = 5000, keepAliveIntervalMs = 500)
        val ssh = AsyncSshClient(config, hostKeyVerifier = { _, _ -> true })
        ssh.connect()
        val result = ssh.authPassword(password)
        assertTrue(result is AuthResult.Success)
        clients.add(ssh)

        ssh.startKeepAlive(500)

        val session = ssh.openSession()
        session.requestExec("sleep 1 && echo keepalive_ok")
        val output = drainOutput(session)
        assertTrue("Command must complete with keepalive active", output.contains("keepalive_ok"))
    }

    // ---- 9. Multiple independent connections: NIO selector must handle N sockets ----

    @Test(timeout = 20_000)
    fun `three independent connections work simultaneously`() = runBlocking {
        val results = ConcurrentLinkedQueue<Pair<Int, String>>()
        val errors = ConcurrentLinkedQueue<Throwable>()

        val jobs = (0 until 3).map { idx ->
            async {
                try {
                    val ssh = connectAndAuth()
                    val session = ssh.openSession()
                    session.requestExec("echo conn_$idx")
                    val output = drainOutput(session)
                    results.add(idx to output)
                } catch (e: Throwable) {
                    errors.add(e)
                }
            }
        }
        jobs.awaitAll()

        assertTrue("No errors: ${errors.firstOrNull()}", errors.isEmpty())
        assertEquals(3, results.size)
        for ((idx, output) in results) {
            assertTrue("Connection $idx output must match", output.contains("conn_$idx"))
        }
    }

    // ---- Helpers ----

    private suspend fun drainOutput(session: AsyncSessionChannel): String {
        val buf = ByteArrayOutputStream()
        while (true) {
            val data = session.read()
            if (data.isEmpty()) break
            buf.write(data)
        }
        return buf.toString(Charsets.UTF_8.name())
    }

    private suspend fun readUntilMarker(session: AsyncSessionChannel, marker: String, timeoutMs: Long): String {
        val buf = StringBuilder()
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val data = session.read()
            if (data.isEmpty()) break
            buf.append(String(data))
            if (buf.contains(marker)) break
        }
        return buf.toString()
    }
}
