package de.arcan.arcshell.ssh.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for the [AuthResult] sealed class hierarchy and [Prompt] data class.
 * These are pure data class tests -- no mocking needed.
 */
class SshAuthResultTest {

    // =========================================================================
    // AuthResult.Success
    // =========================================================================

    @Test
    fun `Success is a singleton`() {
        val a = AuthResult.Success
        val b = AuthResult.Success
        assertTrue(a === b)
    }

    @Test
    fun `Success is an AuthResult`() {
        val result: AuthResult = AuthResult.Success
        assertTrue(result is AuthResult.Success)
    }

    @Test
    fun `Success toString contains Success`() {
        assertTrue(AuthResult.Success.toString().contains("Success"))
    }

    // =========================================================================
    // AuthResult.Failure
    // =========================================================================

    @Test
    fun `Failure stores methodsCanContinue`() {
        val failure = AuthResult.Failure(
            methodsCanContinue = listOf("publickey", "keyboard-interactive"),
            partialSuccess = false
        )
        assertEquals(2, failure.methodsCanContinue.size)
        assertEquals("publickey", failure.methodsCanContinue[0])
        assertEquals("keyboard-interactive", failure.methodsCanContinue[1])
    }

    @Test
    fun `Failure stores partialSuccess false`() {
        val failure = AuthResult.Failure(listOf("password"), partialSuccess = false)
        assertFalse(failure.partialSuccess)
    }

    @Test
    fun `Failure stores partialSuccess true`() {
        val failure = AuthResult.Failure(listOf("publickey"), partialSuccess = true)
        assertTrue(failure.partialSuccess)
    }

    @Test
    fun `Failure with empty methods list`() {
        val failure = AuthResult.Failure(emptyList(), partialSuccess = false)
        assertTrue(failure.methodsCanContinue.isEmpty())
    }

    @Test
    fun `Failure equality`() {
        val a = AuthResult.Failure(listOf("password"), false)
        val b = AuthResult.Failure(listOf("password"), false)
        assertEquals(a, b)
    }

    @Test
    fun `Failure inequality on methods`() {
        val a = AuthResult.Failure(listOf("password"), false)
        val b = AuthResult.Failure(listOf("publickey"), false)
        assertNotEquals(a, b)
    }

    @Test
    fun `Failure inequality on partialSuccess`() {
        val a = AuthResult.Failure(listOf("password"), false)
        val b = AuthResult.Failure(listOf("password"), true)
        assertNotEquals(a, b)
    }

    @Test
    fun `Failure copy changes partialSuccess`() {
        val original = AuthResult.Failure(listOf("password", "publickey"), false)
        val copy = original.copy(partialSuccess = true)
        assertTrue(copy.partialSuccess)
        assertEquals(original.methodsCanContinue, copy.methodsCanContinue)
    }

    @Test
    fun `Failure copy changes methods`() {
        val original = AuthResult.Failure(listOf("password"), false)
        val copy = original.copy(methodsCanContinue = listOf("publickey", "keyboard-interactive"))
        assertEquals(2, copy.methodsCanContinue.size)
        assertFalse(copy.partialSuccess)
    }

    @Test
    fun `Failure is an AuthResult`() {
        val result: AuthResult = AuthResult.Failure(listOf("password"), false)
        assertTrue(result is AuthResult.Failure)
    }

    @Test
    fun `Failure hashCode consistent with equals`() {
        val a = AuthResult.Failure(listOf("password"), false)
        val b = AuthResult.Failure(listOf("password"), false)
        assertEquals(a.hashCode(), b.hashCode())
    }

    // =========================================================================
    // AuthResult.Banner
    // =========================================================================

    @Test
    fun `Banner stores message`() {
        val banner = AuthResult.Banner("Welcome to the server!")
        assertEquals("Welcome to the server!", banner.message)
    }

    @Test
    fun `Banner with empty message`() {
        val banner = AuthResult.Banner("")
        assertEquals("", banner.message)
    }

    @Test
    fun `Banner with multiline message`() {
        val msg = "Line 1\nLine 2\nLine 3"
        val banner = AuthResult.Banner(msg)
        assertEquals(msg, banner.message)
        assertTrue(banner.message.contains("\n"))
    }

    @Test
    fun `Banner equality`() {
        val a = AuthResult.Banner("hello")
        val b = AuthResult.Banner("hello")
        assertEquals(a, b)
    }

    @Test
    fun `Banner inequality`() {
        val a = AuthResult.Banner("hello")
        val b = AuthResult.Banner("world")
        assertNotEquals(a, b)
    }

    @Test
    fun `Banner copy`() {
        val original = AuthResult.Banner("original message")
        val copy = original.copy(message = "new message")
        assertEquals("new message", copy.message)
    }

    @Test
    fun `Banner is an AuthResult`() {
        val result: AuthResult = AuthResult.Banner("test")
        assertTrue(result is AuthResult.Banner)
    }

    @Test
    fun `Banner hashCode consistent with equals`() {
        val a = AuthResult.Banner("same")
        val b = AuthResult.Banner("same")
        assertEquals(a.hashCode(), b.hashCode())
    }

    // =========================================================================
    // AuthResult.InfoRequest
    // =========================================================================

    @Test
    fun `InfoRequest stores all fields`() {
        val prompts = listOf(Prompt("Password: ", false), Prompt("Token: ", true))
        val info = AuthResult.InfoRequest(
            name = "Authentication",
            instruction = "Please enter your credentials",
            prompts = prompts
        )
        assertEquals("Authentication", info.name)
        assertEquals("Please enter your credentials", info.instruction)
        assertEquals(2, info.prompts.size)
    }

    @Test
    fun `InfoRequest with empty prompts`() {
        val info = AuthResult.InfoRequest("", "", emptyList())
        assertEquals("", info.name)
        assertEquals("", info.instruction)
        assertTrue(info.prompts.isEmpty())
    }

    @Test
    fun `InfoRequest equality`() {
        val prompts = listOf(Prompt("Pass: ", false))
        val a = AuthResult.InfoRequest("name", "instr", prompts)
        val b = AuthResult.InfoRequest("name", "instr", prompts)
        assertEquals(a, b)
    }

    @Test
    fun `InfoRequest inequality on name`() {
        val prompts = listOf(Prompt("Pass: ", false))
        val a = AuthResult.InfoRequest("name1", "instr", prompts)
        val b = AuthResult.InfoRequest("name2", "instr", prompts)
        assertNotEquals(a, b)
    }

    @Test
    fun `InfoRequest copy changes instruction`() {
        val original = AuthResult.InfoRequest("n", "old instruction", listOf(Prompt("x", true)))
        val copy = original.copy(instruction = "new instruction")
        assertEquals("new instruction", copy.instruction)
        assertEquals(original.name, copy.name)
        assertEquals(original.prompts, copy.prompts)
    }

    @Test
    fun `InfoRequest is an AuthResult`() {
        val result: AuthResult = AuthResult.InfoRequest("n", "i", emptyList())
        assertTrue(result is AuthResult.InfoRequest)
    }

    // =========================================================================
    // AuthResult sealed class exhaustive when
    // =========================================================================

    @Test
    fun `when expression covers all AuthResult subtypes`() {
        val results: List<AuthResult> = listOf(
            AuthResult.Success,
            AuthResult.Failure(listOf("password"), false),
            AuthResult.Banner("msg"),
            AuthResult.InfoRequest("n", "i", emptyList())
        )

        val labels = results.map { result ->
            when (result) {
                is AuthResult.Success -> "success"
                is AuthResult.Failure -> "failure"
                is AuthResult.Banner -> "banner"
                is AuthResult.InfoRequest -> "info"
            }
        }

        assertEquals(listOf("success", "failure", "banner", "info"), labels)
    }

    // =========================================================================
    // Prompt data class
    // =========================================================================

    @Test
    fun `Prompt stores text and echo`() {
        val prompt = Prompt(text = "Password: ", echo = false)
        assertEquals("Password: ", prompt.text)
        assertFalse(prompt.echo)
    }

    @Test
    fun `Prompt with echo true`() {
        val prompt = Prompt(text = "Username: ", echo = true)
        assertEquals("Username: ", prompt.text)
        assertTrue(prompt.echo)
    }

    @Test
    fun `Prompt with empty text`() {
        val prompt = Prompt(text = "", echo = false)
        assertEquals("", prompt.text)
    }

    @Test
    fun `Prompt equality`() {
        val a = Prompt("Password: ", false)
        val b = Prompt("Password: ", false)
        assertEquals(a, b)
    }

    @Test
    fun `Prompt inequality on text`() {
        val a = Prompt("Password: ", false)
        val b = Prompt("Token: ", false)
        assertNotEquals(a, b)
    }

    @Test
    fun `Prompt inequality on echo`() {
        val a = Prompt("Password: ", false)
        val b = Prompt("Password: ", true)
        assertNotEquals(a, b)
    }

    @Test
    fun `Prompt copy`() {
        val original = Prompt("old", false)
        val copy = original.copy(text = "new", echo = true)
        assertEquals("new", copy.text)
        assertTrue(copy.echo)
    }

    @Test
    fun `Prompt hashCode consistent with equals`() {
        val a = Prompt("same", true)
        val b = Prompt("same", true)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun `Prompt toString contains fields`() {
        val prompt = Prompt("Enter code: ", true)
        val str = prompt.toString()
        assertTrue(str.contains("Enter code: "))
        assertTrue(str.contains("true"))
    }

    @Test
    fun `Prompt destructuring`() {
        val prompt = Prompt("Password: ", false)
        val (text, echo) = prompt
        assertEquals("Password: ", text)
        assertFalse(echo)
    }
}
