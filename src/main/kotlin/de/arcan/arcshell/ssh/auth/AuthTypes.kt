package de.arcan.arcshell.ssh.auth

sealed class AuthResult {
    data object Success : AuthResult()
    data class Failure(val methodsCanContinue: List<String>, val partialSuccess: Boolean) : AuthResult()
    data class InfoRequest(val name: String, val instruction: String, val prompts: List<Prompt>) : AuthResult()
    data class Banner(val message: String) : AuthResult()
}

data class Prompt(val text: String, val echo: Boolean)
