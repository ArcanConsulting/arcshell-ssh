package de.arcan.arcshell.ssh

data class SshConfig(
    val hostname: String,
    val port: Int = 22,
    val username: String,
    val connectTimeoutMs: Int = 10_000,
    val keepAliveIntervalMs: Int = 0
)
