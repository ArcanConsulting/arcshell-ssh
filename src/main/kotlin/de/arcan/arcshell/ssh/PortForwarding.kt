package de.arcan.arcshell.ssh

enum class ForwardType { LOCAL, REMOTE, DYNAMIC }

data class PortForwarding(
    val type: ForwardType,
    val localPort: Int,
    val remoteHost: String,
    val remotePort: Int,
    val enabled: Boolean = true
)
