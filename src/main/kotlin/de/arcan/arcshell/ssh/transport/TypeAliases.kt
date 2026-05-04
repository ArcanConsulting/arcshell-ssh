package de.arcan.arcshell.ssh.transport

typealias HostKeyVerifier = (hostKeyType: String, hostKeyBlob: ByteArray) -> Boolean

typealias LegacyAlgorithmApprover = (legacyAlgorithms: List<String>) -> Boolean
