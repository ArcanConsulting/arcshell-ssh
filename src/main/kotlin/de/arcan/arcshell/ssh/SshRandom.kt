package de.arcan.arcshell.ssh

import java.security.SecureRandom

object SshRandom {
    val instance: SecureRandom by lazy {
        SecureRandom().also {
            val seed = ByteArray(32)
            it.nextBytes(seed)
        }
    }
}
