package de.arcan.arcshell.ssh.transport

import javax.crypto.Cipher
import javax.crypto.Mac

data class CryptoState(
    val cipher: Cipher,
    val mac: Mac?,
    val macLength: Int,
    val isAead: Boolean = false,
    val etm: Boolean = false,
    val aesKey: javax.crypto.spec.SecretKeySpec? = null,
    val baseIv: ByteArray? = null,
    val isChaCha: Boolean = false,
    val chaChaK1: ByteArray? = null,
    val chaChaK2: ByteArray? = null
) {
    fun buildNonce(sequenceNumber: Long): ByteArray {
        val iv = baseIv?.copyOf() ?: throw IllegalStateException("No base IV for AEAD")
        var carry = sequenceNumber
        for (i in 0 until 8) {
            val pos = iv.size - 1 - i
            val sum = (iv[pos].toLong() and 0xFF) + (carry and 0xFF)
            iv[pos] = sum.toByte()
            carry = (carry ushr 8) + (sum ushr 8)
        }
        return iv
    }

    override fun equals(other: Any?): Boolean = this === other
    override fun hashCode(): Int = System.identityHashCode(this)
}

class SshProtocolException(message: String, cause: Throwable? = null) :
    Exception(message, cause)
