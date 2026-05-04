package de.arcan.arcshell.ssh.transport

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * SSH cipher/MAC algorithm definitions and key derivation (RFC 4253 §7.2).
 *
 * After key exchange, session keys are derived from the shared secret K and
 * the exchange hash H using the hash function from the KEX algorithm.
 */
data class CipherAlgorithm(
    val name: String,
    val jcaName: String,
    val keySize: Int,      // bytes
    val ivSize: Int,       // bytes (block size for CTR, nonce size for GCM)
    val blockSize: Int,    // bytes
    val isAead: Boolean    // true for GCM, ChaCha20-Poly1305 (no separate MAC needed)
)

data class MacAlgorithm(
    val name: String,
    val jcaName: String,
    val keySize: Int,      // bytes
    val macLength: Int,    // output bytes
    val etm: Boolean       // encrypt-then-mac
)

/** Supported encryption algorithms, ordered by preference. */
object CipherRegistry {
    val CHACHA20_POLY1305 = CipherAlgorithm("chacha20-poly1305@openssh.com", "ChaCha20", 64, 0, 8, true)
    val AES256_GCM = CipherAlgorithm("aes256-gcm@openssh.com", "AES/GCM/NoPadding", 32, 12, 16, true)
    val AES128_GCM = CipherAlgorithm("aes128-gcm@openssh.com", "AES/GCM/NoPadding", 16, 12, 16, true)
    val AES256_CTR = CipherAlgorithm("aes256-ctr", "AES/CTR/NoPadding", 32, 16, 16, false)
    val AES192_CTR = CipherAlgorithm("aes192-ctr", "AES/CTR/NoPadding", 24, 16, 16, false)
    val AES128_CTR = CipherAlgorithm("aes128-ctr", "AES/CTR/NoPadding", 16, 16, 16, false)
    val AES256_CBC = CipherAlgorithm("aes256-cbc", "AES/CBC/NoPadding", 32, 16, 16, false)
    val AES128_CBC = CipherAlgorithm("aes128-cbc", "AES/CBC/NoPadding", 16, 16, 16, false)

    fun getPreferred(): List<CipherAlgorithm> = listOf(
        CHACHA20_POLY1305, AES256_GCM, AES128_GCM, AES256_CTR, AES192_CTR, AES128_CTR,
        AES256_CBC, AES128_CBC
    )

    fun byName(name: String): CipherAlgorithm? = getPreferred().firstOrNull { it.name == name }

    fun nameList(): List<String> = getPreferred().map { it.name }

    fun isChaCha(name: String): Boolean = name == CHACHA20_POLY1305.name
    fun isCbc(name: String): Boolean = name.endsWith("-cbc")
}

/** Supported MAC algorithms (only needed for non-AEAD ciphers). */
object MacRegistry {
    val HMAC_SHA2_256_ETM = MacAlgorithm("hmac-sha2-256-etm@openssh.com", "HmacSHA256", 32, 32, true)
    val HMAC_SHA2_512_ETM = MacAlgorithm("hmac-sha2-512-etm@openssh.com", "HmacSHA512", 64, 64, true)
    val HMAC_SHA2_256 = MacAlgorithm("hmac-sha2-256", "HmacSHA256", 32, 32, false)
    val HMAC_SHA2_512 = MacAlgorithm("hmac-sha2-512", "HmacSHA512", 64, 64, false)
    val HMAC_SHA1 = MacAlgorithm("hmac-sha1", "HmacSHA1", 20, 20, false)

    val LEGACY_ALGORITHMS = setOf("hmac-sha1")

    fun getPreferred(): List<MacAlgorithm> = listOf(
        HMAC_SHA2_256_ETM, HMAC_SHA2_512_ETM, HMAC_SHA2_256, HMAC_SHA2_512,
        HMAC_SHA1 // Legacy fallback (last resort)
    )

    fun byName(name: String): MacAlgorithm? = getPreferred().firstOrNull { it.name == name }

    fun nameList(): List<String> = getPreferred().map { it.name }
}

/** Supported compression algorithms. */
object CompressionRegistry {
    fun nameList(): List<String> = listOf("none")
}

/** Supported host key types, ordered by preference. */
object HostKeyRegistry {
    fun nameList(): List<String> = listOf(
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "rsa-sha2-512",
        "rsa-sha2-256",
        "ssh-rsa"
    )
}

/**
 * Derives session keys from the shared secret K and exchange hash H
 * per RFC 4253 §7.2. Each key is derived as:
 *   HASH(K || H || X || session_id)
 * where X is a single character identifying the key purpose:
 *   'A' = IV client→server
 *   'B' = IV server→client
 *   'C' = encryption key client→server
 *   'D' = encryption key server→client
 *   'E' = MAC key client→server
 *   'F' = MAC key server→client
 */
object KeyDerivation {

    fun deriveKey(
        hashAlgorithm: String,
        sharedSecret: java.math.BigInteger,
        exchangeHash: ByteArray,
        keyId: Char,
        sessionId: ByteArray,
        neededLength: Int
    ): ByteArray {
        val digest = MessageDigest.getInstance(hashAlgorithm)

        // K is encoded as mpint
        val kBytes = SshBufferWriter(64).writeMpint(sharedSecret).toByteArray()

        // First round: HASH(K || H || X || session_id)
        digest.update(kBytes)
        digest.update(exchangeHash)
        digest.update(keyId.code.toByte())
        digest.update(sessionId)
        var key = digest.digest()

        // Extend key if needed: HASH(K || H || K1), HASH(K || H || K1 || K2), ...
        while (key.size < neededLength) {
            digest.reset()
            digest.update(kBytes)
            digest.update(exchangeHash)
            digest.update(key)
            key = key + digest.digest()
        }

        return key.copyOf(neededLength)
    }

    /** Create a JCA Cipher instance initialized for encryption or decryption. */
    fun createCipher(algo: CipherAlgorithm, key: ByteArray, iv: ByteArray, encrypt: Boolean): Cipher {
        val cipher = Cipher.getInstance(algo.jcaName)
        val keySpec = SecretKeySpec(key, "AES")
        val mode = if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE

        if (algo.isAead) {
            cipher.init(mode, keySpec, GCMParameterSpec(128, iv))
        } else {
            cipher.init(mode, keySpec, IvParameterSpec(iv))
        }
        return cipher
    }

    /** Create a JCA Mac instance initialized with the given key. */
    fun createMac(algo: MacAlgorithm, key: ByteArray): Mac {
        val mac = Mac.getInstance(algo.jcaName)
        mac.init(SecretKeySpec(key, algo.jcaName))
        return mac
    }
}
