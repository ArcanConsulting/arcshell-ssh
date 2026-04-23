package de.arcan.arcshell.ssh.transport

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Hybrid Post-Quantum Key Exchange: X25519 + ML-KEM-768 (Kyber).
 *
 * Uses the same SSH KEX pattern as curve25519-sha256 but concatenates
 * X25519 and Kyber shared secrets before hashing. This provides
 * quantum resistance while maintaining classical security.
 *
 * Algorithm name follows the IETF draft convention.
 * Client sends: [32-byte X25519 pubkey][1184-byte Kyber-768 pubkey]
 * Server replies: [32-byte X25519 pubkey][1088-byte Kyber-768 ciphertext]
 * Shared secret: SHA-512(X25519_shared || Kyber_shared)
 */
class MlKem768X25519Sha512 : KeyExchangeAlgorithm {

    override val name = "mlkem768x25519-sha512"
    override val hashAlgorithm = "SHA-512"

    // X25519 keys
    private var x25519Private: X25519PrivateKeyParameters? = null
    private var x25519Public: ByteArray = ByteArray(0)

    // Kyber keys
    private var kyberPrivateKey: org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters? = null
    private var kyberPublicKey: ByteArray = ByteArray(0)

    override fun generateClientKey(): ByteArray {
        // Generate X25519 key pair
        val x25519Gen = X25519KeyPairGenerator()
        x25519Gen.init(X25519KeyGenerationParameters(SecureRandom()))
        val x25519Pair = x25519Gen.generateKeyPair()
        x25519Private = x25519Pair.private as X25519PrivateKeyParameters
        x25519Public = (x25519Pair.public as X25519PublicKeyParameters).encoded

        // Generate Kyber-768 key pair
        val kyberGen = KyberKeyPairGenerator()
        kyberGen.init(KyberKeyGenerationParameters(SecureRandom(), KyberParameters.kyber768))
        val kyberPair = kyberGen.generateKeyPair()
        kyberPrivateKey = kyberPair.private as org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters
        kyberPublicKey = (kyberPair.public as org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters).encoded

        // Concatenate: [X25519 pubkey (32)][Kyber pubkey (1184)]
        return x25519Public + kyberPublicKey
    }

    override fun computeSharedSecret(serverPublicKey: ByteArray): BigInteger {
        // Server response: [X25519 pubkey (32)][Kyber ciphertext (1088)]
        require(serverPublicKey.size > 32) { "Server key too short" }

        val serverX25519 = serverPublicKey.copyOfRange(0, 32)
        val kyberCiphertext = serverPublicKey.copyOfRange(32, serverPublicKey.size)

        // X25519 shared secret
        val agreement = X25519Agreement()
        agreement.init(x25519Private)
        val x25519Shared = ByteArray(32)
        agreement.calculateAgreement(X25519PublicKeyParameters(serverX25519, 0), x25519Shared, 0)

        // Kyber decapsulation
        val extractor = KyberKEMExtractor(kyberPrivateKey)
        val kyberShared = extractor.extractSecret(kyberCiphertext)

        // Combined: SHA-512(X25519_shared || Kyber_shared)
        val digest = MessageDigest.getInstance("SHA-512")
        digest.update(x25519Shared)
        digest.update(kyberShared)
        val combined = digest.digest()

        return BigInteger(1, combined)
    }
}
