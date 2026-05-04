package de.arcan.arcshell.ssh.transport

import de.arcan.arcshell.crypto.bc.crypto.agreement.X25519Agreement
import de.arcan.arcshell.crypto.bc.crypto.generators.X25519KeyPairGenerator
import de.arcan.arcshell.crypto.bc.crypto.params.X25519KeyGenerationParameters
import de.arcan.arcshell.crypto.bc.crypto.params.X25519PrivateKeyParameters
import de.arcan.arcshell.crypto.bc.crypto.params.X25519PublicKeyParameters
import de.arcan.arcshell.crypto.bc.pqc.crypto.mlkem.MLKEMExtractor
import de.arcan.arcshell.crypto.bc.pqc.crypto.mlkem.MLKEMGenerator
import de.arcan.arcshell.crypto.bc.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import de.arcan.arcshell.crypto.bc.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import de.arcan.arcshell.crypto.bc.pqc.crypto.mlkem.MLKEMParameters
import de.arcan.arcshell.crypto.bc.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import de.arcan.arcshell.crypto.bc.pqc.crypto.mlkem.MLKEMPublicKeyParameters
import de.arcan.arcshell.crypto.bc.pqc.crypto.ntruprime.SNTRUPrimeKeyGenerationParameters
import de.arcan.arcshell.crypto.bc.pqc.crypto.ntruprime.SNTRUPrimeKeyPairGenerator
import de.arcan.arcshell.crypto.bc.pqc.crypto.ntruprime.SNTRUPrimeKEMExtractor
import de.arcan.arcshell.crypto.bc.pqc.crypto.ntruprime.SNTRUPrimeParameters
import de.arcan.arcshell.crypto.bc.pqc.crypto.ntruprime.SNTRUPrimePrivateKeyParameters
import de.arcan.arcshell.crypto.bc.pqc.crypto.ntruprime.SNTRUPrimePublicKeyParameters
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Hybrid Post-Quantum Key Exchange: X25519 + ML-KEM-768.
 *
 * Client sends: [32-byte X25519 pubkey][1184-byte ML-KEM-768 pubkey]
 * Server replies: [32-byte X25519 pubkey][1088-byte ML-KEM-768 ciphertext]
 * Shared secret: SHA-512(X25519_shared || ML-KEM_shared)
 */
class MlKem768X25519Sha512 : KeyExchangeAlgorithm {

    override val name = "mlkem768x25519-sha512"
    override val hashAlgorithm = "SHA-512"

    private var x25519Private: X25519PrivateKeyParameters? = null
    private var x25519Public: ByteArray = ByteArray(0)
    private var mlkemPrivateKey: MLKEMPrivateKeyParameters? = null
    private var mlkemPublicKey: ByteArray = ByteArray(0)

    override fun generateClientKey(): ByteArray {
        val x25519Gen = X25519KeyPairGenerator()
        x25519Gen.init(X25519KeyGenerationParameters(de.arcan.arcshell.ssh.SshRandom.instance))
        val x25519Pair = x25519Gen.generateKeyPair()
        x25519Private = x25519Pair.private as X25519PrivateKeyParameters
        x25519Public = (x25519Pair.public as X25519PublicKeyParameters).encoded

        val mlkemGen = MLKEMKeyPairGenerator()
        mlkemGen.init(MLKEMKeyGenerationParameters(de.arcan.arcshell.ssh.SshRandom.instance, MLKEMParameters.ml_kem_768))
        val mlkemPair = mlkemGen.generateKeyPair()
        mlkemPrivateKey = mlkemPair.private as MLKEMPrivateKeyParameters
        mlkemPublicKey = (mlkemPair.public as MLKEMPublicKeyParameters).encoded

        return x25519Public + mlkemPublicKey
    }

    override fun computeSharedSecret(serverPublicKey: ByteArray): BigInteger {
        require(serverPublicKey.size > 32) { "Server key too short" }

        val serverX25519 = serverPublicKey.copyOfRange(0, 32)
        val mlkemCiphertext = serverPublicKey.copyOfRange(32, serverPublicKey.size)

        val agreement = X25519Agreement()
        agreement.init(x25519Private)
        val x25519Shared = ByteArray(32)
        agreement.calculateAgreement(X25519PublicKeyParameters(serverX25519, 0), x25519Shared, 0)

        val extractor = MLKEMExtractor(mlkemPrivateKey)
        val mlkemShared = extractor.extractSecret(mlkemCiphertext)

        val digest = MessageDigest.getInstance("SHA-512")
        digest.update(x25519Shared)
        digest.update(mlkemShared)
        return BigInteger(1, digest.digest())
    }
}

/**
 * Hybrid Post-Quantum Key Exchange: sntrup761 + X25519 (OpenSSH wire order).
 *
 * Client sends: [1158-byte sntrup761 pubkey][32-byte X25519 pubkey]
 * Server replies: [1039-byte sntrup761 ciphertext][32-byte X25519 pubkey]
 * Shared secret K: sntrup761_shared(32) || X25519_shared(32) as BigInteger
 */
open class Sntrup761X25519Sha512 : KeyExchangeAlgorithm {

    override val name = "sntrup761x25519-sha512@openssh.com"
    override val hashAlgorithm = "SHA-512"

    private var x25519Private: X25519PrivateKeyParameters? = null
    private var x25519Public: ByteArray = ByteArray(0)
    private var sntrupPrivateKey: SNTRUPrimePrivateKeyParameters? = null
    private var sntrupPublicKey: ByteArray = ByteArray(0)
    private var rawSharedSecret: ByteArray = ByteArray(0)

    override fun generateClientKey(): ByteArray {
        val sntrupGen = SNTRUPrimeKeyPairGenerator()
        sntrupGen.init(SNTRUPrimeKeyGenerationParameters(de.arcan.arcshell.ssh.SshRandom.instance, SNTRUPrimeParameters.sntrup761))
        val sntrupPair = sntrupGen.generateKeyPair()
        sntrupPrivateKey = sntrupPair.private as SNTRUPrimePrivateKeyParameters
        sntrupPublicKey = (sntrupPair.public as SNTRUPrimePublicKeyParameters).encoded

        val x25519Gen = X25519KeyPairGenerator()
        x25519Gen.init(X25519KeyGenerationParameters(de.arcan.arcshell.ssh.SshRandom.instance))
        val x25519Pair = x25519Gen.generateKeyPair()
        x25519Private = x25519Pair.private as X25519PrivateKeyParameters
        x25519Public = (x25519Pair.public as X25519PublicKeyParameters).encoded

        return sntrupPublicKey + x25519Public
    }

    override fun computeSharedSecret(serverPublicKey: ByteArray): BigInteger {
        val sntrupCtLen = serverPublicKey.size - 32
        require(sntrupCtLen > 0) { "Server key too short" }

        val sntrupCiphertext = serverPublicKey.copyOfRange(0, sntrupCtLen)
        val serverX25519 = serverPublicKey.copyOfRange(sntrupCtLen, serverPublicKey.size)

        val extractor = SNTRUPrimeKEMExtractor(sntrupPrivateKey)
        val sntrupShared = extractor.extractSecret(sntrupCiphertext)

        val agreement = X25519Agreement()
        agreement.init(x25519Private)
        val x25519Shared = ByteArray(32)
        agreement.calculateAgreement(X25519PublicKeyParameters(serverX25519, 0), x25519Shared, 0)

        val concatenated = sntrupShared + x25519Shared
        val hashed = MessageDigest.getInstance("SHA-512").digest(concatenated)
        rawSharedSecret = hashed
        return BigInteger(1, hashed)
    }

    override fun encodedSharedSecret(k: BigInteger): ByteArray =
        SshBufferWriter(72).writeString(rawSharedSecret).toByteArray()

    override fun computeExchangeHash(
        clientVersion: String, serverVersion: String,
        clientKexInit: ByteArray, serverKexInit: ByteArray,
        hostKeyBlob: ByteArray, clientPublicKey: ByteArray,
        serverPublicKey: ByteArray, sharedSecret: BigInteger
    ): ByteArray {
        val buf = SshBufferWriter(4096)
            .writeUtf8(clientVersion)
            .writeUtf8(serverVersion)
            .writeString(clientKexInit)
            .writeString(serverKexInit)
            .writeString(hostKeyBlob)
            .writeString(clientPublicKey)
            .writeString(serverPublicKey)
            .writeString(rawSharedSecret)
        return MessageDigest.getInstance(hashAlgorithm).digest(buf.toByteArray())
    }
}

class Sntrup761X25519Sha512Standard : Sntrup761X25519Sha512() {
    override val name = "sntrup761x25519-sha512"
}
