package de.arcan.arcshell.ssh.transport

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters
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
