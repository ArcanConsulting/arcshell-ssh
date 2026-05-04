package de.arcan.arcshell.ssh.transport

import de.arcan.arcshell.ssh.SshMsgType
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement

/**
 * Interface for SSH key exchange algorithms. Each implementation handles the
 * specific DH/ECDH math and produces a shared secret + exchange hash.
 */
interface KeyExchangeAlgorithm {
    /** Algorithm name as used in the SSH name-list. */
    val name: String

    /** Hash algorithm used for the exchange hash (SHA-256, SHA-512). */
    val hashAlgorithm: String

    /** Generate the client's ephemeral key pair and return the public key bytes to send. */
    fun generateClientKey(): ByteArray

    /**
     * Compute the shared secret from the server's public key.
     * @param serverPublicKey the server's ephemeral public key (raw bytes from KEX_REPLY)
     * @return the shared secret K as a BigInteger
     */
    fun computeSharedSecret(serverPublicKey: ByteArray): BigInteger

    /**
     * Compute the exchange hash H.
     * @param clientVersion client version string (without CR/LF)
     * @param serverVersion server version string
     * @param clientKexInit raw bytes of client's SSH_MSG_KEXINIT
     * @param serverKexInit raw bytes of server's SSH_MSG_KEXINIT
     * @param hostKeyBlob server's host key as SSH string blob
     * @param clientPublicKey our ephemeral public key
     * @param serverPublicKey server's ephemeral public key
     * @param sharedSecret K
     * @return the exchange hash H
     */
    fun computeExchangeHash(
        clientVersion: String,
        serverVersion: String,
        clientKexInit: ByteArray,
        serverKexInit: ByteArray,
        hostKeyBlob: ByteArray,
        clientPublicKey: ByteArray,
        serverPublicKey: ByteArray,
        sharedSecret: BigInteger
    ): ByteArray {
        val buf = SshBufferWriter(1024)
            .writeUtf8(clientVersion)
            .writeUtf8(serverVersion)
            .writeString(clientKexInit)
            .writeString(serverKexInit)
            .writeString(hostKeyBlob)
            .writeString(clientPublicKey)
            .writeString(serverPublicKey)
            .writeMpint(sharedSecret)
        val digest = MessageDigest.getInstance(hashAlgorithm)
        return digest.digest(buf.toByteArray())
    }
}

/**
 * Curve25519 key exchange (curve25519-sha256, RFC 8731).
 * Uses BouncyCastle's X25519 implementation.
 */
open class Curve25519Sha256 : KeyExchangeAlgorithm {
    override val name = "curve25519-sha256"
    override val hashAlgorithm = "SHA-256"

    private var privateKey: X25519PrivateKeyParameters? = null

    override fun generateClientKey(): ByteArray {
        val kpg = X25519KeyPairGenerator()
        kpg.init(X25519KeyGenerationParameters(de.arcan.arcshell.ssh.SshRandom.instance))
        val kp = kpg.generateKeyPair()
        privateKey = kp.private as X25519PrivateKeyParameters
        return (kp.public as X25519PublicKeyParameters).encoded
    }

    override fun computeSharedSecret(serverPublicKey: ByteArray): BigInteger {
        val priv = privateKey ?: throw IllegalStateException("generateClientKey not called")
        val serverPub = X25519PublicKeyParameters(serverPublicKey, 0)
        val agreement = X25519Agreement()
        agreement.init(priv)
        val secret = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(serverPub, secret, 0)
        // Convert to positive BigInteger (SSH mpint is always positive for shared secret)
        return BigInteger(1, secret)
    }
}

/**
 * Curve25519 key exchange with @libssh.org name (older convention).
 */
class Curve25519Sha256LibSsh : Curve25519Sha256() {
    override val name = "curve25519-sha256@libssh.org"
}

/**
 * ECDH key exchange using NIST P-256/P-384/P-521 (RFC 5656).
 */
class EcdhSha2(private val curveName: String, override val hashAlgorithm: String) : KeyExchangeAlgorithm {
    override val name = "ecdh-sha2-$curveName"

    private var privateKey: java.security.PrivateKey? = null
    private var publicKeyBytes: ByteArray? = null

    override fun generateClientKey(): ByteArray {
        val kpg = KeyPairGenerator.getInstance("EC")
        val jcaCurve = when (curveName) {
            "nistp256" -> "secp256r1"
            "nistp384" -> "secp384r1"
            "nistp521" -> "secp521r1"
            else -> throw IllegalArgumentException("Unknown curve: $curveName")
        }
        kpg.initialize(ECGenParameterSpec(jcaCurve))
        val kp = kpg.generateKeyPair()
        privateKey = kp.private
        val ecPub = kp.public as ECPublicKey
        publicKeyBytes = encodeEcPoint(ecPub.w, ecPub.params.curve.field.fieldSize)
        return publicKeyBytes!!
    }

    override fun computeSharedSecret(serverPublicKey: ByteArray): BigInteger {
        val priv = privateKey ?: throw IllegalStateException("generateClientKey not called")
        val jcaCurve = when (curveName) {
            "nistp256" -> "secp256r1"
            "nistp384" -> "secp384r1"
            "nistp521" -> "secp521r1"
            else -> throw IllegalArgumentException("Unknown curve: $curveName")
        }
        val ecParams = (KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec(jcaCurve))
        }.generateKeyPair().public as ECPublicKey).params

        val point = decodeEcPoint(serverPublicKey, ecParams.curve)
        val pubSpec = ECPublicKeySpec(point, ecParams)
        val serverPub = KeyFactory.getInstance("EC").generatePublic(pubSpec)

        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(priv)
        ka.doPhase(serverPub, true)
        return BigInteger(1, ka.generateSecret())
    }

    private fun encodeEcPoint(point: ECPoint, fieldSize: Int): ByteArray {
        val byteLen = (fieldSize + 7) / 8
        val x = point.affineX.toByteArray().let { stripLeadingZeros(it, byteLen) }
        val y = point.affineY.toByteArray().let { stripLeadingZeros(it, byteLen) }
        return byteArrayOf(0x04) + x + y // uncompressed point
    }

    private fun decodeEcPoint(encoded: ByteArray, curve: java.security.spec.EllipticCurve): ECPoint {
        if (encoded[0].toInt() != 0x04) throw SshProtocolException("Only uncompressed EC points supported")
        val coordLen = (encoded.size - 1) / 2
        val x = BigInteger(1, encoded.copyOfRange(1, 1 + coordLen))
        val y = BigInteger(1, encoded.copyOfRange(1 + coordLen, encoded.size))
        return ECPoint(x, y)
    }

    private fun stripLeadingZeros(bytes: ByteArray, targetLen: Int): ByteArray {
        if (bytes.size == targetLen) return bytes
        if (bytes.size > targetLen) return bytes.copyOfRange(bytes.size - targetLen, bytes.size)
        val padded = ByteArray(targetLen)
        System.arraycopy(bytes, 0, padded, targetLen - bytes.size, bytes.size)
        return padded
    }
}

/**
 * Generalized Diffie-Hellman group key exchange (RFC 4253 §8 + RFC 3526 + RFC 8268).
 * Supports Group 14 (2048-bit), Group 16 (4096-bit), and Group 18 (8192-bit).
 */
open class DhGroupKex(
    override val name: String,
    override val hashAlgorithm: String,
    private val prime: BigInteger,
    private val generator: BigInteger,
    private val bitSize: Int
) : KeyExchangeAlgorithm {

    private var privateKey: BigInteger? = null
    private var publicKeyValue: BigInteger? = null

    override fun generateClientKey(): ByteArray {
        val random = de.arcan.arcshell.ssh.SshRandom.instance
        val x = BigInteger(bitSize, random).mod(prime.subtract(BigInteger.valueOf(2)))
            .add(BigInteger.ONE)
        privateKey = x
        publicKeyValue = generator.modPow(x, prime)
        // Return as mpint bytes (without length prefix -- KEX_DH_INIT sends it as mpint)
        return publicKeyValue!!.toByteArray()
    }

    override fun computeSharedSecret(serverPublicKey: ByteArray): BigInteger {
        val priv = privateKey ?: throw IllegalStateException("generateClientKey not called")
        val serverPub = BigInteger(serverPublicKey)
        if (serverPub <= BigInteger.ONE || serverPub >= prime.subtract(BigInteger.ONE)) {
            throw SshProtocolException("Invalid DH server public key")
        }
        return serverPub.modPow(priv, prime)
    }

    // For DH groups, the exchange hash computation uses mpint for client/server keys
    override fun computeExchangeHash(
        clientVersion: String, serverVersion: String,
        clientKexInit: ByteArray, serverKexInit: ByteArray,
        hostKeyBlob: ByteArray, clientPublicKey: ByteArray,
        serverPublicKey: ByteArray, sharedSecret: BigInteger
    ): ByteArray {
        val buf = SshBufferWriter(1024)
            .writeUtf8(clientVersion)
            .writeUtf8(serverVersion)
            .writeString(clientKexInit)
            .writeString(serverKexInit)
            .writeString(hostKeyBlob)
            .writeMpint(BigInteger(clientPublicKey))
            .writeMpint(BigInteger(serverPublicKey))
            .writeMpint(sharedSecret)
        return MessageDigest.getInstance(hashAlgorithm).digest(buf.toByteArray())
    }
}

/** Diffie-Hellman Group14 SHA-1 (RFC 4253 §8, 2048-bit, legacy). */
class DhGroup14Sha1 : DhGroupKex(
    name = "diffie-hellman-group14-sha1",
    hashAlgorithm = "SHA-1",
    prime = DhGroup14Sha256.DH_GROUP14_P,
    generator = BigInteger.valueOf(2),
    bitSize = 2048
)

/** Diffie-Hellman Group14 SHA-256 (RFC 4253 §8 + RFC 8268, 2048-bit). */
class DhGroup14Sha256 : DhGroupKex(
    name = "diffie-hellman-group14-sha256",
    hashAlgorithm = "SHA-256",
    prime = DH_GROUP14_P,
    generator = BigInteger.valueOf(2),
    bitSize = 2048
) {
    companion object {
        /** RFC 3526 §3: 2048-bit MODP group (Group 14). */
        val DH_GROUP14_P = BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
        )
    }
}

/** Diffie-Hellman Group16 SHA-512 (RFC 3526 §5 + RFC 8268, 4096-bit). */
class DhGroup16Sha512 : DhGroupKex(
    name = "diffie-hellman-group16-sha512",
    hashAlgorithm = "SHA-512",
    prime = DH_GROUP16_P,
    generator = BigInteger.valueOf(2),
    bitSize = 4096
) {
    companion object {
        /** RFC 3526 §5: 4096-bit MODP group (Group 16). */
        val DH_GROUP16_P = BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
            "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
            "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
            "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
            "F12FFA06D98A0864D87602733EC86A64521F2B18177B200CB" +
            "BE117577A615D6C770988C0BAD946E208E24FA074E5AB3143" +
            "DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7887" +
            "19A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583" +
            "E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C5" +
            "9474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F6129" +
            "70CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA9" +
            "88D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4" +
            "D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406A" +
            "D9E530EE5DB382F413001AEB06A53ED9027D831179727B086" +
            "5A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6C" +
            "C254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B9" +
            "2ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C" +
            "82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88B" +
            "E0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D8" +
            "14CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F" +
            "550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387" +
            "FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F" +
            "91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D" +
            "073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936B" +
            "A424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D" +
            "652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C" +
            "73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879" +
            "683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310" +
            "EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195" +
            "DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB87" +
            "9F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E47" +
            "9558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C9" +
            "80DD98EDD3DFFFFFFFFFFFFFFFF", 16
        )
    }
}

/** Diffie-Hellman Group18 SHA-512 (RFC 3526 §7 + RFC 8268, 8192-bit). */
class DhGroup18Sha512 : DhGroupKex(
    name = "diffie-hellman-group18-sha512",
    hashAlgorithm = "SHA-512",
    prime = DH_GROUP18_P,
    generator = BigInteger.valueOf(2),
    bitSize = 8192
) {
    companion object {
        /** RFC 3526 §7: 8192-bit MODP group (Group 18). */
        val DH_GROUP18_P = BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
            "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
            "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
            "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
            "F12FFA06D98A0864D87602733EC86A64521F2B18177B200CB" +
            "BE117577A615D6C770988C0BAD946E208E24FA074E5AB3143" +
            "DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7887" +
            "19A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583" +
            "E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C5" +
            "9474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F6129" +
            "70CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA9" +
            "88D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4" +
            "D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406A" +
            "D9E530EE5DB382F413001AEB06A53ED9027D831179727B086" +
            "5A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6C" +
            "C254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B9" +
            "2ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C" +
            "82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88B" +
            "E0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D8" +
            "14CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F" +
            "550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387" +
            "FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F" +
            "91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D" +
            "073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936B" +
            "A424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D" +
            "652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C" +
            "73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879" +
            "683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310" +
            "EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195" +
            "DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB87" +
            "9F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E47" +
            "9558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C9" +
            "80DD98EDD3DFFFFFFFFFFFFFFFF", 16
        )
    }
}

/** Registry of supported key exchange algorithms, ordered by preference. */
object KeyExchangeRegistry {
    val LEGACY_ALGORITHMS = setOf("diffie-hellman-group14-sha1")

    fun getPreferred(): List<KeyExchangeAlgorithm> = listOf(
        MlKem768X25519Sha512(),     // Post-Quantum hybrid (highest priority)
        Curve25519Sha256(),
        Curve25519Sha256LibSsh(),
        EcdhSha2("nistp256", "SHA-256"),
        EcdhSha2("nistp384", "SHA-384"),
        EcdhSha2("nistp521", "SHA-512"),
        DhGroup16Sha512(),
        DhGroup18Sha512(),
        DhGroup14Sha256(),
        DhGroup14Sha1()             // Legacy fallback (last resort)
    )

    fun byName(name: String): KeyExchangeAlgorithm? =
        getPreferred().firstOrNull { it.name == name }

    fun nameList(): List<String> = getPreferred().map { it.name }
}
