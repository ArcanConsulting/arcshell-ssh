package de.arcan.arcshell.ssh.transport

/**
 * Parses and represents an OpenSSH certificate per the PROTOCOL.certkeys spec.
 *
 * Wire format:
 * ```
 * string    cert type (e.g. "ssh-ed25519-cert-v01@openssh.com")
 * string    nonce
 * [key-specific fields]
 * uint64    serial
 * uint32    type (1=user, 2=host)
 * string    key id
 * string    valid principals (packed: uint32 count, then count x string)
 * uint64    valid after
 * uint64    valid before
 * string    critical options (packed pairs: string name, string data)
 * string    extensions (packed pairs: string name, string data)
 * string    reserved
 * string    signature key (full SSH public key blob of the CA)
 * string    signature
 * ```
 */
class SshCertificate private constructor(
    val certType: String,
    val nonce: ByteArray,
    val serial: Long,
    val type: Int,
    val keyId: String,
    val validPrincipals: List<String>,
    val validAfter: Long,
    val validBefore: Long,
    val signatureKeyBlob: ByteArray,
    val signature: ByteArray,
    val innerPublicKeyBlob: ByteArray
) {

    companion object {
        const val TYPE_USER = 1
        const val TYPE_HOST = 2

        private val ED25519_CERT = "ssh-ed25519-cert-v01@openssh.com"
        private val RSA_SHA2_256_CERT = "rsa-sha2-256-cert-v01@openssh.com"
        private val RSA_SHA2_512_CERT = "rsa-sha2-512-cert-v01@openssh.com"
        private val ECDSA_256_CERT = "ecdsa-sha2-nistp256-cert-v01@openssh.com"
        private val ECDSA_384_CERT = "ecdsa-sha2-nistp384-cert-v01@openssh.com"
        private val ECDSA_521_CERT = "ecdsa-sha2-nistp521-cert-v01@openssh.com"

        /**
         * Parse an OpenSSH certificate from raw wire bytes.
         *
         * @param blob the certificate blob (as received in SSH_MSG_KEXINIT
         *             host key or SSH_MSG_USERAUTH_REQUEST public key field)
         * @throws IllegalArgumentException if the blob cannot be parsed
         * @throws IllegalStateException on buffer underflow
         */
        fun parse(blob: ByteArray): SshCertificate {
            val reader = SshBufferReader(blob)

            val certType = reader.readUtf8()
            require(certType.endsWith("-cert-v01@openssh.com")) {
                "Not an OpenSSH certificate: $certType"
            }

            val nonce = reader.readString()

            val innerPubKeyBlob = readInnerPublicKey(reader, certType)

            val serial = reader.readUint64()
            val type = reader.readUint32().toInt()
            val keyId = reader.readUtf8()

            val principalsBlob = reader.readString()
            val validPrincipals = parsePrincipals(principalsBlob)

            val validAfter = reader.readUint64()
            val validBefore = reader.readUint64()

            // Critical options and extensions: read as opaque blobs (skip)
            reader.readString() // critical options
            reader.readString() // extensions
            reader.readString() // reserved

            val signatureKeyBlob = reader.readString()
            val signature = reader.readString()

            return SshCertificate(
                certType = certType,
                nonce = nonce,
                serial = serial,
                type = type,
                keyId = keyId,
                validPrincipals = validPrincipals,
                validAfter = validAfter,
                validBefore = validBefore,
                signatureKeyBlob = signatureKeyBlob,
                signature = signature,
                innerPublicKeyBlob = innerPubKeyBlob
            )
        }

        /**
         * Returns true if [keyType] is an OpenSSH certificate key type.
         */
        fun isCertificateType(keyType: String): Boolean {
            return keyType.endsWith("-cert-v01@openssh.com")
        }

        /**
         * Returns the base key type for a certificate type.
         * e.g. "ssh-ed25519-cert-v01@openssh.com" -> "ssh-ed25519"
         */
        fun baseKeyType(certType: String): String {
            return certType.removeSuffix("-cert-v01@openssh.com")
        }

        /**
         * Read the key-type-specific public key fields from the certificate
         * and reconstruct the standard SSH public key blob.
         */
        private fun readInnerPublicKey(reader: SshBufferReader, certType: String): ByteArray {
            val writer = SshBufferWriter()

            when (certType) {
                ED25519_CERT -> {
                    val pubkey = reader.readString()
                    writer.writeUtf8("ssh-ed25519")
                    writer.writeString(pubkey)
                }

                RSA_SHA2_256_CERT, RSA_SHA2_512_CERT -> {
                    val e = reader.readMpint()
                    val n = reader.readMpint()
                    writer.writeUtf8("ssh-rsa")
                    writer.writeMpint(e)
                    writer.writeMpint(n)
                }

                ECDSA_256_CERT -> {
                    val curve = reader.readUtf8()
                    val q = reader.readString()
                    writer.writeUtf8("ecdsa-sha2-nistp256")
                    writer.writeUtf8(curve)
                    writer.writeString(q)
                }

                ECDSA_384_CERT -> {
                    val curve = reader.readUtf8()
                    val q = reader.readString()
                    writer.writeUtf8("ecdsa-sha2-nistp384")
                    writer.writeUtf8(curve)
                    writer.writeString(q)
                }

                ECDSA_521_CERT -> {
                    val curve = reader.readUtf8()
                    val q = reader.readString()
                    writer.writeUtf8("ecdsa-sha2-nistp521")
                    writer.writeUtf8(curve)
                    writer.writeString(q)
                }

                else -> throw IllegalArgumentException("Unsupported certificate type: $certType")
            }

            return writer.toByteArray()
        }

        /**
         * Parse the packed principals blob: uint32 count, then count x string.
         */
        private fun parsePrincipals(blob: ByteArray): List<String> {
            if (blob.isEmpty()) return emptyList()
            val reader = SshBufferReader(blob)
            val principals = mutableListOf<String>()
            while (reader.remaining > 0) {
                principals.add(reader.readUtf8())
            }
            return principals
        }
    }

    /**
     * Check if the certificate is within its validity period.
     *
     * @param now current Unix timestamp in seconds (defaults to current time)
     */
    fun isValid(now: Long = System.currentTimeMillis() / 1000): Boolean {
        return now >= validAfter && now <= validBefore
    }

    /**
     * Returns true if this is a host certificate (type 2).
     */
    fun isHostCertificate(): Boolean = type == TYPE_HOST

    /**
     * Returns true if this is a user certificate (type 1).
     */
    fun isUserCertificate(): Boolean = type == TYPE_USER
}
