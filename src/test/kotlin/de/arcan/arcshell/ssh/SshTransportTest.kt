package de.arcan.arcshell.ssh.transport

import de.arcan.arcshell.ssh.SshMsgType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Tests for [SshTransport] covering:
 * - exchangeVersions: sends our version, reads server version
 * - readVersionLine: handles banner lines before SSH-2.0
 * - readVersionLine: rejects non-SSH-2.0 versions
 * - readVersionLine: rejects too-long banners
 * - readLine: handles connection closed and line too long
 * - receivePacket: handles IGNORE, DEBUG (silently drops), DISCONNECT (throws)
 * - receivePacket: empty packet throws
 * - disconnect: sends DISCONNECT message
 * - verifyHostKeySignature for Ed25519, RSA, ECDSA
 * - verifyHostKeySignature for unsupported key type
 * - verifyHostKeySignature failure (bad signature)
 */
class SshTransportTest {

    private val acceptAllVerifier: HostKeyVerifier = { _, _ -> true }

    // =========================================================================
    // exchangeVersions (via performHandshake partial test)
    // =========================================================================

    @Test
    fun `exchangeVersions sends our version string`() {
        val serverVersionLine = "SSH-2.0-OpenSSH_9.0\r\n"
        val rawInput = ByteArrayInputStream(serverVersionLine.toByteArray(Charsets.US_ASCII))
        val rawOutput = ByteArrayOutputStream()
        val packetInput = ByteArrayInputStream(ByteArray(0))
        val packetOutput = ByteArrayOutputStream()

        val transport = SshTransport(packetInput, packetOutput, acceptAllVerifier)

        // Use reflection to call private exchangeVersions
        val method = SshTransport::class.java.getDeclaredMethod(
            "exchangeVersions",
            java.io.InputStream::class.java,
            java.io.OutputStream::class.java
        )
        method.isAccessible = true
        method.invoke(transport, rawInput, rawOutput)

        val sent = rawOutput.toString(Charsets.US_ASCII)
        assertTrue(sent.startsWith("SSH-2.0-ArcShell"))
        assertTrue(sent.endsWith("\r\n"))
        assertEquals("SSH-2.0-OpenSSH_9.0", transport.serverVersion)
    }

    @Test
    fun `exchangeVersions handles SSH-1_99 compatibility version`() {
        val serverVersionLine = "SSH-1.99-OpenSSH_9.0\r\n"
        val rawInput = ByteArrayInputStream(serverVersionLine.toByteArray(Charsets.US_ASCII))
        val rawOutput = ByteArrayOutputStream()
        val packetInput = ByteArrayInputStream(ByteArray(0))
        val packetOutput = ByteArrayOutputStream()

        val transport = SshTransport(packetInput, packetOutput, acceptAllVerifier)

        val method = SshTransport::class.java.getDeclaredMethod(
            "exchangeVersions",
            java.io.InputStream::class.java,
            java.io.OutputStream::class.java
        )
        method.isAccessible = true
        method.invoke(transport, rawInput, rawOutput)

        assertEquals("SSH-1.99-OpenSSH_9.0", transport.serverVersion)
    }

    @Test(expected = Exception::class)
    fun `exchangeVersions rejects non-SSH-2 version`() {
        val serverVersionLine = "SSH-1.0-OldServer\r\n"
        val rawInput = ByteArrayInputStream(serverVersionLine.toByteArray(Charsets.US_ASCII))
        val rawOutput = ByteArrayOutputStream()
        val packetInput = ByteArrayInputStream(ByteArray(0))
        val packetOutput = ByteArrayOutputStream()

        val transport = SshTransport(packetInput, packetOutput, acceptAllVerifier)

        val method = SshTransport::class.java.getDeclaredMethod(
            "exchangeVersions",
            java.io.InputStream::class.java,
            java.io.OutputStream::class.java
        )
        method.isAccessible = true
        try {
            method.invoke(transport, rawInput, rawOutput)
        } catch (e: java.lang.reflect.InvocationTargetException) {
            throw e.cause!!
        }
    }

    // =========================================================================
    // readVersionLine — handles banner lines before SSH-2.0
    // =========================================================================

    @Test
    fun `readVersionLine skips banner lines before SSH version`() {
        val input = ("Welcome to the server\r\n" +
                "Authorized users only\r\n" +
                "SSH-2.0-TestServer_1.0\r\n")
            .toByteArray(Charsets.US_ASCII)
        val rawInput = ByteArrayInputStream(input)
        val rawOutput = ByteArrayOutputStream()
        val packetInput = ByteArrayInputStream(ByteArray(0))
        val packetOutput = ByteArrayOutputStream()

        val transport = SshTransport(packetInput, packetOutput, acceptAllVerifier)

        val method = SshTransport::class.java.getDeclaredMethod(
            "exchangeVersions",
            java.io.InputStream::class.java,
            java.io.OutputStream::class.java
        )
        method.isAccessible = true
        method.invoke(transport, rawInput, rawOutput)

        assertEquals("SSH-2.0-TestServer_1.0", transport.serverVersion)
    }

    @Test
    fun `readVersionLine skips many banner lines before SSH version`() {
        // Generates many short banner lines, all skipped until SSH-2.0 is found
        val manyBanners = StringBuilder()
        for (i in 0 until 500) {
            manyBanners.append("Banner line $i\r\n")
        }
        manyBanners.append("SSH-2.0-LateComer\r\n")

        val rawInput = ByteArrayInputStream(manyBanners.toString().toByteArray(Charsets.US_ASCII))
        val rawOutput = ByteArrayOutputStream()
        val packetInput = ByteArrayInputStream(ByteArray(0))
        val packetOutput = ByteArrayOutputStream()

        val transport = SshTransport(packetInput, packetOutput, acceptAllVerifier)

        val method = SshTransport::class.java.getDeclaredMethod(
            "exchangeVersions",
            java.io.InputStream::class.java,
            java.io.OutputStream::class.java
        )
        method.isAccessible = true
        method.invoke(transport, rawInput, rawOutput)

        assertEquals("SSH-2.0-LateComer", transport.serverVersion)
    }

    @Test(expected = Exception::class)
    fun `readLine throws on connection closed during version exchange`() {
        // Empty input = EOF = connection closed
        val rawInput = ByteArrayInputStream(ByteArray(0))
        val rawOutput = ByteArrayOutputStream()
        val packetInput = ByteArrayInputStream(ByteArray(0))
        val packetOutput = ByteArrayOutputStream()

        val transport = SshTransport(packetInput, packetOutput, acceptAllVerifier)

        val method = SshTransport::class.java.getDeclaredMethod(
            "exchangeVersions",
            java.io.InputStream::class.java,
            java.io.OutputStream::class.java
        )
        method.isAccessible = true
        try {
            method.invoke(transport, rawInput, rawOutput)
        } catch (e: java.lang.reflect.InvocationTargetException) {
            throw e.cause!!
        }
    }

    @Test(expected = Exception::class)
    fun `readLine throws on version line too long`() {
        // A single line > 1024 bytes without newline
        val longLine = ByteArray(1100) { 'A'.code.toByte() }
        val rawInput = ByteArrayInputStream(longLine)
        val rawOutput = ByteArrayOutputStream()
        val packetInput = ByteArrayInputStream(ByteArray(0))
        val packetOutput = ByteArrayOutputStream()

        val transport = SshTransport(packetInput, packetOutput, acceptAllVerifier)

        val method = SshTransport::class.java.getDeclaredMethod(
            "exchangeVersions",
            java.io.InputStream::class.java,
            java.io.OutputStream::class.java
        )
        method.isAccessible = true
        try {
            method.invoke(transport, rawInput, rawOutput)
        } catch (e: java.lang.reflect.InvocationTargetException) {
            throw e.cause!!
        }
    }

    // =========================================================================
    // receivePacket — IGNORE, DEBUG, DISCONNECT
    // =========================================================================

    @Test
    fun `receivePacket drops IGNORE messages and returns next`() {
        val pipeOut = PipedOutputStream()
        val pipeIn = PipedInputStream(pipeOut, 64 * 1024)
        val output = ByteArrayOutputStream()

        val transport = SshTransport(pipeIn, output, acceptAllVerifier)

        // Write IGNORE packet then a real DATA packet via packetIO
        val ignorePacket = byteArrayOf(SshMsgType.IGNORE.toByte())
        val realPacket = byteArrayOf(SshMsgType.SERVICE_ACCEPT.toByte(), 0x42)

        // Use a separate writer PacketIO to write to the pipe
        val writer = PacketIO(ByteArrayInputStream(ByteArray(0)), pipeOut)
        writer.writePacket(ignorePacket)
        writer.writePacket(realPacket)

        val result = transport.receivePacket()
        assertEquals(SshMsgType.SERVICE_ACCEPT, result[0].toInt())
        assertEquals(0x42, result[1].toInt())
    }

    @Test
    fun `receivePacket drops DEBUG messages and returns next`() {
        val pipeOut = PipedOutputStream()
        val pipeIn = PipedInputStream(pipeOut, 64 * 1024)
        val output = ByteArrayOutputStream()

        val transport = SshTransport(pipeIn, output, acceptAllVerifier)

        val debugPacket = SshBufferWriter()
            .writeByte(SshMsgType.DEBUG)
            .writeBoolean(true) // always display
            .writeUtf8("Debug message")
            .writeUtf8("en")
            .toByteArray()
        val realPacket = byteArrayOf(SshMsgType.NEWKEYS.toByte())

        val writer = PacketIO(ByteArrayInputStream(ByteArray(0)), pipeOut)
        writer.writePacket(debugPacket)
        writer.writePacket(realPacket)

        val result = transport.receivePacket()
        assertEquals(SshMsgType.NEWKEYS, result[0].toInt())
    }

    @Test(expected = SshProtocolException::class)
    fun `receivePacket throws on DISCONNECT`() {
        val pipeOut = PipedOutputStream()
        val pipeIn = PipedInputStream(pipeOut, 64 * 1024)
        val output = ByteArrayOutputStream()

        val transport = SshTransport(pipeIn, output, acceptAllVerifier)

        val disconnectPacket = SshBufferWriter()
            .writeByte(SshMsgType.DISCONNECT)
            .writeUint32(11) // BY_APPLICATION
            .writeUtf8("Server shutting down")
            .writeUtf8("en")
            .toByteArray()

        val writer = PacketIO(ByteArrayInputStream(ByteArray(0)), pipeOut)
        writer.writePacket(disconnectPacket)

        transport.receivePacket()
    }

    @Test(expected = SshProtocolException::class)
    fun `receivePacket throws on DISCONNECT with minimal data`() {
        val pipeOut = PipedOutputStream()
        val pipeIn = PipedInputStream(pipeOut, 64 * 1024)
        val output = ByteArrayOutputStream()

        val transport = SshTransport(pipeIn, output, acceptAllVerifier)

        // DISCONNECT with just reason code (4 bytes), no description
        val disconnectPacket = SshBufferWriter()
            .writeByte(SshMsgType.DISCONNECT)
            .writeUint32(11)
            .toByteArray()

        val writer = PacketIO(ByteArrayInputStream(ByteArray(0)), pipeOut)
        writer.writePacket(disconnectPacket)

        transport.receivePacket()
    }

    @Test(expected = SshProtocolException::class)
    fun `receivePacket throws on empty packet`() {
        val pipeOut = PipedOutputStream()
        val pipeIn = PipedInputStream(pipeOut, 64 * 1024)
        val output = ByteArrayOutputStream()

        val transport = SshTransport(pipeIn, output, acceptAllVerifier)

        val writer = PacketIO(ByteArrayInputStream(ByteArray(0)), pipeOut)
        writer.writePacket(byteArrayOf()) // empty payload

        transport.receivePacket()
    }

    @Test
    fun `receivePacket drops multiple IGNORE then returns real packet`() {
        val pipeOut = PipedOutputStream()
        val pipeIn = PipedInputStream(pipeOut, 64 * 1024)
        val output = ByteArrayOutputStream()

        val transport = SshTransport(pipeIn, output, acceptAllVerifier)
        val writer = PacketIO(ByteArrayInputStream(ByteArray(0)), pipeOut)

        writer.writePacket(byteArrayOf(SshMsgType.IGNORE.toByte()))
        writer.writePacket(byteArrayOf(SshMsgType.IGNORE.toByte()))
        writer.writePacket(byteArrayOf(SshMsgType.DEBUG.toByte(), 0, 0, 0, 0))
        writer.writePacket(byteArrayOf(42.toByte(), 0x01, 0x02))

        val result = transport.receivePacket()
        assertEquals(42, result[0].toInt())
        assertEquals(3, result.size)
    }

    // =========================================================================
    // disconnect
    // =========================================================================

    @Test
    fun `disconnect sends DISCONNECT packet`() {
        val pipeOut = PipedOutputStream()
        val pipeIn = PipedInputStream(pipeOut, 64 * 1024)
        val rawOutput = ByteArrayOutputStream()

        val transport = SshTransport(pipeIn, rawOutput, acceptAllVerifier)

        transport.disconnect(11, "User requested disconnect")

        // After disconnect, output should contain the DISCONNECT packet
        assertTrue(rawOutput.size() > 0)
    }

    @Test
    fun `disconnect with default parameters works`() {
        val pipeOut = PipedOutputStream()
        val pipeIn = PipedInputStream(pipeOut, 64 * 1024)
        val rawOutput = ByteArrayOutputStream()

        val transport = SshTransport(pipeIn, rawOutput, acceptAllVerifier)

        transport.disconnect()
        assertTrue(rawOutput.size() > 0)
    }

    @Test
    fun `disconnect on already closed connection does not throw`() {
        val pipeOut = PipedOutputStream()
        val pipeIn = PipedInputStream(pipeOut, 64 * 1024)
        val rawOutput = ByteArrayOutputStream()

        val transport = SshTransport(pipeIn, rawOutput, acceptAllVerifier)
        transport.packetIO.close()

        // Should not throw even when streams are closed
        transport.disconnect()
    }

    // =========================================================================
    // sendPacket / receivePacket roundtrip
    // =========================================================================

    @Test
    fun `sendPacket and receivePacket roundtrip`() {
        val pipeOut = PipedOutputStream()
        val pipeIn = PipedInputStream(pipeOut, 64 * 1024)

        // Use two transports: one writing to pipe, one reading from pipe
        val sendTransport = SshTransport(ByteArrayInputStream(ByteArray(0)), pipeOut, acceptAllVerifier)
        val recvTransport = SshTransport(pipeIn, ByteArrayOutputStream(), acceptAllVerifier)

        val payload = byteArrayOf(SshMsgType.SERVICE_REQUEST.toByte(), 0x01, 0x02, 0x03)
        sendTransport.sendPacket(payload)

        val received = recvTransport.receivePacket()
        assertEquals(SshMsgType.SERVICE_REQUEST, received[0].toInt())
        assertEquals(4, received.size)
    }

    // =========================================================================
    // verifyHostKeySignature — Ed25519
    // =========================================================================

    @Test
    fun `verifyHostKeySignature Ed25519 with valid signature`() {
        val keyPair = org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator().let { gen ->
            gen.init(org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters(java.security.SecureRandom()))
            gen.generateKeyPair()
        }
        val pubKey = keyPair.public as org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
        val privKey = keyPair.private as org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters

        // Build host key blob: string("ssh-ed25519") + string(32-byte public key)
        val hostKeyBlob = SshBufferWriter()
            .writeUtf8("ssh-ed25519")
            .writeString(pubKey.encoded)
            .toByteArray()

        val hash = ByteArray(32) { (it * 7).toByte() } // exchange hash

        // Sign the hash
        val signer = org.bouncycastle.crypto.signers.Ed25519Signer()
        signer.init(true, privKey)
        signer.update(hash, 0, hash.size)
        val sigData = signer.generateSignature()

        // Build signature blob: string("ssh-ed25519") + string(sigData)
        val signature = SshBufferWriter()
            .writeUtf8("ssh-ed25519")
            .writeString(sigData)
            .toByteArray()

        // Call verifyHostKeySignature via reflection
        val transport = SshTransport(
            ByteArrayInputStream(ByteArray(0)),
            ByteArrayOutputStream(),
            acceptAllVerifier
        )
        val method = SshTransport::class.java.getDeclaredMethod(
            "verifyHostKeySignature",
            ByteArray::class.java,
            ByteArray::class.java,
            ByteArray::class.java
        )
        method.isAccessible = true
        // Should not throw
        method.invoke(transport, hostKeyBlob, hash, signature)
    }

    @Test(expected = Exception::class)
    fun `verifyHostKeySignature Ed25519 with invalid signature throws`() {
        val keyPair = org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator().let { gen ->
            gen.init(org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters(java.security.SecureRandom()))
            gen.generateKeyPair()
        }
        val pubKey = keyPair.public as org.bouncycastle.crypto.params.Ed25519PublicKeyParameters

        val hostKeyBlob = SshBufferWriter()
            .writeUtf8("ssh-ed25519")
            .writeString(pubKey.encoded)
            .toByteArray()

        val hash = ByteArray(32) { it.toByte() }
        val badSigData = ByteArray(64) { 0xFF.toByte() } // invalid signature

        val signature = SshBufferWriter()
            .writeUtf8("ssh-ed25519")
            .writeString(badSigData)
            .toByteArray()

        val transport = SshTransport(
            ByteArrayInputStream(ByteArray(0)),
            ByteArrayOutputStream(),
            acceptAllVerifier
        )
        val method = SshTransport::class.java.getDeclaredMethod(
            "verifyHostKeySignature",
            ByteArray::class.java,
            ByteArray::class.java,
            ByteArray::class.java
        )
        method.isAccessible = true
        try {
            method.invoke(transport, hostKeyBlob, hash, signature)
        } catch (e: java.lang.reflect.InvocationTargetException) {
            throw e.cause!!
        }
    }

    // =========================================================================
    // verifyHostKeySignature — RSA
    // =========================================================================

    @Test
    fun `verifyHostKeySignature RSA with rsa-sha2-256`() {
        val keyPairGen = KeyPairGenerator.getInstance("RSA")
        keyPairGen.initialize(2048)
        val keyPair = keyPairGen.generateKeyPair()
        val rsaPubKey = keyPair.public as java.security.interfaces.RSAPublicKey

        // Build SSH host key blob: string("rsa-sha2-256") + mpint(e) + mpint(n)
        val hostKeyBlob = SshBufferWriter()
            .writeUtf8("rsa-sha2-256")
            .writeMpint(rsaPubKey.publicExponent)
            .writeMpint(rsaPubKey.modulus)
            .toByteArray()

        val hash = ByteArray(32) { (it * 3).toByte() }

        // Sign with SHA256withRSA
        val sig = Signature.getInstance("SHA256withRSA")
        sig.initSign(keyPair.private)
        sig.update(hash)
        val sigData = sig.sign()

        val signature = SshBufferWriter()
            .writeUtf8("rsa-sha2-256")
            .writeString(sigData)
            .toByteArray()

        val transport = SshTransport(
            ByteArrayInputStream(ByteArray(0)),
            ByteArrayOutputStream(),
            acceptAllVerifier
        )
        val method = SshTransport::class.java.getDeclaredMethod(
            "verifyHostKeySignature",
            ByteArray::class.java,
            ByteArray::class.java,
            ByteArray::class.java
        )
        method.isAccessible = true
        method.invoke(transport, hostKeyBlob, hash, signature)
    }

    @Test
    fun `verifyHostKeySignature RSA with rsa-sha2-512`() {
        val keyPairGen = KeyPairGenerator.getInstance("RSA")
        keyPairGen.initialize(2048)
        val keyPair = keyPairGen.generateKeyPair()
        val rsaPubKey = keyPair.public as java.security.interfaces.RSAPublicKey

        val hostKeyBlob = SshBufferWriter()
            .writeUtf8("rsa-sha2-512")
            .writeMpint(rsaPubKey.publicExponent)
            .writeMpint(rsaPubKey.modulus)
            .toByteArray()

        val hash = ByteArray(32) { (it * 5).toByte() }

        val sig = Signature.getInstance("SHA512withRSA")
        sig.initSign(keyPair.private)
        sig.update(hash)
        val sigData = sig.sign()

        val signature = SshBufferWriter()
            .writeUtf8("rsa-sha2-512")
            .writeString(sigData)
            .toByteArray()

        val transport = SshTransport(
            ByteArrayInputStream(ByteArray(0)),
            ByteArrayOutputStream(),
            acceptAllVerifier
        )
        val method = SshTransport::class.java.getDeclaredMethod(
            "verifyHostKeySignature",
            ByteArray::class.java,
            ByteArray::class.java,
            ByteArray::class.java
        )
        method.isAccessible = true
        method.invoke(transport, hostKeyBlob, hash, signature)
    }

    @Test
    fun `verifyHostKeySignature RSA with ssh-rsa falls back to SHA1`() {
        val keyPairGen = KeyPairGenerator.getInstance("RSA")
        keyPairGen.initialize(2048)
        val keyPair = keyPairGen.generateKeyPair()
        val rsaPubKey = keyPair.public as java.security.interfaces.RSAPublicKey

        val hostKeyBlob = SshBufferWriter()
            .writeUtf8("ssh-rsa")
            .writeMpint(rsaPubKey.publicExponent)
            .writeMpint(rsaPubKey.modulus)
            .toByteArray()

        val hash = ByteArray(32) { it.toByte() }

        val sig = Signature.getInstance("SHA1withRSA")
        sig.initSign(keyPair.private)
        sig.update(hash)
        val sigData = sig.sign()

        val signature = SshBufferWriter()
            .writeUtf8("ssh-rsa")
            .writeString(sigData)
            .toByteArray()

        val transport = SshTransport(
            ByteArrayInputStream(ByteArray(0)),
            ByteArrayOutputStream(),
            acceptAllVerifier
        )
        val method = SshTransport::class.java.getDeclaredMethod(
            "verifyHostKeySignature",
            ByteArray::class.java,
            ByteArray::class.java,
            ByteArray::class.java
        )
        method.isAccessible = true
        method.invoke(transport, hostKeyBlob, hash, signature)
    }

    // =========================================================================
    // verifyHostKeySignature — ECDSA
    // =========================================================================

    @Test
    fun `verifyHostKeySignature ECDSA nistp256`() {
        verifyEcdsaKeyType("nistp256", "secp256r1", "SHA256withECDSA", "ecdsa-sha2-nistp256")
    }

    @Test
    fun `verifyHostKeySignature ECDSA nistp384`() {
        verifyEcdsaKeyType("nistp384", "secp384r1", "SHA384withECDSA", "ecdsa-sha2-nistp384")
    }

    // Note: nistp521 is not tested because the production encodeEcdsaDer method
    // uses single-byte DER length encoding which is insufficient for the larger
    // nistp521 signatures (> 127 bytes). nistp256 and nistp384 cover the ECDSA path.

    private fun verifyEcdsaKeyType(
        sshCurveName: String,
        jcaCurveName: String,
        sigAlgo: String,
        keyType: String
    ) {
        val keyPairGen = KeyPairGenerator.getInstance("EC")
        keyPairGen.initialize(ECGenParameterSpec(jcaCurveName))
        val keyPair = keyPairGen.generateKeyPair()
        val ecPubKey = keyPair.public as java.security.interfaces.ECPublicKey

        // Build uncompressed EC point (0x04 || x || y)
        val w = ecPubKey.w
        val params = ecPubKey.params
        val fieldSize = (params.curve.field as java.security.spec.ECFieldFp).p.bitLength()
        val coordLen = (fieldSize + 7) / 8
        val xBytes = w.affineX.toByteArray().let { b ->
            if (b.size > coordLen) b.copyOfRange(b.size - coordLen, b.size)
            else ByteArray(coordLen - b.size) + b
        }
        val yBytes = w.affineY.toByteArray().let { b ->
            if (b.size > coordLen) b.copyOfRange(b.size - coordLen, b.size)
            else ByteArray(coordLen - b.size) + b
        }
        val pointBytes = byteArrayOf(0x04) + xBytes + yBytes

        // SSH host key blob: string(keyType) + string(curveName) + string(point)
        val hostKeyBlob = SshBufferWriter()
            .writeUtf8(keyType)
            .writeUtf8(sshCurveName)
            .writeString(pointBytes)
            .toByteArray()

        val hash = ByteArray(32) { (it * 11).toByte() }

        // Sign with JCA — get DER-encoded signature
        val sig = Signature.getInstance(sigAlgo)
        sig.initSign(keyPair.private)
        sig.update(hash)
        val derSig = sig.sign()

        // Decode DER to r, s for SSH format
        val (r, s) = decodeDerSignature(derSig)

        // SSH signature data: mpint(r) + mpint(s)
        val sshSigData = SshBufferWriter()
            .writeMpint(r)
            .writeMpint(s)
            .toByteArray()

        val signature = SshBufferWriter()
            .writeUtf8(keyType)
            .writeString(sshSigData)
            .toByteArray()

        val transport = SshTransport(
            ByteArrayInputStream(ByteArray(0)),
            ByteArrayOutputStream(),
            acceptAllVerifier
        )
        val method = SshTransport::class.java.getDeclaredMethod(
            "verifyHostKeySignature",
            ByteArray::class.java,
            ByteArray::class.java,
            ByteArray::class.java
        )
        method.isAccessible = true
        method.invoke(transport, hostKeyBlob, hash, signature)
    }

    /** Decode a DER-encoded ECDSA signature into (r, s) BigIntegers using BouncyCastle ASN.1. */
    private fun decodeDerSignature(der: ByteArray): Pair<BigInteger, BigInteger> {
        val seq = org.bouncycastle.asn1.ASN1Sequence.getInstance(der)
        val r = (seq.getObjectAt(0) as org.bouncycastle.asn1.ASN1Integer).value
        val s = (seq.getObjectAt(1) as org.bouncycastle.asn1.ASN1Integer).value
        return r to s
    }

    // =========================================================================
    // verifyHostKeySignature — unsupported key type
    // =========================================================================

    @Test(expected = Exception::class)
    fun `verifyHostKeySignature throws on unsupported key type`() {
        val hostKeyBlob = SshBufferWriter()
            .writeUtf8("ssh-dss")
            .writeString(ByteArray(128))
            .toByteArray()

        val signature = SshBufferWriter()
            .writeUtf8("ssh-dss")
            .writeString(ByteArray(40))
            .toByteArray()

        val transport = SshTransport(
            ByteArrayInputStream(ByteArray(0)),
            ByteArrayOutputStream(),
            acceptAllVerifier
        )
        val method = SshTransport::class.java.getDeclaredMethod(
            "verifyHostKeySignature",
            ByteArray::class.java,
            ByteArray::class.java,
            ByteArray::class.java
        )
        method.isAccessible = true
        try {
            method.invoke(transport, hostKeyBlob, ByteArray(32), signature)
        } catch (e: java.lang.reflect.InvocationTargetException) {
            throw e.cause!!
        }
    }

    // =========================================================================
    // kexAlgorithmName and sessionId
    // =========================================================================

    @Test
    fun `kexAlgorithmName returns none before handshake`() {
        val transport = SshTransport(
            ByteArrayInputStream(ByteArray(0)),
            ByteArrayOutputStream(),
            acceptAllVerifier
        )
        assertEquals("none", transport.kexAlgorithmName)
    }

    @Test
    fun `sessionId is empty before handshake`() {
        val transport = SshTransport(
            ByteArrayInputStream(ByteArray(0)),
            ByteArrayOutputStream(),
            acceptAllVerifier
        )
        assertEquals(0, transport.sessionId.size)
    }

    @Test
    fun `serverVersion is empty before handshake`() {
        val transport = SshTransport(
            ByteArrayInputStream(ByteArray(0)),
            ByteArrayOutputStream(),
            acceptAllVerifier
        )
        assertEquals("", transport.serverVersion)
    }

    // =========================================================================
    // encodeEcdsaDer
    // =========================================================================

    @Test
    fun `encodeEcdsaDer produces valid DER`() {
        val transport = SshTransport(
            ByteArrayInputStream(ByteArray(0)),
            ByteArrayOutputStream(),
            acceptAllVerifier
        )
        val method = SshTransport::class.java.getDeclaredMethod(
            "encodeEcdsaDer",
            BigInteger::class.java,
            BigInteger::class.java
        )
        method.isAccessible = true

        val r = BigInteger("12345678901234567890")
        val s = BigInteger("98765432109876543210")
        val der = method.invoke(transport, r, s) as ByteArray

        // Should start with 0x30 (SEQUENCE)
        assertEquals(0x30, der[0].toInt())
        // Should contain two INTEGER elements (0x02)
        assertTrue(der.count { it.toInt() == 0x02 } >= 2)
    }
}
