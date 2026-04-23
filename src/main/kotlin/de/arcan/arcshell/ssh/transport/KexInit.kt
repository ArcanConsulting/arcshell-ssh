package de.arcan.arcshell.ssh.transport

import de.arcan.arcshell.ssh.SshMsgType
import java.security.SecureRandom

/**
 * SSH_MSG_KEXINIT message (RFC 4253 §7.1).
 * Sent by both client and server to negotiate algorithms.
 */
data class KexInit(
    val cookie: ByteArray,
    val kexAlgorithms: List<String>,
    val serverHostKeyAlgorithms: List<String>,
    val encryptionClientToServer: List<String>,
    val encryptionServerToClient: List<String>,
    val macClientToServer: List<String>,
    val macServerToClient: List<String>,
    val compressionClientToServer: List<String>,
    val compressionServerToClient: List<String>,
    val languagesClientToServer: List<String>,
    val languagesServerToClient: List<String>,
    val firstKexPacketFollows: Boolean
) {
    /** Encode to SSH wire format (including message type byte). */
    fun encode(): ByteArray {
        val buf = SshBufferWriter(512)
            .writeByte(SshMsgType.KEXINIT)
            .writeBytes(cookie)
            .writeNameList(kexAlgorithms)
            .writeNameList(serverHostKeyAlgorithms)
            .writeNameList(encryptionClientToServer)
            .writeNameList(encryptionServerToClient)
            .writeNameList(macClientToServer)
            .writeNameList(macServerToClient)
            .writeNameList(compressionClientToServer)
            .writeNameList(compressionServerToClient)
            .writeNameList(languagesClientToServer)
            .writeNameList(languagesServerToClient)
            .writeBoolean(firstKexPacketFollows)
            .writeUint32(0) // reserved
        return buf.toByteArray()
    }

    companion object {
        /** Build our client KEXINIT with preferred algorithms. */
        fun createClient(): KexInit {
            val cookie = ByteArray(16).also { SecureRandom().nextBytes(it) }
            return KexInit(
                cookie = cookie,
                kexAlgorithms = KeyExchangeRegistry.nameList() + "kex-strict-c-v00@openssh.com",
                serverHostKeyAlgorithms = HostKeyRegistry.nameList(),
                encryptionClientToServer = CipherRegistry.nameList(),
                encryptionServerToClient = CipherRegistry.nameList(),
                macClientToServer = MacRegistry.nameList(),
                macServerToClient = MacRegistry.nameList(),
                compressionClientToServer = CompressionRegistry.nameList(),
                compressionServerToClient = CompressionRegistry.nameList(),
                languagesClientToServer = emptyList(),
                languagesServerToClient = emptyList(),
                firstKexPacketFollows = false
            )
        }

        /** Parse a KEXINIT message from wire data (payload after message type byte). */
        fun decode(payload: ByteArray): KexInit {
            val reader = SshBufferReader(payload, 0)
            // Message type already stripped by caller, but handle both cases
            val firstByte = reader.readByte()
            val startPos = if (firstByte == SshMsgType.KEXINIT) 0 else -1
            // If first byte wasn't KEXINIT, it's part of the cookie — rewind isn't possible,
            // so we handle by reading cookie as 15 bytes + first byte
            val cookie = if (firstByte == SshMsgType.KEXINIT) {
                reader.readBytes(16)
            } else {
                byteArrayOf(firstByte.toByte()) + reader.readBytes(15)
            }

            return KexInit(
                cookie = cookie,
                kexAlgorithms = reader.readNameList(),
                serverHostKeyAlgorithms = reader.readNameList(),
                encryptionClientToServer = reader.readNameList(),
                encryptionServerToClient = reader.readNameList(),
                macClientToServer = reader.readNameList(),
                macServerToClient = reader.readNameList(),
                compressionClientToServer = reader.readNameList(),
                compressionServerToClient = reader.readNameList(),
                languagesClientToServer = reader.readNameList(),
                languagesServerToClient = reader.readNameList(),
                firstKexPacketFollows = if (reader.remaining > 0) reader.readBoolean() else false
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is KexInit) return false
        return kexAlgorithms == other.kexAlgorithms &&
            serverHostKeyAlgorithms == other.serverHostKeyAlgorithms &&
            encryptionClientToServer == other.encryptionClientToServer
    }

    override fun hashCode(): Int = kexAlgorithms.hashCode()
}

/**
 * Negotiates algorithms between client and server KEXINIT messages.
 * Per RFC 4253 §7.1: first algorithm in the client's list that the
 * server also supports wins.
 */
data class NegotiatedAlgorithms(
    val kex: String,
    val hostKey: String,
    val cipherC2S: String,
    val cipherS2C: String,
    val macC2S: String,
    val macS2C: String,
    val compressionC2S: String,
    val compressionS2C: String
)

fun negotiateAlgorithms(client: KexInit, server: KexInit): NegotiatedAlgorithms {
    fun negotiate(clientList: List<String>, serverList: List<String>, what: String): String {
        return clientList.firstOrNull { it in serverList }
            ?: throw SshProtocolException(
                "No common $what algorithm. Client: $clientList, Server: $serverList"
            )
    }

    val cipherC2S = negotiate(client.encryptionClientToServer, server.encryptionClientToServer, "encryption (c→s)")
    val cipherS2C = negotiate(client.encryptionServerToClient, server.encryptionServerToClient, "encryption (s→c)")

    // MAC is only needed for non-AEAD ciphers
    val cipherC2SAlgo = CipherRegistry.byName(cipherC2S)
    val cipherS2CAlgo = CipherRegistry.byName(cipherS2C)
    val macC2S = if (cipherC2SAlgo?.isAead == true) "none"
        else negotiate(client.macClientToServer, server.macClientToServer, "MAC (c→s)")
    val macS2C = if (cipherS2CAlgo?.isAead == true) "none"
        else negotiate(client.macServerToClient, server.macServerToClient, "MAC (s→c)")

    return NegotiatedAlgorithms(
        kex = negotiate(client.kexAlgorithms, server.kexAlgorithms, "key exchange"),
        hostKey = negotiate(client.serverHostKeyAlgorithms, server.serverHostKeyAlgorithms, "host key"),
        cipherC2S = cipherC2S,
        cipherS2C = cipherS2C,
        macC2S = macC2S,
        macS2C = macS2C,
        compressionC2S = negotiate(client.compressionClientToServer, server.compressionClientToServer, "compression (c→s)"),
        compressionS2C = negotiate(client.compressionServerToClient, server.compressionServerToClient, "compression (s→c)")
    )
}
