package de.arcan.arcshell.ssh

/** SSH protocol message type constants (RFC 4250, 4252, 4253, 4254). */
object SshMsgType {
    // Transport layer (RFC 4253)
    const val DISCONNECT = 1
    const val IGNORE = 2
    const val UNIMPLEMENTED = 3
    const val DEBUG = 4
    const val SERVICE_REQUEST = 5
    const val SERVICE_ACCEPT = 6

    // Key exchange (RFC 4253)
    const val KEXINIT = 20
    const val NEWKEYS = 21

    // Diffie-Hellman / ECDH (RFC 4253 §8, RFC 5656)
    const val KEXDH_INIT = 30
    const val KEXDH_REPLY = 31

    // User authentication (RFC 4252)
    const val USERAUTH_REQUEST = 50
    const val USERAUTH_FAILURE = 51
    const val USERAUTH_SUCCESS = 52
    const val USERAUTH_BANNER = 53
    const val USERAUTH_PK_OK = 60
    const val USERAUTH_INFO_REQUEST = 60
    const val USERAUTH_INFO_RESPONSE = 61

    // Connection protocol (RFC 4254)
    const val GLOBAL_REQUEST = 80
    const val REQUEST_SUCCESS = 81
    const val REQUEST_FAILURE = 82
    const val CHANNEL_OPEN = 90
    const val CHANNEL_OPEN_CONFIRMATION = 91
    const val CHANNEL_OPEN_FAILURE = 92
    const val CHANNEL_WINDOW_ADJUST = 93
    const val CHANNEL_DATA = 94
    const val CHANNEL_EXTENDED_DATA = 95
    const val CHANNEL_EOF = 96
    const val CHANNEL_CLOSE = 97
    const val CHANNEL_REQUEST = 98
    const val CHANNEL_SUCCESS = 99
    const val CHANNEL_FAILURE = 100
}

/** SSH disconnect reason codes (RFC 4253 §11.1). */
object SshDisconnectReason {
    const val HOST_NOT_ALLOWED_TO_CONNECT = 1
    const val PROTOCOL_ERROR = 2
    const val KEY_EXCHANGE_FAILED = 3
    const val RESERVED = 4
    const val MAC_ERROR = 5
    const val COMPRESSION_ERROR = 6
    const val SERVICE_NOT_AVAILABLE = 7
    const val PROTOCOL_VERSION_NOT_SUPPORTED = 8
    const val HOST_KEY_NOT_VERIFIABLE = 9
    const val CONNECTION_LOST = 10
    const val BY_APPLICATION = 11
    const val TOO_MANY_CONNECTIONS = 12
    const val AUTH_CANCELLED_BY_USER = 13
    const val NO_MORE_AUTH_METHODS_AVAILABLE = 14
    const val ILLEGAL_USER_NAME = 15
}

/** SSH channel open failure reason codes (RFC 4254 §5.1). */
object SshChannelOpenFailure {
    const val ADMINISTRATIVELY_PROHIBITED = 1
    const val CONNECT_FAILED = 2
    const val UNKNOWN_CHANNEL_TYPE = 3
    const val RESOURCE_SHORTAGE = 4
}

/** Well-known SSH service names. */
object SshService {
    const val USERAUTH = "ssh-userauth"
    const val CONNECTION = "ssh-connection"
}

/** Protocol version identification string. */
const val SSH_VERSION_STRING = "SSH-2.0-ArcShell_1.0"
