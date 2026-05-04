# arcshell-ssh

Pure Kotlin SSH-2 library built on BouncyCastle. No Android dependencies — runs on any JVM.

Used in production by [ArcShell](https://arcshell.app) — an SSH client for Android.

## Architecture

**NIO-based async I/O** with Kotlin coroutines. The library uses a single-threaded event loop
(`SshEventLoop`) backed by Java NIO `Selector` for non-blocking socket I/O. All SSH operations
(connect, auth, channel open, read/write) are `suspend` functions.

```
AsyncSshClient
  └── AsyncSshTransport (NIO socket, KEX, packet encryption)
        └── AsyncSshConnection (channel multiplexing)
              ├── AsyncSessionChannel (shell, exec, subsystem)
              ├── SftpClient (SFTP subsystem)
              └── Direct-TCP channels (port forwarding)
```

## Features

### Key Exchange
- **mlkem768x25519-sha512** — Post-quantum hybrid (ML-KEM-768 + X25519)
- curve25519-sha256 (RFC 8731)
- ecdh-sha2-nistp256/384/521 (RFC 5656)
- diffie-hellman-group16-sha512 (RFC 3526, 4096-bit)
- diffie-hellman-group14-sha256 (RFC 8268)

### Ciphers
- **chacha20-poly1305@openssh.com** — Preferred (no AES-NI needed)
- aes256-gcm@openssh.com / aes128-gcm@openssh.com (AEAD)
- aes256-ctr / aes128-ctr

### MACs (non-AEAD ciphers)
- hmac-sha2-256-etm@openssh.com / hmac-sha2-512-etm@openssh.com (Encrypt-then-MAC)
- hmac-sha2-256 / hmac-sha2-512

### Host Key Algorithms
- ssh-ed25519
- ecdsa-sha2-nistp256/384/521
- rsa-sha2-512 / rsa-sha2-256
- ssh-rsa (SHA-1, verify-only for legacy servers)

### Authentication
- Public key (Ed25519, RSA, ECDSA)
- Password
- Keyboard-interactive (multi-round challenge-response)

### Protocol
- SSH-2 transport (RFC 4253), authentication (RFC 4252), connection (RFC 4254)
- **Strict KEX** — Terrapin attack mitigation (CVE-2023-48795)
- Channel multiplexing (shell, exec, subsystem, direct-tcpip)
- SFTP subsystem (v3 protocol)
- Port forwarding (local, remote, dynamic)
- Keep-alive (`keepalive@openssh.com` / `SSH_MSG_IGNORE`)
- Shared `SecureRandom` instance (eliminates crypto cold-start delay)

## Usage

```kotlin
val config = SshConfig(
    hostname = "example.com",
    port = 22,
    username = "admin",
    connectTimeoutMs = 10_000
)

val client = AsyncSshClient(config, hostKeyVerifier)
client.connect()

// Authenticate
client.authPassword("secret")
// or: client.authPublicKey(keyType, publicKeyBlob, signer)

// Open shell
val session = client.openSession()
session.requestPty("xterm-256color", 80, 24)
session.requestShell()

// Read/write (suspend functions)
session.write("ls\n".toByteArray())
val output = session.read() // suspends until data available

// Exec (one-shot command)
val exec = client.openSession()
exec.requestExec("uptime")
val result = exec.read()

// SFTP
val sftp = SftpClient(client.openSession())
sftp.connect()
val files = sftp.listDirectory("/home/admin")
sftp.downloadFile("/remote/file.txt", outputStream)
sftp.close()

// Port forwarding
val forwarding = PortForwarding(
    type = ForwardType.LOCAL,
    bindPort = 8080,
    targetHost = "internal-db",
    targetPort = 5432
)
TunnelManager.activate(client, listOf(forwarding), "my-host", scope)

client.disconnect()
```

## Module Structure

```
ssh/
├── nio/                  — Async NIO client, transport, channels
│   ├── AsyncSshClient    — Top-level API, connect + auth + open channels
│   ├── AsyncSshTransport — NIO socket, KEX negotiation, packet encryption
│   ├── AsyncSshConnection — Channel multiplexing, window management
│   ├── AsyncSessionChannel — Shell, exec, subsystem channels
│   ├── AsyncPacketIO     — Packet framing, encryption, MAC
│   └── SshEventLoop      — NIO Selector event loop
├── transport/            — Crypto primitives
│   ├── CipherSuite       — Algorithm negotiation + instantiation
│   ├── KeyExchange       — DH, ECDH key exchange
│   ├── PostQuantumKex    — ML-KEM-768 hybrid KEX
│   ├── KexInit           — SSH_MSG_KEXINIT packet
│   ├── SshBuffer         — SSH wire format read/write
│   └── CryptoState       — Per-direction cipher + MAC state
├── auth/                 — Authentication types
├── sftp/                 — SFTP v3 client
├── service/              — TunnelManager for port forwarding
├── SshConfig.kt          — Connection configuration
├── SshConstants.kt       — SSH protocol constants
├── SshRandom.kt          — Shared SecureRandom
└── PortForwarding.kt     — Forwarding rules
```

## Dependencies

- **BouncyCastle 1.80** (`bcprov-jdk18on`, `bcpkix-jdk18on`)
- Kotlin Coroutines
- Kotlin stdlib

## Known Limitations

- No SSH certificate support (openssh-cert-v01@openssh.com) — planned for v1.4
- No agent forwarding — planned for v1.4
- No compression (not advertised)
- No GSSAPI/Kerberos authentication
- ssh-rsa (SHA-1) accepted for host key verification only

## Security

- All randomness via shared `java.security.SecureRandom` instance
- No hardcoded keys or secrets
- Strict KEX enabled by default (CVE-2023-48795)
- Post-quantum hybrid KEX protects against harvest-now-decrypt-later attacks
- Coroutine-safe packet I/O with Mutex

## License

Apache License 2.0 — see [LICENSE](LICENSE)

Copyright 2026 Arcan Consulting
