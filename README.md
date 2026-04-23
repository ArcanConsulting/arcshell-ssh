# arcshell-ssh

Pure Kotlin SSH-2 library built on BouncyCastle. No Android dependencies — runs on any JVM.

## Features

### Key Exchange
- **mlkem768x25519-sha512** — Post-quantum hybrid (ML-KEM-768 + X25519)
- curve25519-sha256 (RFC 8731)
- ecdh-sha2-nistp256/384/521 (RFC 5656)
- diffie-hellman-group16-sha512 (RFC 3526, 4096-bit)
- diffie-hellman-group18-sha512 (RFC 3526, 8192-bit)
- diffie-hellman-group14-sha256 (RFC 8268)

### Ciphers
- **chacha20-poly1305@openssh.com** — Preferred on mobile (no AES-NI needed)
- aes256-gcm@openssh.com / aes128-gcm@openssh.com (AEAD)
- aes256-ctr / aes192-ctr / aes128-ctr
- aes256-cbc / aes128-cbc (legacy fallback)

### MACs (non-AEAD)
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
- Keyboard-interactive (basic)

### Protocol
- SSH-2 transport (RFC 4253), authentication (RFC 4252), connection (RFC 4254)
- **Strict KEX** — Terrapin attack mitigation (CVE-2023-48795)
- SFTP subsystem (RFC 4251-compliant wire format)
- Channel multiplexing (shell, exec, subsystem, direct-tcpip)
- Keep-alive (`keepalive@openssh.com`)

## Usage

```kotlin
val config = SshConfig(
    hostname = "example.com",
    port = 22,
    username = "admin",
    connectTimeoutMs = 10_000
)

val client = SshClient(config, hostKeyVerifier)
client.connect()

// Authenticate
val methods = client.queryAuthMethods()
client.authPassword("secret")
// or: client.authPublicKey(keyType, publicKeyBlob, signer)

// Open shell
val session = client.openSession()
session.requestPty("xterm-256color", 80, 24)
session.requestShell()

// Start message loop (blocking, run on background thread)
Thread { client.processMessages() }.start()

// Read/write
session.write("ls\n".toByteArray())
val output = session.read() // blocks until data available

// SFTP
val sftp = SftpClient(client.openSession())
sftp.connect()
val files = sftp.listDirectory("/home/admin")
sftp.downloadFile("/remote/file.txt", outputStream)
sftp.close()

client.disconnect()
```

## Dependencies

- **BouncyCastle 1.77** (`bcprov-jdk18on`, `bcpkix-jdk18on`)
- Kotlin stdlib

## Known Limitations

- No SSH certificate support (openssh-cert-v01@openssh.com)
- No agent forwarding
- No compression (not advertised)
- No GSSAPI/Kerberos authentication
- Keyboard-interactive: basic single-prompt only
- ssh-rsa (SHA-1) accepted for host key verification only, not offered for client auth

## Security

- All randomness via `java.security.SecureRandom`
- No hardcoded keys or secrets
- Strict KEX enabled by default (CVE-2023-48795)
- Thread-safe packet I/O (synchronized read/write)
- Post-quantum hybrid KEX protects against harvest-now-decrypt-later attacks

## License

Apache License 2.0 — see [LICENSE](LICENSE)

Copyright 2026 Arcan Consulting
