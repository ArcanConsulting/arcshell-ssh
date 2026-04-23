package de.arcan.arcshell.ssh.sftp

/**
 * Thrown when an SFTP operation fails with a non-OK status code.
 *
 * @param statusCode the SSH_FX_* status code from the server
 * @param message human-readable error description
 */
class SftpException(
    val statusCode: Int,
    message: String = SftpConstants.statusMessage(statusCode)
) : Exception("SFTP error $statusCode: $message")
