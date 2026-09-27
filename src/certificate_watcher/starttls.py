"""
Module for handling STARTTLS connections for different application protocols.

Copyright (c) 2026 Eric Dey. All rights reserved.
"""

import imaplib
import smtplib
import socket
import ssl


PROTOCOLS = ["smtp", "imap"]


def starttls(sock: socket.socket, protocol: str, context: ssl.SSLContext,
             remote_host: str | None = None) -> ssl.SSLSocket:
    """Initiates a STARTTLS handshake for the given protocol over the provided socket.

    Args:
        sock (socket.socket): The raw socket to wrap with STARTTLS.
        protocol (str): The protocol to use ("smtp" or "imap").
        context (ssl.SSLContext): The SSL context to use for the handshake.
        remote_host (str | None, optional): The remote host name for the connection. Defaults to None.

    Returns:
        ssl.SSLSocket: The SSL-wrapped socket after successful STARTTLS handshake.

    Raises:
        ValueError: If the protocol or socket family is unsupported.
        ssl.SSLError: If the STARTTLS handshake fails due to SSL issues.
    """
    if protocol not in PROTOCOLS:
        raise ValueError(f"Unsupported protocol: {protocol}")
    _handler = {
        "smtp": _smtp_starttls,
        "imap": _imap_starttls,
    }

    if sock.family not in (socket.AF_INET, socket.AF_INET6):
        raise ValueError(f"Unsupported socket family: {sock.family}")

    return _handler[protocol](sock, context, remote_host)


def _smtp_starttls(sock: socket.socket, context: ssl.SSLContext, host: str | None = None) -> ssl.SSLSocket:
    """uses raw socket to initiate SMTP session and perform STARTTLS handshake."""
    smtp_client = smtplib.SMTP()  # instantiate SMTP without connecting

    # Used provided remote host name or else fall back to the socket's peer name
    if not host:
        host = sock.getpeername()[0]

    # get the local host IP and name for this socket
    (local_ip, local_port) = sock.getsockname()
    local_hostname = socket.getfqdn(local_ip)

    # perform the post-connection setup done by smtplib.SMTP.connect()
    smtp_client.sock = sock
    setattr(smtp_client, "_host", host)
    smtp_client.local_hostname = local_hostname

    # read the server's initial greeting message
    code, message = smtp_client.getreply()
    if code != 220:
        raise smtplib.SMTPConnectError(code, message)

    # start extended SMTP session; required before initiating STARTTLS
    (code, msg) = smtp_client.ehlo()

    # initiate STARTTLS handshake; may raise exceptions depending upon
    # if the strict server verification is enabled by the SSLContext
    smtp_client.starttls(context=context)

    assert isinstance(smtp_client.sock, ssl.SSLSocket)  # ensure the socket is now an SSL socket
    return smtp_client.sock


def _imap_starttls(sock: socket.socket, context: ssl.SSLContext, host: str | None = None) -> ssl.SSLSocket:
    """uses raw socket to initiate IMAP session and perform STARTTLS handshake."""
    resolved_host: str = host or str(sock.getpeername()[0])

    class _ConnectedIMAP(imaplib.IMAP4):
        def _create_socket(self, timeout: float | None = None) -> socket.socket:
            return sock

    imap_client = _ConnectedIMAP(host=resolved_host)

    # initiate STARTTLS handshake; imaplib handles capability negotiation
    # and refreshes capabilities after TLS is established
    imap_client.starttls(ssl_context=context)

    assert isinstance(imap_client.sock, ssl.SSLSocket)  # ensure the socket is now an SSL socket
    return imap_client.sock
