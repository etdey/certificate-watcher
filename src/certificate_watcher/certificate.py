"""
Module to validate SSL/TLS certificates details from an SSL/TLS socket.

Copyright (c) 2026 Eric Dey. All rights reserved.
"""

import datetime
import socket
import ssl
from dataclasses import dataclass
from pprint import pprint

import cryptography.x509

import certificate_watcher.starttls as cw_starttls


@dataclass
class CertificateSummary:
    host: str
    port: int
    subject: str
    issuer: str
    not_before: datetime.datetime
    not_after: datetime.datetime
    time_since_valid: datetime.timedelta
    time_until_expiration: datetime.timedelta
    san: list[str]
    validated: bool = False
    cw_id: str = ""
    cw_description: str = ""
    cw_starttls: str = ""


def create_ssl_context(strict: bool = True) -> ssl.SSLContext:
    """Creates an SSL context for connecting to a TLS server.

    Args:
        strict (bool): Whether to validate the peer's CA chain, signature,
            and hostname. When False, an unverified context is returned so
            only the certificate summary can be retrieved. Defaults to True.

    Returns:
        ssl.SSLContext: The configured SSL context.
    """
    if strict:
        return ssl.create_default_context()
    return ssl._create_unverified_context()


def _connect_tls(host: str, port: int, starttls: str | None = None, strict: bool = True) -> ssl.SSLSocket:
    """Opens a TLS connection to the given host and port, optionally via STARTTLS.

    Args:
        host (str): The remote host name or IP address to connect to.
        port (int): The remote port number to connect to.
        starttls (str | None): The STARTTLS protocol to use (e.g. "smtp", "imap"),
            or None for a direct TLS connection. Defaults to None.
        strict (bool): Whether to validate the CA chain, signature, and
            hostname of the peer certificate. When False, the connection
            succeeds regardless of trust or hostname mismatches, and only
            the certificate summary information is available. Defaults to True.

    Returns:
        ssl.SSLSocket: The established SSL socket.
    """
    context = create_ssl_context(strict)
    sock = socket.create_connection((host, port))
    if starttls is not None:
        return cw_starttls.starttls(sock, starttls, context, remote_host=host)
    return context.wrap_socket(sock, server_hostname=host)


def get_certificate(host: str, port: int, starttls: str | None = None, strict: bool = True, today: datetime.datetime | None = None) -> CertificateSummary:
    """Connects to a host/port and extracts a summary of its SSL/TLS certificate.

    Args:
        host (str): The remote host name or IP address to connect to.
        port (int): The remote port number to connect to.
        starttls (str | None): The STARTTLS protocol to use (e.g. "smtp", "imap"),
            or None for a direct TLS connection. Defaults to None.
        strict (bool): Whether to validate the CA chain, signature, and hostname
            of the peer certificate. Defaults to True.
        today (datetime.datetime | None): The current date and time to use for
            comparisons. Defaults to None, which means the current system time
            will be used.

    Returns:
        CertificateSummary: A summary of the certificate details.
    """
    if not isinstance(today, datetime.datetime):
        today = datetime.datetime.now(datetime.timezone.utc)

    with _connect_tls(host, port, starttls=starttls, strict=strict) as ssl_socket:
        der_cert = ssl_socket.getpeercert(binary_form=True)
        if not der_cert:
            raise ValueError("No certificate found.")

        cert = cryptography.x509.load_der_x509_certificate(der_cert)

        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        san = []
        try:
            san_extension = cert.extensions.get_extension_for_class(cryptography.x509.SubjectAlternativeName)
            san = [str(san) for san in san_extension.value]
        except cryptography.x509.ExtensionNotFound:
            san = []

        return CertificateSummary(
            host = host,
            port = port,
            subject = subject,
            issuer = issuer,
            not_before = not_before,
            not_after = not_after,
            time_since_valid = today - not_before,
            time_until_expiration = not_after - today,
            san = san,
            validated = strict,
        )
