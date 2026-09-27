"""
Tests for the certificate module of the certificate watcher.

Copyright (c) 2026 Eric Dey. All rights reserved.
"""


import datetime
import unittest
from unittest.mock import Mock, patch

from certificate_watcher import certificate
from certificate_watcher.certificate import (
	CertificateSummary,
	_connect_tls,
	create_ssl_context,
	get_certificate,
)


class _FakeName:
	def __init__(self, rendered):
		self.rendered = rendered

	def rfc4514_string(self):
		return self.rendered


class _FakeAlternativeName:
	def __init__(self, rendered):
		self.rendered = rendered

	def __str__(self):
		return self.rendered


class CreateSslContextTests(unittest.TestCase):
	def test_strict_mode_uses_default_context(self):
		expected_context = object()
		with (
			patch.object(certificate.ssl, "create_default_context", return_value=expected_context) as default_context,
			patch.object(certificate.ssl, "_create_unverified_context") as unverified_context,
		):
			result = create_ssl_context(strict=True)

		self.assertIs(result, expected_context)
		default_context.assert_called_once_with()
		unverified_context.assert_not_called()

	def test_non_strict_mode_uses_unverified_context(self):
		expected_context = object()
		with (
			patch.object(certificate.ssl, "create_default_context") as default_context,
			patch.object(certificate.ssl, "_create_unverified_context", return_value=expected_context) as unverified_context,
		):
			result = create_ssl_context(strict=False)

		self.assertIs(result, expected_context)
		default_context.assert_not_called()
		unverified_context.assert_called_once_with()


class ConnectTlsTests(unittest.TestCase):
	def test_direct_tls_connects_and_wraps_with_hostname(self):
		host = "mail.example.test"
		port = 465
		raw_socket = object()
		wrapped_socket = object()
		context = Mock()
		context.wrap_socket.return_value = wrapped_socket

		with (
			patch("certificate_watcher.certificate.create_ssl_context", return_value=context) as create_context,
			patch("certificate_watcher.certificate.socket.create_connection", return_value=raw_socket) as connect,
		):
			result = _connect_tls(host, port, strict=False)

		self.assertIs(result, wrapped_socket)
		create_context.assert_called_once_with(False)
		connect.assert_called_once_with((host, port))
		context.wrap_socket.assert_called_once_with(raw_socket, server_hostname=host)

	def test_starttls_delegates_without_direct_socket_wrapping(self):
		host = "mail.example.test"
		port = 587
		raw_socket = object()
		wrapped_socket = object()
		context = Mock()

		with (
			patch("certificate_watcher.certificate.create_ssl_context", return_value=context) as create_context,
			patch("certificate_watcher.certificate.socket.create_connection", return_value=raw_socket) as connect,
			patch("certificate_watcher.certificate.cw_starttls.starttls", return_value=wrapped_socket) as starttls,
		):
			result = _connect_tls(host, port, starttls="smtp", strict=True)

		self.assertIs(result, wrapped_socket)
		create_context.assert_called_once_with(True)
		connect.assert_called_once_with((host, port))
		starttls.assert_called_once_with(raw_socket, "smtp", context, remote_host=host)
		context.wrap_socket.assert_not_called()


class GetCertificateTests(unittest.TestCase):
	def setUp(self):
		self.host = "www.example.test"
		self.port = 443
		self.today = datetime.datetime(2026, 9, 27, tzinfo=datetime.timezone.utc)
		self.not_before = datetime.datetime(2026, 9, 1, tzinfo=datetime.timezone.utc)
		self.not_after = datetime.datetime(2026, 12, 1, tzinfo=datetime.timezone.utc)

	def _tls_connection(self, der_certificate):
		ssl_socket = Mock()
		ssl_socket.getpeercert.return_value = der_certificate
		connection = Mock()
		connection.__enter__ = Mock(return_value=ssl_socket)
		connection.__exit__ = Mock(return_value=False)
		return connection, ssl_socket

	def _parsed_certificate(self, extensions):
		return Mock(
			subject=_FakeName("CN=www.example.test"),
			issuer=_FakeName("CN=Example CA"),
			not_valid_before_utc=self.not_before,
			not_valid_after_utc=self.not_after,
			extensions=extensions,
		)

	def test_maps_certificate_fields_sans_and_validity_deltas(self):
		der_certificate = b"mock DER certificate"
		connection, ssl_socket = self._tls_connection(der_certificate)
		sans = [
			_FakeAlternativeName("<DNSName(value='www.example.test')>"),
			_FakeAlternativeName("<DNSName(value='api.example.test')>"),
		]
		extensions = Mock()
		extensions.get_extension_for_class.return_value.value = sans
		parsed_certificate = self._parsed_certificate(extensions)

		with (
			patch("certificate_watcher.certificate._connect_tls", return_value=connection) as connect_tls,
			patch(
				"certificate_watcher.certificate.cryptography.x509.load_der_x509_certificate",
				return_value=parsed_certificate,
			) as load_certificate,
		):
			result = get_certificate(
				self.host,
				self.port,
				starttls="smtp",
				strict=False,
				today=self.today,
			)

		self.assertEqual(
			result,
			CertificateSummary(
				host=self.host,
				port=self.port,
				subject="CN=www.example.test",
				issuer="CN=Example CA",
				not_before=self.not_before,
				not_after=self.not_after,
				time_since_valid=datetime.timedelta(days=26),
				time_until_expiration=datetime.timedelta(days=65),
				san=[str(san) for san in sans],
			),
		)
		self.assertEqual((result.cw_id, result.cw_description, result.cw_starttls), ("", "", ""))
		connect_tls.assert_called_once_with(
			self.host,
			self.port,
			starttls="smtp",
			strict=False,
		)
		ssl_socket.getpeercert.assert_called_once_with(binary_form=True)
		load_certificate.assert_called_once_with(der_certificate)
		extensions.get_extension_for_class.assert_called_once_with(
			certificate.cryptography.x509.SubjectAlternativeName
		)

	def test_missing_san_extension_results_in_empty_san_list(self):
		connection, _ = self._tls_connection(b"mock DER certificate")
		extensions = Mock()
		extensions.get_extension_for_class.side_effect = certificate.cryptography.x509.ExtensionNotFound(
			"SAN extension not found",
			certificate.cryptography.x509.ObjectIdentifier("2.5.29.17"),
		)
		parsed_certificate = self._parsed_certificate(extensions)

		with (
			patch("certificate_watcher.certificate._connect_tls", return_value=connection),
			patch(
				"certificate_watcher.certificate.cryptography.x509.load_der_x509_certificate",
				return_value=parsed_certificate,
			),
		):
			result = get_certificate(self.host, self.port, today=self.today)

		self.assertEqual(result.san, [])

	def test_empty_der_certificate_raises_before_parsing(self):
		connection, ssl_socket = self._tls_connection(b"")
		with (
			patch("certificate_watcher.certificate._connect_tls", return_value=connection),
			patch("certificate_watcher.certificate.cryptography.x509.load_der_x509_certificate") as load_certificate,
		):
			with self.assertRaisesRegex(ValueError, "No certificate found"):
				get_certificate(self.host, self.port, today=self.today)

		ssl_socket.getpeercert.assert_called_once_with(binary_form=True)
		load_certificate.assert_not_called()


if __name__ == "__main__":
	unittest.main()
