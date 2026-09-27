"""
Tests for the certificate checking module.

Copyright (c) 2026 Eric Dey. All rights reserved.
"""

import datetime
import unittest
from argparse import Namespace
from unittest.mock import call, patch

from certificate_watcher.certificate import CertificateSummary
from certificate_watcher.checker import check_endpoints
from certificate_watcher.config import AlertConfig, AppConfig, WatchTarget


class CheckEndpointsTests(unittest.TestCase):
	@staticmethod
	def _certificate(host, days_until_expiration, time_since_valid=None):
		today = datetime.datetime(2026, 9, 27, tzinfo=datetime.timezone.utc)
		return CertificateSummary(
			host=host,
			port=443,
			subject=f"CN={host}",
			issuer="CN=Example CA",
			not_before=today,
			not_after=today + datetime.timedelta(days=days_until_expiration),
			time_since_valid=time_since_valid or datetime.timedelta(days=1),
			time_until_expiration=datetime.timedelta(days=days_until_expiration),
			san=[host],
		)

	def test_assigns_watch_metadata_and_classifies_expiration(self):
		watches = [
			WatchTarget(
				id="healthy",
				host="healthy.example.test",
				port=443,
				description="Healthy endpoint",
				strict=True,
			),
			WatchTarget(
				id="warning",
				host="warning.example.test",
				port=465,
				description="Warning endpoint",
				starttls="smtp",
			),
			WatchTarget(
				id="critical",
				host="critical.example.test",
				port=993,
				description="Critical endpoint",
				starttls="imap",
			),
			WatchTarget(
				id="not-yet-valid",
				host="future.example.test",
				port=443,
				description="Future endpoint",
			),
		]
		certificates = [
			self._certificate(watches[0].host, 21),
			self._certificate(watches[1].host, 20),
			self._certificate(watches[2].host, 5),
			self._certificate(
				watches[3].host,
				60,
				time_since_valid=datetime.timedelta(seconds=-1),
			),
		]
		config = AppConfig(
			watch=watches,
			alerts=AlertConfig(warning_days=20, critical_days=5),
		)

		with patch(
			"certificate_watcher.checker.cw_certificate.get_certificate",
			side_effect=certificates,
		) as get_certificate:
			good, warning, critical = check_endpoints(Namespace(), config)

		self.assertEqual(good, [certificates[0]])
		self.assertEqual(warning, [certificates[1]])
		self.assertEqual(critical, [certificates[2], certificates[3]])
		self.assertIs(critical[1], certificates[3])
		self.assertEqual(
			[
				(certificate.cw_id, certificate.cw_description, certificate.cw_starttls)
				for certificate in certificates
			],
			[
				("healthy", "Healthy endpoint", ""),
				("warning", "Warning endpoint", "smtp"),
				("critical", "Critical endpoint", "imap"),
				("not-yet-valid", "Future endpoint", ""),
			],
		)
		self.assertEqual(
			get_certificate.call_args_list,
			[
				call(
					watch.host,
					watch.port,
					starttls=watch.starttls,
					strict=watch.strict,
				)
				for watch in watches
			],
		)

	def test_empty_watch_list_returns_empty_groups_without_fetching(self):
		with patch("certificate_watcher.checker.cw_certificate.get_certificate") as get_certificate:
			result = check_endpoints(Namespace(), AppConfig())

		self.assertEqual(result, ([], [], []))
		get_certificate.assert_not_called()


if __name__ == "__main__":
	unittest.main()
