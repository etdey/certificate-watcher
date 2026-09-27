"""
Tests for the configuration loading and parsing module.

Copyright (c) 2026 Eric Dey. All rights reserved.
"""

import io
from textwrap import dedent
import unittest
from typing import Any, cast

from certificate_watcher.config import (
	AlertConfig,
	EmailNotification,
	MailhostConfig,
	WatchTarget,
	read_config,
)


def _dedent_yaml(text):
	return dedent(text.replace("\t", "    "))


def _yaml_stream(text):
	return io.StringIO(_dedent_yaml(text))


class ReadConfigTests(unittest.TestCase):
	def test_reads_yaml_text(self):
		config = read_config("watch: []")

		self.assertEqual(config.watch, [])
		self.assertEqual(config.alerts, AlertConfig())

	def test_reads_file_like_object(self):
		config = read_config(io.StringIO("watch: []"))

		self.assertEqual(config.watch, [])

	def test_rejects_non_mapping_yaml(self):
		for yaml_text in ("- item", "scalar"):
			with self.subTest(yaml_text=yaml_text):
				with self.assertRaisesRegex(ValueError, "YAML mapping"):
					read_config(yaml_text)

	def test_rejects_unsupported_source_type(self):
		with self.assertRaisesRegex(TypeError, "source must be"):
			read_config(cast(Any, 42))


class ParseConfigTests(unittest.TestCase):
	def test_parses_watch_targets_and_optional_fields(self):
		config = read_config(_yaml_stream(
			"""
			watch:
			  - id: mail
				host: mail.example.com
				port: 587
				description: Outbound mail
				starttls: smtp
				unsafe_validation: true
			  - id: web
				host: www.example.com
				port: 443
			"""
		))

		self.assertEqual(
			config.watch,
			[
				WatchTarget(
					id="mail",
					host="mail.example.com",
					port=587,
					description="Outbound mail",
					starttls="smtp",
					strict=True,
				),
				WatchTarget(id="web", host="www.example.com", port=443),
			],
		)

	def test_empty_or_missing_watch_section_defaults_to_empty_list(self):
		for yaml_text in ("{}", "watch: []"):
			with self.subTest(yaml_text=yaml_text):
				self.assertEqual(read_config(yaml_text).watch, [])

	def test_watch_entry_missing_required_field_raises_value_error(self):
		for entry, field in (
			("watch:\n  - host: example.com\n    port: 443", "id"),
			("watch:\n  - id: web\n    port: 443", "host"),
			("watch:\n  - id: web\n    host: example.com", "port"),
		):
			with self.subTest(field=field):
				with self.assertRaisesRegex(ValueError, field):
					read_config(entry)

	def test_missing_id_error_includes_watch_entry_index(self):
		with self.assertRaisesRegex(ValueError, r"watch entry 0"):
			read_config("watch:\n  - host: example.com\n    port: 443")

	def test_alert_defaults_and_explicit_values(self):
		self.assertEqual(read_config("{}").alerts, AlertConfig(30, 10))
		self.assertEqual(
			read_config("config:\n  warning_days: 45").alerts,
			AlertConfig(45, 10),
		)
		self.assertEqual(
			read_config("config:\n  critical_days: 7").alerts,
			AlertConfig(30, 7),
		)
		self.assertEqual(
			read_config("config:\n  warning_days: 60\n  critical_days: 15").alerts,
			AlertConfig(60, 15),
		)

	def test_warning_days_must_exceed_critical_days(self):
		for warning_days, critical_days in ((10, 10), (9, 10)):
			with self.subTest(warning_days=warning_days, critical_days=critical_days):
				with self.assertRaisesRegex(ValueError, "warning_days"):
					read_config(
						f"config:\n  warning_days: {warning_days}\n"
						f"  critical_days: {critical_days}"
					)

	def test_parses_email_notification_and_mailhost(self):
		config = read_config(_yaml_stream(
			"""
			notifications:
			  source:
				email:
				  address: alerts@example.com
				  from: Certificate Watcher
				  mailhost:
					host: smtp.example.com
					port: 587
					user: watcher
					password: secret
			  destinations:
				- type: email
				  address: ops@example.com
				  to: Operations
			"""
		))

		self.assertEqual(
			config.notifications.destinations,
			[
				EmailNotification(
					type="email",
					from_address="alerts@example.com",
					from_name="Certificate Watcher",
					to_address="ops@example.com",
					to_name="Operations",
				)
			],
		)
		self.assertEqual(
			config.notifications.mailhost,
			MailhostConfig(
				host="smtp.example.com",
				port=587,
				user="watcher",
				password="secret",
			),
		)

	def test_multiple_destinations_share_email_source(self):
		config = read_config(_yaml_stream(
			"""
			notifications:
			  source:
				email:
				  address: alerts@example.com
				  mailhost:
					host: smtp.example.com
			  destinations:
				- type: email
				  address: ops@example.com
				- type: email
				  address: admin@example.com
			"""
		))

		self.assertEqual(
			[item.from_address for item in config.notifications.destinations],
			["alerts@example.com", "alerts@example.com"],
		)
		self.assertEqual(
			[item.to_address for item in config.notifications.destinations],
			["ops@example.com", "admin@example.com"],
		)
		self.assertEqual(
			[(item.from_name, item.to_name) for item in config.notifications.destinations],
			[("", ""), ("", "")],
		)

	def test_empty_or_missing_notifications_defaults_to_empty(self):
		for yaml_text in ("{}", "notifications: {}"):
			with self.subTest(yaml_text=yaml_text):
				notifications = read_config(yaml_text).notifications
				self.assertEqual(notifications.destinations, [])
				self.assertIsNone(notifications.mailhost)

	def test_rejects_unsupported_destination_type(self):
		with self.assertRaisesRegex(ValueError, "unsupported notification type"):
			read_config("notifications:\n  destinations:\n    - type: sms")

	def test_rejects_destination_without_matching_source(self):
		with self.assertRaisesRegex(ValueError, "no matching.*source.email"):
			read_config(
				"notifications:\n  destinations:\n"
				"    - type: email\n      address: ops@example.com"
			)

	def test_requires_source_and_destination_addresses(self):
		source_without_address = _dedent_yaml("""
			notifications:
			  source:
				email:
				  mailhost:
					host: smtp.example.com
			  destinations:
				- type: email
				  address: ops@example.com
			""")
		destination_without_address = _dedent_yaml("""
			notifications:
			  source:
				email:
				  address: alerts@example.com
				  mailhost:
					host: smtp.example.com
			  destinations:
				- type: email
			""")

		with self.assertRaisesRegex(ValueError, "source.email.*address"):
			read_config(io.StringIO(source_without_address))
		with self.assertRaisesRegex(ValueError, "destination 0.*address"):
			read_config(io.StringIO(destination_without_address))

	def test_email_destinations_require_mailhost_host(self):
		for mailhost in ("mailhost: {}", "mailhost:\n                    port: 587"):
			with self.subTest(mailhost=mailhost):
				yaml_text = (
					"notifications:\n  source:\n    email:\n"
					"      address: alerts@example.com\n      "
					+ mailhost
					+ "\n  destinations:\n    - type: email\n"
					"      address: ops@example.com"
				)
				with self.assertRaisesRegex(ValueError, "mailhost.*host"):
					read_config(io.StringIO(yaml_text))

	def test_mailhost_defaults_port_and_retains_user_without_password(self):
		config = read_config(_yaml_stream(
			"""
			notifications:
			  source:
				email:
				  address: alerts@example.com
				  mailhost:
					host: smtp.example.com
					user: watcher
			  destinations:
				- type: email
				  address: ops@example.com
			"""
		))

		mailhost = config.notifications.mailhost
		if mailhost is None:
			self.fail("expected email mailhost configuration")
		self.assertEqual(mailhost, MailhostConfig(host="smtp.example.com", user="watcher"))
		self.assertIsNone(mailhost.password)


if __name__ == "__main__":
	unittest.main()
