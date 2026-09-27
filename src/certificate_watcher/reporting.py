"""
Reporting module for the certificate watcher.
"""

import smtplib
from argparse import Namespace
from email.message import EmailMessage
from email.utils import formataddr, formatdate

from certificate_watcher.config import AppConfig


def _send_email_report(options: Namespace, cw_config: AppConfig, output_groups) -> None:
    ordered_groups = (
        ("critical", "🟥"),
        ("warning", "🟨"),
        ("good", "🟩"),
    )
    subject_marker = next(
        (marker for group, marker in ordered_groups if output_groups.get(group)),
        None,
    )
    if subject_marker is None:
        return

    blocks = []
    for group, marker in ordered_groups:
        for cert in output_groups.get(group, []):
            starttls = f" (starttls: {cert.cw_starttls})" if cert.cw_starttls else ""
            blocks.append(
                "\n".join(
                    (
                        f"{marker} Certificate for {cert.host}:{cert.port}{starttls}",
                        f"\tDescription: {cert.cw_description}",
                        f"\tSubject: {cert.subject}",
                        f"\tStarted: {cert.time_since_valid.days} days ago",
                        f"\tExpires: {cert.not_after}, ({cert.time_until_expiration.days} days left)",
                    )
                )
            )
    body = "\n\n".join(blocks)

    email_destinations = [
        destination
        for destination in cw_config.notifications.destinations
        if destination.type == "email"
    ]
    if not email_destinations:
        return

    mailhost = cw_config.notifications.mailhost
    if mailhost is None:
        raise ValueError("email notifications require notifications.source.email.mailhost.host")

    with smtplib.SMTP(mailhost.host, mailhost.port) as smtp:
        if mailhost.user is not None:
            smtp.login(mailhost.user, mailhost.password or "")

        for destination in email_destinations:
            message = EmailMessage()
            message["From"] = formataddr((destination.from_name, destination.from_address))
            message["To"] = formataddr((destination.to_name, destination.to_address))
            message["Subject"] = f"SSL/TLS Certificate Watcher Report {subject_marker}"
            message["Date"] = formatdate(localtime=True)
            if len(output_groups.get("critical", [])) > 0:
                message["Importance"] = "high"
            message["Content-Type"] = "text/plain; charset=utf-8"
            message.set_content(body, charset="utf-8")
            smtp.send_message(message)


def send_reports(options: Namespace, cw_config: AppConfig, good_certs, warn_certs, crit_certs) -> None:

    output_groups = {
        'good': [],
        'warning': [],
        'critical': []
    }
    if 'good' in options.report:
        output_groups['good'] = good_certs
    if 'warning' in options.report:
        output_groups['warning'] = warn_certs
    if 'critical' in options.report:
        output_groups['critical'] = crit_certs

    reporting_types = set()
    for nd in cw_config.notifications.destinations:
        reporting_types.add(nd.type)

    if 'email' in reporting_types:
        _send_email_report(options, cw_config, output_groups)
