"""
Command-line interface for the certificate watcher.
"""

import argparse
import sys
from pprint import pprint

import certificate_watcher.checker as cw_checker
import certificate_watcher.config as cw_config


def report(options: argparse.Namespace, good_certs, warn_certs, crit_certs) -> None:

    groups = [
        ('Critical Certificates', crit_certs),
        ('Warning Certificates', warn_certs),
        ('Good Certificates', good_certs),
    ]

    for group_name, certs in groups:
        if len(certs) == 0:
            continue

        print(f"\n{group_name}:")
        for cert in certs:
            print(f"  Certificate for {cert.host}:{cert.port}{' (starttls: ' + cert.cw_starttls + ')' if cert.cw_starttls else ''}")
            print(f"    Description: {cert.cw_description}")
            print(f"    Subject: {cert.subject}")
            print(f"    Started: {cert.time_since_valid.days} days ago")
            print(f"    Expires: {cert.not_after}, ({cert.time_until_expiration.days} days left)")
            print()


def main() -> int:
    description = """Watch SSL certificates for expiration."""
    epilog = """"""

    parser = argparse.ArgumentParser(description=description, epilog=epilog)

    # global options
    parser.add_argument("--config", "-c", metavar="FILE", help="YAML configuration file")

    options = parser.parse_args()

    cert_config = None
    if options.config:
        cert_config = cw_config.read_config(options.config)

    if not cert_config:
        print("No configuration provided.")
        return 1

    good_certs, warn_certs, crit_certs = cw_checker.check_endpoints(options, cert_config)

    report(options, good_certs, warn_certs, crit_certs)

    return 0


if __name__ == "__main__":
    sys.exit(main())