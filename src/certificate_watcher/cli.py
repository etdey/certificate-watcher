"""
Command-line interface for the certificate watcher.
"""

import argparse
import shlex
import sys

import certificate_watcher.checker as cw_checker
import certificate_watcher.config as cw_config
import certificate_watcher.reporting as cw_reporting


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


def main(argv: list[str] | None = None) -> int:
    if argv is None:  # launched directly from pyproject.toml scripts section
        argv = sys.argv

    description = """Watch SSL/TLS certificates for expiration."""
    epilog = """"""

    report_choices = ["good", "warning", "critical"]

    parser = argparse.ArgumentParser(description=description, epilog=epilog)

    # Special case handling for VSCode launch.json argsExpand option
    if len(argv) > 1 and argv[1] == '--argsExpand':
        argv.pop(1)  # remove --argsExpand
        if len(argv) > 1:  # still have args to expand
            additionalArgs = ' '.join(argv[1:])
            argv = argv[:1] + shlex.split(additionalArgs)

    # global options
    parser.add_argument("--config", "-c", metavar="FILE", help="YAML configuration file")
    parser.add_argument("--report", "-r", action="append", choices=report_choices, help="groups to report; multiples allowed (default: all groups)")

    options = parser.parse_args(argv[1:])

    cert_config = None
    if options.config:
        cert_config = cw_config.read_config(options.config)
        if not cert_config:
            print("No configuration provided.")
            return 1
    assert(cert_config is not None)

    if options.report is None or len(options.report) == 0:
        options.report = report_choices


    good_certs, warn_certs, crit_certs = cw_checker.check_endpoints(options, cert_config)

    # report(options, good_certs, warn_certs, crit_certs)
    cw_reporting.send_reports(options, cert_config, good_certs, warn_certs, crit_certs)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
