"""
Check and alerting for certificates
"""

from argparse import Namespace

import certificate_watcher.certificate as cw_certificate
import certificate_watcher.config as cw_config


# tuple of good, warning, and critical certificates
CertificateCheckResult = tuple[list[cw_certificate.CertificateSummary], list[cw_certificate.CertificateSummary], list[cw_certificate.CertificateSummary]]


def check_endpoints(options: Namespace, cert_config: cw_config.AppConfig) -> CertificateCheckResult:
    good_certs = []
    warn_certs = []
    crit_certs = []

    for watch in cert_config.watch:
        cert = cw_certificate.get_certificate(watch.host, watch.port, starttls=watch.starttls, strict=watch.strict)
        cert.cw_id = watch.id
        cert.cw_description = watch.description
        cert.cw_starttls = watch.starttls or ""

        if cert.time_since_valid.total_seconds() < 0:  # not yet valid
            crit_certs.append(cert)
        elif cert.time_until_expiration.days <= cert_config.alerts.critical_days:
            crit_certs.append(cert)
        elif cert.time_until_expiration.days <= cert_config.alerts.warning_days:
            warn_certs.append(cert)
        else:  # valid with sufficient time before expiration
            good_certs.append(cert)


    return good_certs, warn_certs, crit_certs