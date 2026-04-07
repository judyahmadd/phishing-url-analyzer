"""
SSL Certificate Check
Examines the SSL/TLS certificate:
- Certificate validity
- Issuer information
- Expiration status
- Self-signed detection
"""

import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime, timezone


def check_ssl_certificate(url: str) -> dict:
    """Analyze SSL certificate for phishing indicators."""

    findings = []
    risk_points = 0
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    port = parsed.port or 443

    if parsed.scheme != "https":
        return {
            "check": "SSL Certificate",
            "findings": ["Site does not use HTTPS — no certificate to check"],
            "risk_points": 20,
        }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:
                cert = tls.getpeercert()

    except ssl.SSLCertVerificationError as e:
        findings.append(f"SSL verification FAILED: {str(e)[:100]}")
        risk_points += 30
        return {
            "check": "SSL Certificate",
            "findings": findings,
            "risk_points": risk_points,
        }
    except Exception as e:
        findings.append(f"Could not connect: {str(e)[:100]}")
        risk_points += 15
        return {
            "check": "SSL Certificate",
            "findings": findings,
            "risk_points": risk_points,
        }

    # --- Check 1: Certificate issuer ---
    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
    issuer_org = issuer_dict.get("organizationName", "Unknown")
    issuer_cn = issuer_dict.get("commonName", "Unknown")
    findings.append(f"Issuer: {issuer_org} ({issuer_cn})")

    # Free/automated CAs (not inherently bad, but common with phishing)
    free_cas = ["Let's Encrypt", "ZeroSSL", "Buypass"]
    if any(ca.lower() in issuer_org.lower() for ca in free_cas):
        findings.append("Uses free/automated CA — common with phishing sites")
        risk_points += 5

    # --- Check 2: Certificate expiration ---
    not_after = cert.get("notAfter", "")
    if not_after:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        expiry = expiry.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_left = (expiry - now).days

        if days_left < 0:
            findings.append(f"Certificate EXPIRED {abs(days_left)} days ago!")
            risk_points += 25
        elif days_left < 14:
            findings.append(f"Certificate expires in {days_left} days")
            risk_points += 10
        else:
            findings.append(f"Certificate valid for {days_left} more days")

    # --- Check 3: Certificate age (short-lived = suspicious) ---
    not_before = cert.get("notBefore", "")
    if not_before and not_after:
        issued = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        cert_lifespan = (expiry - issued).days

        if cert_lifespan <= 90:
            findings.append(f"Short certificate lifespan ({cert_lifespan} days)")
            risk_points += 5

    # --- Check 4: Subject Alternative Names ---
    san_list = cert.get("subjectAltName", [])
    san_domains = [val for typ, val in san_list if typ == "DNS"]

    if len(san_domains) > 10:
        findings.append(f"Certificate covers {len(san_domains)} domains — unusual")
        risk_points += 10
    elif san_domains:
        findings.append(f"Certificate covers: {', '.join(san_domains[:5])}")

    if not findings:
        findings.append("SSL certificate appears valid")

    return {
        "check": "SSL Certificate",
        "findings": findings,
        "risk_points": min(risk_points, 100),
    }
