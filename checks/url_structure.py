"""
URL Structure Analysis
Examines the URL itself for phishing indicators:
- Excessive length
- IP address instead of domain
- Suspicious characters (@, --, encoded chars)
- Too many subdomains
- Suspicious TLDs
"""

import re
from urllib.parse import urlparse, unquote


SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs often abused
    ".buzz", ".top", ".xyz", ".club", ".work",
    ".loan", ".click", ".link", ".info", ".online",
]

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "secure",
    "update", "confirm", "banking", "password", "credential",
    "suspend", "alert", "urgent", "expire", "wallet",
]


def check_url_structure(url: str) -> dict:
    """Analyze URL structure for phishing indicators."""

    findings = []
    risk_points = 0
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = unquote(parsed.path).lower()
    full_url = unquote(url).lower()

    # --- Check 1: URL length ---
    if len(url) > 100:
        findings.append(f"Unusually long URL ({len(url)} characters)")
        risk_points += 10
    if len(url) > 200:
        findings.append("Extremely long URL — strong phishing indicator")
        risk_points += 15

    # --- Check 2: IP address instead of domain ---
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_pattern.match(hostname):
        findings.append(f"Uses IP address instead of domain: {hostname}")
        risk_points += 25

    # --- Check 3: @ symbol in URL (used to trick browsers) ---
    if "@" in url:
        findings.append("Contains '@' symbol — can be used to mislead users")
        risk_points += 20

    # --- Check 4: Excessive subdomains ---
    subdomain_count = len(hostname.split(".")) - 2
    if subdomain_count > 2:
        findings.append(f"Excessive subdomains ({subdomain_count}) — may hide real domain")
        risk_points += 15

    # --- Check 5: Suspicious TLD ---
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            findings.append(f"Suspicious TLD: {tld}")
            risk_points += 10
            break

    # --- Check 6: Suspicious keywords in URL ---
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
    if found_keywords:
        findings.append(f"Suspicious keywords found: {', '.join(found_keywords)}")
        risk_points += 5 * len(found_keywords)

    # --- Check 7: Multiple hyphens in domain ---
    if hostname.count("-") >= 3:
        findings.append(f"Multiple hyphens in domain ({hostname.count('-')})")
        risk_points += 10

    # --- Check 8: Homoglyph / punycode detection ---
    if hostname.startswith("xn--"):
        findings.append("Punycode (internationalized) domain — possible homoglyph attack")
        risk_points += 20

    # --- Check 9: Encoded characters in path ---
    if "%" in parsed.path:
        encoded_chars = re.findall(r"%[0-9a-fA-F]{2}", parsed.path)
        if len(encoded_chars) > 3:
            findings.append(f"Excessive URL encoding ({len(encoded_chars)} encoded chars)")
            risk_points += 10

    # --- Check 10: HTTPS check ---
    if parsed.scheme != "https":
        findings.append("Not using HTTPS")
        risk_points += 10

    if not findings:
        findings.append("No structural anomalies detected")

    return {
        "check": "URL Structure Analysis",
        "findings": findings,
        "risk_points": min(risk_points, 100),
    }
