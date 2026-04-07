"""
Domain Information Check
Uses WHOIS data to analyze domain registration:
- Domain age (newly registered = red flag)
- Registrar info
- Expiration date
"""

from urllib.parse import urlparse
from datetime import datetime, timezone

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


def check_domain_info(url: str) -> dict:
    """Check domain WHOIS information for phishing indicators."""

    findings = []
    risk_points = 0
    parsed = urlparse(url)
    domain = parsed.hostname or ""

    if not WHOIS_AVAILABLE:
        return {
            "check": "Domain Information",
            "findings": ["python-whois not installed — skipping WHOIS check"],
            "risk_points": 0,
        }

    try:
        w = whois.whois(domain)
    except Exception as e:
        findings.append(f"WHOIS lookup failed: {str(e)[:80]}")
        risk_points += 10
        return {
            "check": "Domain Information",
            "findings": findings,
            "risk_points": risk_points,
        }

    # --- Check 1: Domain age ---
    creation_date = w.creation_date
    if isinstance(creation_date, list):
        creation_date = creation_date[0]

    if creation_date:
        now = datetime.now(timezone.utc)
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        age_days = (now - creation_date).days

        if age_days < 30:
            findings.append(f"Domain is only {age_days} days old — HIGH RISK")
            risk_points += 30
        elif age_days < 90:
            findings.append(f"Domain is {age_days} days old — relatively new")
            risk_points += 20
        elif age_days < 365:
            findings.append(f"Domain is {age_days} days old — less than a year")
            risk_points += 10
        else:
            years = age_days // 365
            findings.append(f"Domain age: {years} year(s) — established")
    else:
        findings.append("Creation date not available in WHOIS")
        risk_points += 5

    # --- Check 2: Registrar ---
    registrar = w.registrar
    if registrar:
        findings.append(f"Registrar: {registrar}")
    else:
        findings.append("Registrar information not available")

    # --- Check 3: Expiration date ---
    expiration_date = w.expiration_date
    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]

    if expiration_date:
        if expiration_date.tzinfo is None:
            expiration_date = expiration_date.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        days_until_expiry = (expiration_date - now).days

        if days_until_expiry < 30:
            findings.append(f"Domain expires in {days_until_expiry} days — suspicious")
            risk_points += 15
        elif days_until_expiry < 90:
            findings.append(f"Domain expires in {days_until_expiry} days")
            risk_points += 5
        else:
            findings.append(f"Domain expires in {days_until_expiry} days")

    # --- Check 4: Country ---
    country = w.country
    if country:
        findings.append(f"Registrant country: {country}")

    if not findings:
        findings.append("No domain anomalies detected")

    return {
        "check": "Domain Information",
        "findings": findings,
        "risk_points": min(risk_points, 100),
    }
