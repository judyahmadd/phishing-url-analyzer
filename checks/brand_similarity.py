"""
Brand Similarity Check
Detects typosquatting by comparing the domain against known brands:
- Levenshtein-like similarity using difflib
- Common substitution patterns (0 for o, 1 for l, etc.)
"""

from difflib import SequenceMatcher
from urllib.parse import urlparse


# Popular brands commonly targeted by phishing
TARGET_BRANDS = [
    "google", "facebook", "apple", "amazon", "microsoft",
    "paypal", "netflix", "instagram", "twitter", "linkedin",
    "dropbox", "github", "whatsapp", "telegram", "yahoo",
    "outlook", "office365", "icloud", "chase", "wellsfargo",
    "bankofamerica", "citibank", "coinbase", "binance", "metamask",
    "spotify", "adobe", "zoom", "slack", "steam",
]

# Common character substitutions used in typosquatting
SUBSTITUTIONS = {
    "o": ["0"],
    "l": ["1", "i"],
    "i": ["1", "l"],
    "e": ["3"],
    "a": ["@", "4"],
    "s": ["5", "$"],
    "g": ["9"],
}


def _similarity_ratio(a: str, b: str) -> float:
    """Calculate similarity ratio between two strings."""
    return SequenceMatcher(None, a, b).ratio()


def _check_substitutions(domain_part: str, brand: str) -> bool:
    """Check if domain uses common character substitutions of a brand."""
    if len(domain_part) != len(brand):
        return False

    diff_count = 0
    for d_char, b_char in zip(domain_part, brand):
        if d_char != b_char:
            subs = SUBSTITUTIONS.get(b_char, [])
            if d_char not in subs:
                return False
            diff_count += 1

    return 1 <= diff_count <= 3


def check_brand_similarity(url: str) -> dict:
    """Check if the URL domain mimics a known brand."""

    findings = []
    risk_points = 0
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # Extract the main domain part (without TLD)
    parts = hostname.split(".")
    # Check all parts AND hyphen-split sub-parts (e.g., g00gle-login → g00gle, login)
    domain_parts = set()
    for p in parts:
        if len(p) > 2:
            domain_parts.add(p)
        for sub in p.split("-"):
            if len(sub) > 2:
                domain_parts.add(sub)
    domain_parts = list(domain_parts)

    matches = []

    for part in domain_parts:
        for brand in TARGET_BRANDS:
            # Exact match in a subdomain (e.g., google.evil.com)
            if part == brand:
                # Only flag if it's NOT the actual brand's domain
                if not hostname.endswith(f"{brand}.com") and not hostname.endswith(f"{brand}.org"):
                    matches.append((brand, 1.0, "exact brand name in subdomain"))
                continue

            # Skip if the part IS the brand (legitimate site)
            if part == brand:
                continue

            # Character substitution check
            if _check_substitutions(part, brand):
                matches.append((brand, 0.95, "character substitution"))
                continue

            # Similarity check
            ratio = _similarity_ratio(part, brand)
            if ratio >= 0.80 and part != brand:
                matches.append((brand, ratio, "high similarity"))
            elif ratio >= 0.65 and part != brand:
                matches.append((brand, ratio, "moderate similarity"))

            # Brand contained within a longer string (e.g., googlesecure)
            if brand in part and part != brand:
                matches.append((brand, 0.85, "brand name embedded in domain"))

    if matches:
        # Sort by similarity score
        matches.sort(key=lambda x: x[1], reverse=True)

        for brand, score, method in matches[:3]:  # Report top 3
            pct = int(score * 100)
            findings.append(
                f"Resembles '{brand}' ({pct}% match via {method})"
            )

            if score >= 0.90:
                risk_points += 30
            elif score >= 0.80:
                risk_points += 20
            else:
                risk_points += 10
    else:
        findings.append("No brand impersonation detected")

    return {
        "check": "Brand Similarity",
        "findings": findings,
        "risk_points": min(risk_points, 100),
    }
