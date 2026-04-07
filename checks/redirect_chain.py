"""
Redirect Chain Tracker
Follows the URL through all redirects to find:
- Number of redirects (excessive = suspicious)
- Final destination URL
- Cross-domain redirects
"""

import requests
from urllib.parse import urlparse


def check_redirect_chain(url: str) -> dict:
    """Track URL redirect chain for phishing indicators."""

    findings = []
    risk_points = 0
    chain = []

    try:
        response = requests.get(
            url,
            allow_redirects=True,
            timeout=15,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                )
            },
        )

        # Build the redirect chain
        if response.history:
            for r in response.history:
                chain.append({
                    "url": r.url,
                    "status": r.status_code,
                })
            chain.append({
                "url": response.url,
                "status": response.status_code,
            })

    except requests.exceptions.SSLError:
        findings.append("SSL error during connection")
        risk_points += 15
        return {
            "check": "Redirect Chain",
            "findings": findings,
            "risk_points": risk_points,
        }
    except requests.exceptions.ConnectionError:
        findings.append("Could not connect to URL")
        risk_points += 10
        return {
            "check": "Redirect Chain",
            "findings": findings,
            "risk_points": risk_points,
        }
    except requests.exceptions.Timeout:
        findings.append("Connection timed out")
        risk_points += 5
        return {
            "check": "Redirect Chain",
            "findings": findings,
            "risk_points": risk_points,
        }
    except Exception as e:
        findings.append(f"Error following redirects: {str(e)[:80]}")
        return {
            "check": "Redirect Chain",
            "findings": findings,
            "risk_points": 5,
        }

    # --- Check 1: Number of redirects ---
    num_redirects = len(chain) - 1 if chain else 0

    if num_redirects == 0:
        findings.append("No redirects — URL loads directly")
    elif num_redirects <= 2:
        findings.append(f"{num_redirects} redirect(s) — normal")
    elif num_redirects <= 4:
        findings.append(f"{num_redirects} redirects — suspicious")
        risk_points += 15
    else:
        findings.append(f"{num_redirects} redirects — excessive, likely malicious")
        risk_points += 25

    # --- Check 2: Cross-domain redirects ---
    if chain:
        domains_visited = []
        for hop in chain:
            domain = urlparse(hop["url"]).hostname
            if domain and domain not in domains_visited:
                domains_visited.append(domain)

        if len(domains_visited) > 1:
            findings.append(
                f"Crosses {len(domains_visited)} domains: "
                f"{' → '.join(domains_visited)}"
            )
            if len(domains_visited) >= 3:
                risk_points += 20
            else:
                risk_points += 10

    # --- Check 3: Final destination ---
    if chain:
        final_url = chain[-1]["url"]
        original_domain = urlparse(url).hostname
        final_domain = urlparse(final_url).hostname

        if original_domain != final_domain:
            findings.append(
                f"Final destination differs from original: {final_domain}"
            )
            risk_points += 15
        else:
            findings.append(f"Final destination: {final_url[:100]}")

    if not findings:
        findings.append("No redirect anomalies detected")

    return {
        "check": "Redirect Chain",
        "findings": findings,
        "risk_points": min(risk_points, 100),
        "chain": chain,
    }
