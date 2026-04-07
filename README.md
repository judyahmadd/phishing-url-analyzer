# 🛡️ PhishGuard — Phishing URL Analyzer

A lightweight command-line tool that analyzes URLs for phishing indicators using heuristic analysis. Unlike blocklist-based tools that only catch *known* threats, PhishGuard examines the **structural characteristics** of a URL to detect phishing attempts — even brand-new ones that haven't been reported yet.

## Why PhishGuard?

Most phishing detection relies on databases of known malicious URLs. The problem? **New phishing sites appear every 11 seconds**, and blocklists can't keep up. PhishGuard takes a different approach by analyzing:

- **URL structure** — length, encoding tricks, suspicious characters
- **Domain intelligence** — WHOIS age, registration patterns
- **SSL certificates** — issuer, validity, anomalies  
- **Brand impersonation** — typosquatting and homoglyph detection
- **Redirect behavior** — chain length, cross-domain hops

Each check contributes to a **risk score (0–100)** with a clear verdict: `SAFE`, `LOW RISK`, `SUSPICIOUS`, `DANGEROUS`, or `CRITICAL`.

## Installation

```bash
git clone https://github.com/judyahmad/phishing-url-analyzer.git
cd phishing-url-analyzer
pip install -r requirements.txt
```

**Requirements:** Python 3.9+

## Usage

### Basic analysis
```bash
python analyzer.py https://example.com
```

### JSON output
```bash
python analyzer.py https://suspicious-site.com --json
```

### Save report to file
```bash
python analyzer.py https://suspicious-site.com -o report.json
```

## Example Output

```
 ____  _     _     _      ____                     _
|  _ \| |__ (_)___| |__  / ___|_   _  __ _ _ __ __| |
| |_) | '_ \| / __| '_ \| |  _| | | |/ _` | '__/ _` |
|  __/| | | | \__ \ | | | |_| | |_| | (_| | | | (_| |
|_|   |_| |_|_|___/_| |_|\____|\__,_|\__,_|_|  \__,_|

        Phishing URL Analyzer v1.0

╭─ PhishGuard Analysis Report ────────────────────────╮
│ Target: https://g00gle-login.secure-verify.tk       │
│ Time:   2026-04-07 12:00:00 UTC                     │
╰─────────────────────────────────────────────────────╯

 ✗ URL Structure Analysis                      [45 pts]
   Suspicious TLD: .tk
   Suspicious keywords found: login, secure, verify
   Multiple hyphens in domain (2)

 ✗ Brand Similarity                            [30 pts]
   Resembles 'google' (95% match via character substitution)

 ⚠ Domain Information                          [20 pts]
   Domain is 12 days old — HIGH RISK

╭─ Final Verdict ─────────────────────────────────────╮
│  RISK SCORE: 78/100 — DANGEROUS                     │
╰─────────────────────────────────────────────────────╯
```

## Exit Codes

PhishGuard returns meaningful exit codes for scripting and CI/CD integration:

| Code | Meaning |
|------|---------|
| `0` | Safe (score ≤ 40) |
| `1` | Suspicious (score 41–65) |
| `2` | Dangerous (score > 65) |

## Project Structure

```
phishing-url-analyzer/
├── analyzer.py              # CLI entry point
├── checks/
│   ├── __init__.py
│   ├── url_structure.py     # URL pattern analysis
│   ├── domain_info.py       # WHOIS lookup
│   ├── ssl_check.py         # Certificate inspection
│   ├── brand_similarity.py  # Typosquatting detection
│   ├── redirect_chain.py    # Redirect tracking
│   └── scoring.py           # Risk scoring engine
├── requirements.txt
├── LICENSE
└── README.md
```

## Use Cases

- **SOC Analysts** — Quickly triage suspicious URLs from phishing reports
- **IT Administrators** — Verify links reported by employees
- **Penetration Testers** — Analyze phishing infrastructure during engagements
- **Security Automation** — Integrate via JSON output and exit codes into pipelines

## Limitations

- WHOIS lookups may be rate-limited or blocked for some TLDs
- SSL checks require network access to the target
- Brand list covers major targets but is not exhaustive
- This is a heuristic tool — not a replacement for threat intelligence feeds

## Contributing

Contributions are welcome! Some ideas:

- Add more brands to the similarity database
- Implement HTML content analysis
- Add VirusTotal API integration
- Build a web interface

## License

MIT License — see [LICENSE](LICENSE) for details.

## Author

**Judy Ahmad** — Cybersecurity Professional  
🌐 [judyahmad.com](https://judyahmad.com) · 🐙 [GitHub](https://github.com/judyahmad)
