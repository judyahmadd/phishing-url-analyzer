#!/usr/bin/env python3
"""
PhishGuard — Phishing URL Analyzer
A lightweight CLI tool that analyzes URLs for phishing indicators.

Author: Judy Ahmad
GitHub: https://github.com/judyahmadd
Website: https://judyahmad.com

Usage:
    python analyzer.py <url>
    python analyzer.py <url> --json
    python analyzer.py <url> --json -o report.json
"""

import argparse
import json
import sys
import time
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

from checks import (
    check_url_structure,
    check_domain_info,
    check_ssl_certificate,
    check_brand_similarity,
    check_redirect_chain,
    calculate_risk_score,
)

console = Console()

BANNER = r"""
 ____  _     _     _      ____                     _
|  _ \| |__ (_)___| |__  / ___|_   _  __ _ _ __ __| |
| |_) | '_ \| / __| '_ \| |  _| | | |/ _` | '__/ _` |
|  __/| | | | \__ \ | | | |_| | |_| | (_| | | | (_| |
|_|   |_| |_|_|___/_| |_|\____|\__,_|\__,_|_|  \__,_|

        Phishing URL Analyzer v1.0
        by Judy Ahmad | judyahmad.com
"""


def validate_url(url: str) -> str:
    """Ensure URL has a scheme."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    if not parsed.hostname:
        console.print("[red]Error:[/red] Invalid URL provided.")
        sys.exit(1)

    return url


def run_analysis(url: str, quiet: bool = False) -> dict:
    """Run all checks against the URL."""

    checks = [
        ("URL Structure", check_url_structure),
        ("Domain Info (WHOIS)", check_domain_info),
        ("SSL Certificate", check_ssl_certificate),
        ("Brand Similarity", check_brand_similarity),
        ("Redirect Chain", check_redirect_chain),
    ]

    results = []

    if quiet:
        for name, check_func in checks:
            try:
                result = check_func(url)
            except Exception as e:
                result = {
                    "check": name,
                    "findings": [f"Error: {str(e)[:100]}"],
                    "risk_points": 0,
                }
            results.append(result)
    else:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:

            for name, check_func in checks:
                task = progress.add_task(f"Running {name}...", total=None)
                try:
                    result = check_func(url)
                except Exception as e:
                    result = {
                        "check": name,
                        "findings": [f"Error: {str(e)[:100]}"],
                        "risk_points": 0,
                    }
                results.append(result)
                progress.update(task, completed=True)

    # Calculate final score
    score = calculate_risk_score(results)

    return {
        "url": url,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "checks": results,
        "score": score,
    }


def display_results(report: dict) -> None:
    """Display results in a formatted terminal output."""

    console.print()

    # --- Header ---
    console.print(
        Panel(
            f"[bold]Target:[/bold] {report['url']}\n"
            f"[bold]Time:[/bold]   {report['timestamp']}",
            title="[bold blue]PhishGuard Analysis Report[/bold blue]",
            border_style="blue",
        )
    )

    # --- Individual check results ---
    for check in report["checks"]:
        risk = check["risk_points"]
        if risk == 0:
            style = "green"
            icon = "✓"
        elif risk <= 15:
            style = "yellow"
            icon = "⚠"
        else:
            style = "red"
            icon = "✗"

        table = Table(
            show_header=False,
            box=None,
            padding=(0, 2),
            expand=True,
        )
        table.add_column(ratio=1)
        table.add_column(justify="right", width=12)

        for finding in check["findings"]:
            table.add_row(
                f"  {finding}",
                "",
            )

        header = Text(f" {icon} {check['check']} ", style=f"bold {style}")
        points = Text(f"[{risk} pts]", style=style)

        console.print()
        console.print(header, points, sep="  ")
        console.print(table)

    # --- Final Score ---
    score = report["score"]
    color = score["color"]

    score_display = (
        f"\n[bold {color}]"
        f"  RISK SCORE: {score['normalized_score']}/100 — {score['risk_level']}"
        f"[/bold {color}]"
    )

    console.print()
    console.print(
        Panel(
            score_display,
            title="[bold]Final Verdict[/bold]",
            border_style=color,
        )
    )

    # --- Top risks summary ---
    if score["top_risks"]:
        console.print("\n[bold]Top Risk Factors:[/bold]")
        for i, risk in enumerate(score["top_risks"], 1):
            console.print(f"  {i}. {risk['top_finding']} ({risk['check']})")

    console.print()


def interactive_mode():
    """Run PhishGuard in interactive mode with a menu."""

    last_report = None

    while True:
        console.print()
        console.print(
            Panel(
                "[bold white]  [1]  Analyze a URL\n"
                "  [2]  Batch scan (multiple URLs)\n"
                "  [3]  Export last report to JSON\n"
                "  [4]  History (this session)\n"
                "  [5]  Help\n"
                "  [6]  Exit[/bold white]",
                title="[bold cyan]🛡️  PhishGuard Menu[/bold cyan]",
                border_style="cyan",
                padding=(1, 3),
            )
        )

        choice = console.input("\n[bold]Choose an option (1-6):[/bold] ").strip()

        # --- Option 1: Single URL ---
        if choice == "1":
            url = console.input("\n[bold]Enter URL to analyze:[/bold] ").strip()
            if not url:
                console.print("[red]No URL entered.[/red]")
                continue
            url = validate_url(url)
            report = run_analysis(url)
            display_results(report)
            last_report = report
            history.append(report)

        # --- Option 2: Batch scan ---
        elif choice == "2":
            console.print(
                "\n[bold]Enter URLs to scan (one per line, empty line to start):[/bold]"
            )
            urls = []
            while True:
                line = console.input("  → ").strip()
                if not line:
                    break
                urls.append(line)

            if not urls:
                console.print("[red]No URLs entered.[/red]")
                continue

            console.print(f"\n[bold]Scanning {len(urls)} URLs...[/bold]\n")

            # Summary table
            table = Table(title="Batch Scan Results", border_style="blue")
            table.add_column("URL", style="white", max_width=50)
            table.add_column("Score", justify="center", width=8)
            table.add_column("Verdict", justify="center", width=12)

            for raw_url in urls:
                url = validate_url(raw_url)
                report = run_analysis(url, quiet=True)
                score = report["score"]
                color = score["color"]

                table.add_row(
                    raw_url[:50],
                    f"[{color}]{score['normalized_score']}[/{color}]",
                    f"[{color}]{score['risk_level']}[/{color}]",
                )
                history.append(report)
                last_report = report

            console.print(table)

        # --- Option 3: Export last report ---
        elif choice == "3":
            if not last_report:
                console.print("[red]No report to export. Analyze a URL first.[/red]")
                continue

            filename = console.input(
                "\n[bold]Filename (default: report.json):[/bold] "
            ).strip()
            if not filename:
                filename = "report.json"
            if not filename.endswith(".json"):
                filename += ".json"

            with open(filename, "w") as f:
                json.dump(last_report, f, indent=2)
            console.print(f"[green]✓ Report saved to {filename}[/green]")

        # --- Option 4: History ---
        elif choice == "4":
            if not history:
                console.print("[yellow]No scans yet this session.[/yellow]")
                continue

            table = Table(title="Session History", border_style="blue")
            table.add_column("#", width=4)
            table.add_column("URL", max_width=50)
            table.add_column("Score", justify="center", width=8)
            table.add_column("Verdict", justify="center", width=12)
            table.add_column("Time", width=22)

            for i, report in enumerate(history, 1):
                score = report["score"]
                color = score["color"]
                table.add_row(
                    str(i),
                    report["url"][:50],
                    f"[{color}]{score['normalized_score']}[/{color}]",
                    f"[{color}]{score['risk_level']}[/{color}]",
                    report["timestamp"],
                )

            console.print(table)

        # --- Option 5: Help ---
        elif choice == "5":
            console.print(
                Panel(
                    "[bold]PhishGuard[/bold] analyzes URLs for phishing indicators:\n\n"
                    "  [cyan]• URL Structure[/cyan] — length, encoding, suspicious chars\n"
                    "  [cyan]• Domain Info[/cyan] — WHOIS age, registrar, expiration\n"
                    "  [cyan]• SSL Certificate[/cyan] — issuer, validity, anomalies\n"
                    "  [cyan]• Brand Similarity[/cyan] — typosquatting detection\n"
                    "  [cyan]• Redirect Chain[/cyan] — hops, cross-domain redirects\n\n"
                    "Each check adds risk points → final score 0-100.\n\n"
                    "[bold]CLI usage:[/bold]\n"
                    "  python analyzer.py https://example.com\n"
                    "  python analyzer.py https://example.com --json\n"
                    "  python analyzer.py https://example.com -o report.json",
                    title="[bold cyan]Help[/bold cyan]",
                    border_style="cyan",
                )
            )

        # --- Option 6: Exit ---
        elif choice == "6":
            console.print("\n[bold cyan]Goodbye! Stay safe. 🛡️[/bold cyan]\n")
            break

        else:
            console.print("[red]Invalid option. Choose 1-6.[/red]")


# Session history for interactive mode
history = []


def main():
    parser = argparse.ArgumentParser(
        description="PhishGuard — Analyze URLs for phishing indicators",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python analyzer.py                              (interactive mode)\n"
               "  python analyzer.py https://suspicious-site.com\n"
               "  python analyzer.py paypa1-secure.login.com --json\n"
               "  python analyzer.py evil.site -o report.json\n",
    )
    parser.add_argument("url", nargs="?", default=None, help="URL to analyze (omit for interactive mode)")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "-o", "--output",
        help="Save JSON report to file",
    )

    args = parser.parse_args()

    # Show banner
    if not args.json:
        console.print(BANNER, style="bold cyan")

    # Interactive mode if no URL provided
    if args.url is None:
        interactive_mode()
        return

    # Direct mode
    url = validate_url(args.url)
    report = run_analysis(url, quiet=args.json)

    # Output
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        display_results(report)

    # Save to file if requested
    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        console.print(f"[green]Report saved to {args.output}[/green]")

    # Exit code based on risk
    risk_score = report["score"]["normalized_score"]
    if risk_score > 65:
        sys.exit(2)  # Dangerous
    elif risk_score > 40:
        sys.exit(1)  # Suspicious
    else:
        sys.exit(0)  # Safe


if __name__ == "__main__":
    main()
