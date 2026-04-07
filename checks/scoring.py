"""
Risk Scoring Engine
Aggregates risk points from all checks and produces a final verdict.
"""


RISK_LEVELS = {
    "SAFE":       (0, 20,  "green"),
    "LOW RISK":   (21, 40, "yellow"),
    "SUSPICIOUS": (41, 65, "dark_orange"),
    "DANGEROUS":  (66, 85, "red"),
    "CRITICAL":   (86, 100, "bold red"),
}


def calculate_risk_score(check_results: list[dict]) -> dict:
    """Calculate overall risk score from individual check results."""

    total_points = sum(r.get("risk_points", 0) for r in check_results)

    # Normalize to 0-100 scale
    # Use diminishing returns curve so even moderate findings score meaningfully
    normalized_score = min(int(total_points * 100 / 150), 100)

    # Determine risk level
    risk_level = "SAFE"
    color = "green"
    for level, (low, high, col) in RISK_LEVELS.items():
        if low <= normalized_score <= high:
            risk_level = level
            color = col
            break

    # Build summary
    top_risks = []
    for r in sorted(check_results, key=lambda x: x["risk_points"], reverse=True):
        if r["risk_points"] > 0:
            top_risks.append({
                "check": r["check"],
                "points": r["risk_points"],
                "top_finding": r["findings"][0] if r["findings"] else "N/A",
            })

    return {
        "total_raw_points": total_points,
        "normalized_score": normalized_score,
        "risk_level": risk_level,
        "color": color,
        "top_risks": top_risks[:3],
        "checks_run": len(check_results),
    }
