"""Terminal and JSON report output for JS Strike findings."""

import json
import os
import sys
from typing import List, Dict
from collections import defaultdict

from .models import Finding, Severity, Category


# ---------------------------------------------------------------------------
# ANSI color codes
# ---------------------------------------------------------------------------

class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"

    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"
    BG_MAGENTA = "\033[45m"
    BG_BLUE = "\033[44m"
    BG_GRAY = "\033[100m"


if not sys.stdout.isatty() or "NO_COLOR" in os.environ:
    for _attr in (
        "RESET", "BOLD", "DIM",
        "RED", "YELLOW", "GREEN", "BLUE", "CYAN", "MAGENTA", "WHITE", "GRAY",
        "BG_RED", "BG_YELLOW", "BG_MAGENTA", "BG_BLUE", "BG_GRAY",
    ):
        setattr(Color, _attr, "")


SEVERITY_COLORS = {
    Severity.CRITICAL: (Color.BG_RED + Color.WHITE + Color.BOLD, " CRITICAL "),
    Severity.HIGH:     (Color.RED + Color.BOLD, " HIGH "),
    Severity.MEDIUM:   (Color.YELLOW + Color.BOLD, " MEDIUM "),
    Severity.LOW:      (Color.BLUE, " LOW "),
    Severity.INFO:     (Color.GRAY, " INFO "),
}

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _severity_badge(severity: Severity) -> str:
    color, label = SEVERITY_COLORS[severity]
    return f"{color}[{label}]{Color.RESET}"


def _truncate(text: str, max_len: int = 100) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


BANNER = r"""
     ╦╔═╗  ╔═╗┌┬┐┬─┐┬┬┌─┌─┐
     ║╚═╗  ╚═╗ │ ├┬┘│├┴┐├┤
    ╚╝╚═╝  ╚═╝ ┴ ┴└─┴┴ ┴└─┘
    JavaScript Static Analysis for Security
"""


def print_banner():
    print(f"{Color.CYAN}{Color.BOLD}{BANNER}{Color.RESET}")


def print_terminal_report(findings: List[Finding], verbose: bool = False):
    """Print a color-coded terminal report grouped by severity."""
    if not findings:
        print(f"\n{Color.GREEN}{Color.BOLD}  ✓ No findings detected.{Color.RESET}\n")
        return

    # Group by severity
    by_severity: Dict[Severity, List[Finding]] = defaultdict(list)
    for f in findings:
        by_severity[f.severity].append(f)

    # Summary counts
    print(f"\n{Color.BOLD}  ══════════════════════════════════════════════════{Color.RESET}")
    print(f"{Color.BOLD}  SCAN RESULTS SUMMARY{Color.RESET}")
    print(f"{Color.BOLD}  ══════════════════════════════════════════════════{Color.RESET}\n")

    total = len(findings)
    for sev in SEVERITY_ORDER:
        count = len(by_severity.get(sev, []))
        if count > 0:
            badge = _severity_badge(sev)
            print(f"    {badge}  {count} finding{'s' if count != 1 else ''}")

    print(f"\n    {Color.BOLD}Total: {total} finding{'s' if total != 1 else ''}{Color.RESET}\n")

    # Detailed findings
    print(f"{Color.BOLD}  ══════════════════════════════════════════════════{Color.RESET}")
    print(f"{Color.BOLD}  DETAILED FINDINGS{Color.RESET}")
    print(f"{Color.BOLD}  ══════════════════════════════════════════════════{Color.RESET}\n")

    idx = 0
    for sev in SEVERITY_ORDER:
        sev_findings = by_severity.get(sev, [])
        if not sev_findings:
            continue

        for f in sev_findings:
            idx += 1
            badge = _severity_badge(sev)
            print(f"  {Color.BOLD}#{idx}{Color.RESET} {badge}  {Color.BOLD}{f.category.value}{Color.RESET}")
            print(f"     {Color.DIM}File:{Color.RESET}       {f.file_url}")
            print(f"     {Color.DIM}Line:{Color.RESET}       {f.line_number}")
            print(f"     {Color.DIM}Confidence:{Color.RESET} {f.confidence.value}")
            print(f"     {Color.DIM}Detector:{Color.RESET}   {f.detector}")
            print(f"     {Color.DIM}Detail:{Color.RESET}     {f.explanation}")
            if verbose or sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                print(f"     {Color.DIM}Snippet:{Color.RESET}    {Color.GRAY}{_truncate(f.snippet, 120)}{Color.RESET}")
            print()

    # Endpoint summary
    _print_endpoint_summary(findings)

    # Secret summary
    _print_secret_summary(findings)


def _print_endpoint_summary(findings: List[Finding]):
    """Print a quick-reference list of extracted endpoints."""
    endpoints = [f for f in findings if f.category in
                 (Category.ENDPOINT, Category.ADMIN_ROUTE, Category.IDOR_CANDIDATE)]
    if not endpoints:
        return

    print(f"{Color.BOLD}  ══════════════════════════════════════════════════{Color.RESET}")
    print(f"{Color.BOLD}  EXTRACTED ENDPOINTS ({len(endpoints)}){Color.RESET}")
    print(f"{Color.BOLD}  ══════════════════════════════════════════════════{Color.RESET}\n")

    for f in endpoints:
        icon = "🔒" if f.category == Category.ADMIN_ROUTE else ("🔑" if f.category == Category.IDOR_CANDIDATE else "→")
        # Extract the actual path from the explanation
        path = f.explanation.split(": ", 1)[-1] if ": " in f.explanation else f.snippet
        sev_color = Color.YELLOW if f.severity >= Severity.MEDIUM else Color.GRAY
        print(f"    {icon} {sev_color}{_truncate(path, 100)}{Color.RESET}  {Color.DIM}({f.file_url}:{f.line_number}){Color.RESET}")
    print()


def _print_secret_summary(findings: List[Finding]):
    """Print a quick-reference list of detected secrets."""
    secrets = [f for f in findings if f.category in
               (Category.SECRET_EXPOSURE, Category.INTERNAL_INFRA)]
    if not secrets:
        return

    print(f"{Color.BOLD}  ══════════════════════════════════════════════════{Color.RESET}")
    print(f"{Color.BOLD}  DETECTED SECRETS & INFRA LEAKS ({len(secrets)}){Color.RESET}")
    print(f"{Color.BOLD}  ══════════════════════════════════════════════════{Color.RESET}\n")

    for f in secrets:
        icon = "🔴" if f.severity >= Severity.HIGH else "🟡"
        sev_color = Color.RED if f.severity >= Severity.HIGH else Color.YELLOW
        print(f"    {icon} {sev_color}{_truncate(f.explanation, 100)}{Color.RESET}  {Color.DIM}({f.file_url}:{f.line_number}){Color.RESET}")
    print()


def print_json_report(findings: List[Finding]):
    """Print structured JSON report to stdout."""
    report = {
        "tool": "JS Strike",
        "version": "1.0.0",
        "total_findings": len(findings),
        "summary": {},
        "findings": [f.to_dict() for f in findings],
        "endpoints": [],
        "secrets": [],
    }

    # Summary counts
    for sev in SEVERITY_ORDER:
        count = sum(1 for f in findings if f.severity == sev)
        report["summary"][sev.value] = count

    # Endpoint list
    for f in findings:
        if f.category in (Category.ENDPOINT, Category.ADMIN_ROUTE, Category.IDOR_CANDIDATE):
            path = f.explanation.split(": ", 1)[-1] if ": " in f.explanation else f.snippet
            report["endpoints"].append({
                "path": path,
                "category": f.category.value,
                "file": f.file_url,
                "line": f.line_number,
            })

    # Secret list
    for f in findings:
        if f.category in (Category.SECRET_EXPOSURE, Category.INTERNAL_INFRA):
            report["secrets"].append({
                "type": f.explanation.split(" detected")[0] if " detected" in f.explanation else f.category.value,
                "file": f.file_url,
                "line": f.line_number,
                "severity": f.severity.value,
            })

    print(json.dumps(report, indent=2))

