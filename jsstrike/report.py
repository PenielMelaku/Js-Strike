"""Terminal and JSON report output for JS Strike findings."""

import json
import os
import sys
from typing import List, Dict
from collections import defaultdict

from . import __version__
from .models import Finding, Severity, Category

GITHUB_URL = "https://github.com/PenielMelaku"


# ---------------------------------------------------------------------------
# ANSI color codes (automatically disabled for non-TTY stdout or NO_COLOR)
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
    Severity.HIGH:     (Color.RED + Color.BOLD, "   HIGH   "),
    Severity.MEDIUM:   (Color.YELLOW + Color.BOLD, "  MEDIUM  "),
    Severity.LOW:      (Color.BLUE + Color.BOLD, "   LOW    "),
    Severity.INFO:     (Color.GRAY, "   INFO   "),
}

SEVERITY_BAR_COLORS = {
    Severity.CRITICAL: Color.RED + Color.BOLD,
    Severity.HIGH:     Color.RED,
    Severity.MEDIUM:   Color.YELLOW,
    Severity.LOW:      Color.BLUE,
    Severity.INFO:     Color.GRAY,
}

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def _severity_badge(severity: Severity) -> str:
    color, label = SEVERITY_COLORS[severity]
    return f"{color}[{label}]{Color.RESET}"


def _truncate(text: str, max_len: int = 100) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


def _section_header(title: str, width: int = 66) -> str:
    """Render a clean box-drawn section header."""
    bar = "─" * max(4, width - len(title) - 5)
    return (
        f"  {Color.CYAN}{Color.BOLD}╭─ {Color.WHITE}{title} {Color.CYAN}{bar}╮{Color.RESET}"
    )


def _section_footer(width: int = 66) -> str:
    bar = "─" * (width - 2)
    return f"  {Color.CYAN}{Color.BOLD}╰{bar}╯{Color.RESET}"


def print_banner():
    """Print the JS Strike startup banner with GitHub attribution."""
    w = 64
    border = "─" * w
    print()
    print(f"  {Color.CYAN}{Color.BOLD}╭{border}╮{Color.RESET}")
    print(f"  {Color.CYAN}{Color.BOLD}│{Color.RESET}  {Color.CYAN}{Color.BOLD}     ╦╔═╗  ╔═╗┌┬┐┬─┐┬┬┌─┌─┐{Color.RESET}                                   {Color.CYAN}{Color.BOLD}│{Color.RESET}")
    print(f"  {Color.CYAN}{Color.BOLD}│{Color.RESET}  {Color.CYAN}{Color.BOLD}     ║╚═╗  ╚═╗ │ ├┬┘│├┴┐├┤ {Color.RESET}   {Color.WHITE}{Color.BOLD}v{__version__}{Color.RESET}                          {Color.CYAN}{Color.BOLD}│{Color.RESET}")
    print(f"  {Color.CYAN}{Color.BOLD}│{Color.RESET}  {Color.CYAN}{Color.BOLD}    ╚╝╚═╝  ╚═╝ ┴ ┴└─┴┴ ┴└─┘{Color.RESET}                                   {Color.CYAN}{Color.BOLD}│{Color.RESET}")
    print(f"  {Color.CYAN}{Color.BOLD}│{Color.RESET}  {Color.WHITE}JavaScript Static Analysis & Recon CLI{Color.RESET}                        {Color.CYAN}{Color.BOLD}│{Color.RESET}")
    print(f"  {Color.CYAN}{Color.BOLD}│{Color.RESET}  {Color.DIM}GitHub:{Color.RESET} {Color.BLUE}{GITHUB_URL}{Color.RESET}                       {Color.CYAN}{Color.BOLD}│{Color.RESET}")
    print(f"  {Color.CYAN}{Color.BOLD}╰{border}╯{Color.RESET}")


def print_scan_target(target: str, include_third_party: bool = False,
                      allow_domain: List[str] | None = None):
    """Print a compact scan configuration block."""
    scope = "Same domain + subdomains"
    if include_third_party:
        scope = "All scripts (including third-party)"
    elif allow_domain:
        scope = f"Same domain + {', '.join(allow_domain)}"

    print(f"  {Color.DIM}Target:{Color.RESET} {Color.WHITE}{Color.BOLD}{target}{Color.RESET}")
    print(f"  {Color.DIM}Scope:{Color.RESET}  {scope}")
    print()


def print_terminal_report(findings: List[Finding], verbose: bool = False):
    """Print a color-coded terminal report grouped by severity."""
    if not findings:
        print(f"\n  {Color.GREEN}{Color.BOLD}✔ No findings detected.{Color.RESET}\n")
        _print_footer()
        return

    # Group by severity
    by_severity: Dict[Severity, List[Finding]] = defaultdict(list)
    for f in findings:
        by_severity[f.severity].append(f)

    total = len(findings)
    unique_files = len({f.file_url for f in findings})
    bar_width = 24

    # Summary dashboard
    print(_section_header("SCAN RESULTS SUMMARY"))
    print(f"  {Color.CYAN}│{Color.RESET}")

    for sev in SEVERITY_ORDER:
        count = len(by_severity.get(sev, []))
        pct = (count / total * 100) if total else 0.0
        filled = round((count / total) * bar_width) if total else 0
        if count > 0 and filled == 0:
            filled = 1
        empty = bar_width - filled
        bar_color = SEVERITY_BAR_COLORS[sev]
        bar = f"{bar_color}{'█' * filled}{Color.GRAY}{'░' * empty}{Color.RESET}"
        badge = _severity_badge(sev)
        print(f"  {Color.CYAN}│{Color.RESET}  {badge}  {bar}  {Color.BOLD}{count:>4}{Color.RESET} {Color.DIM}({pct:5.1f}%){Color.RESET}")

    print(f"  {Color.CYAN}│{Color.RESET}")
    print(
        f"  {Color.CYAN}│{Color.RESET}  {Color.BOLD}Total:{Color.RESET} {Color.WHITE}{Color.BOLD}{total}{Color.RESET} finding{'s' if total != 1 else ''}"
        f"  {Color.DIM}•{Color.RESET}  {Color.BOLD}Scripts:{Color.RESET} {unique_files}"
    )
    print(_section_footer())
    print()

    # Detailed findings
    print(_section_header("DETAILED FINDINGS"))
    print()

    idx = 0
    for sev in SEVERITY_ORDER:
        sev_findings = by_severity.get(sev, [])
        if not sev_findings:
            continue

        for f in sev_findings:
            idx += 1
            badge = _severity_badge(sev)
            show_snippet = verbose or sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)

            print(f"  {Color.BOLD}{Color.WHITE}#{idx:<3}{Color.RESET} {badge}  {Color.BOLD}{f.category.value}{Color.RESET}")
            print(f"   {Color.DIM}├─ Location{Color.RESET}   {Color.CYAN}{f.file_url}:{f.line_number}{Color.RESET}")
            print(
                f"   {Color.DIM}├─ Meta{Color.RESET}       confidence: {Color.WHITE}{f.confidence.value}{Color.RESET}"
                f"  {Color.DIM}•{Color.RESET}  detector: {Color.WHITE}{f.detector}{Color.RESET}"
            )
            detail_branch = "├─" if show_snippet else "╰─"
            print(f"   {Color.DIM}{detail_branch} Detail{Color.RESET}     {f.explanation}")
            if show_snippet:
                print(f"   {Color.DIM}╰─ Snippet{Color.RESET}    {Color.GRAY}{_truncate(f.snippet, 115)}{Color.RESET}")
            print()

    # Endpoint summary
    _print_endpoint_summary(findings)

    # Secret summary
    _print_secret_summary(findings)

    # Footer
    _print_footer()


def _print_endpoint_summary(findings: List[Finding]):
    """Print a quick-reference list of extracted endpoints."""
    endpoints = [
        f for f in findings
        if f.category in (Category.ENDPOINT, Category.ADMIN_ROUTE, Category.IDOR_CANDIDATE)
    ]
    if not endpoints:
        return

    print(_section_header(f"EXTRACTED ENDPOINTS ({len(endpoints)})"))
    print()

    for f in endpoints:
        if f.category == Category.ADMIN_ROUTE:
            tag = f"{Color.YELLOW}{Color.BOLD}[ADMIN]{Color.RESET}"
            path_color = Color.YELLOW
        elif f.category == Category.IDOR_CANDIDATE:
            tag = f"{Color.MAGENTA}{Color.BOLD}[IDOR ]{Color.RESET}"
            path_color = Color.MAGENTA
        else:
            tag = f"{Color.CYAN}[ API ]{Color.RESET}"
            path_color = Color.WHITE

        path = f.explanation.split(": ", 1)[-1] if ": " in f.explanation else f.snippet
        print(f"    {tag} {path_color}{_truncate(path, 88)}{Color.RESET}  {Color.DIM}({f.file_url}:{f.line_number}){Color.RESET}")
    print()


def _print_secret_summary(findings: List[Finding]):
    """Print a quick-reference list of detected secrets."""
    secrets = [
        f for f in findings
        if f.category in (Category.SECRET_EXPOSURE, Category.INTERNAL_INFRA)
    ]
    if not secrets:
        return

    print(_section_header(f"DETECTED SECRETS & INFRA LEAKS ({len(secrets)})"))
    print()

    for f in secrets:
        if f.severity == Severity.CRITICAL:
            tag = f"{Color.BG_RED}{Color.WHITE}{Color.BOLD}[CRIT]{Color.RESET}"
            text_color = Color.RED
        elif f.severity == Severity.HIGH:
            tag = f"{Color.RED}{Color.BOLD}[HIGH]{Color.RESET}"
            text_color = Color.RED
        elif f.severity == Severity.MEDIUM:
            tag = f"{Color.YELLOW}{Color.BOLD}[MED ]{Color.RESET}"
            text_color = Color.YELLOW
        else:
            tag = f"{Color.BLUE}[LOW ]{Color.RESET}"
            text_color = Color.GRAY

        print(f"    {tag} {text_color}{_truncate(f.explanation, 88)}{Color.RESET}  {Color.DIM}({f.file_url}:{f.line_number}){Color.RESET}")
    print()


def _print_footer():
    print(f"  {Color.DIM}JS Strike v{__version__}  •  {GITHUB_URL}  •  Authorized security testing only{Color.RESET}\n")


def print_json_report(findings: List[Finding]):
    """Print structured JSON report to stdout."""
    report = {
        "tool": "JS Strike",
        "version": __version__,
        "author": GITHUB_URL,
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
