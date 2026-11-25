"""Terminal and JSON report output for JS Strike findings (msfconsole-inspired UI)."""

import json
import os
import sys
import time
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

SEVERITY_PREFIX = {
    Severity.CRITICAL: f"{Color.RED}{Color.BOLD}[-]{Color.RESET}",
    Severity.HIGH:     f"{Color.RED}{Color.BOLD}[!]{Color.RESET}",
    Severity.MEDIUM:   f"{Color.YELLOW}{Color.BOLD}[!]{Color.RESET}",
    Severity.LOW:      f"{Color.BLUE}{Color.BOLD}[*]{Color.RESET}",
    Severity.INFO:     f"{Color.GRAY}[*]{Color.RESET}",
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


def _msf_section(title: str):
    """Print a Metasploit-style section header with underlined title."""
    print(f"  {Color.WHITE}{Color.BOLD}{title}{Color.RESET}")
    print(f"  {Color.CYAN}{'=' * len(title)}{Color.RESET}")
    print()


def print_banner(animate: bool = True):
    """Print an msfconsole-inspired JS Strike banner with stats block."""
    banner_lines = [
        "",
        f"{Color.RED}{Color.BOLD}       ██╗███████╗    ███████╗████████╗██████╗ ██╗██╗  ██╗███████╗{Color.RESET}",
        f"{Color.RED}{Color.BOLD}       ██║██╔════╝    ██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝{Color.RESET}",
        f"{Color.WHITE}{Color.BOLD}       ██║███████╗    ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  {Color.RESET}",
        f"{Color.CYAN}  ██   ██║╚════██║    ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  {Color.RESET}",
        f"{Color.CYAN}  ╚█████╔╝███████║    ███████║   ██║   ██║  ██║██║██║  ██╗███████╗{Color.RESET}",
        f"{Color.DIM}   ╚════╝ ╚══════╝    ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝{Color.RESET}",
        "",
        f"         {Color.DIM}=[ {Color.CYAN}{Color.BOLD}jsstrike v{__version__}{Color.RESET} {Color.DIM}- JavaScript Static Recon Console   ]{Color.RESET}",
        f"  {Color.DIM}+ -- --=[ {Color.WHITE}14 detectors{Color.RESET} {Color.DIM}- {Color.WHITE}4 suites{Color.RESET} {Color.DIM}- {Color.WHITE}passive static analysis{Color.RESET}      {Color.DIM}]{Color.RESET}",
        f"  {Color.DIM}+ -- --=[ {Color.BLUE}{GITHUB_URL}{Color.RESET}                         {Color.DIM}]{Color.RESET}",
        "",
    ]
    should_animate = animate and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    for line in banner_lines:
        print(line, flush=True)
        if should_animate and line:
            time.sleep(0.04)


def print_scan_target(target: str, include_third_party: bool = False,
                      allow_domain: List[str] | None = None):
    """Print an msfconsole-style module options / command prompt block."""
    scope = "same-domain + subdomains"
    if include_third_party:
        scope = "all (including third-party)"
    elif allow_domain:
        scope = f"same-domain + {', '.join(allow_domain)}"

    print(f"  {Color.BOLD}jsstrike{Color.RESET} {Color.RED}> {Color.WHITE}run -u {target}{Color.RESET}")
    print()
    print(f"  {Color.DIM}{'Option':<12} {'Current Setting':<38} {'Description'}{Color.RESET}")
    print(f"  {Color.CYAN}{'------':<12} {'---------------':<38} {'-----------'}{Color.RESET}")
    print(f"  {'RURL':<12} {Color.WHITE}{_truncate(target, 36):<38}{Color.RESET} {Color.DIM}Target URL to analyze{Color.RESET}")
    print(f"  {'SCOPE':<12} {Color.WHITE}{_truncate(scope, 36):<38}{Color.RESET} {Color.DIM}Script domain inclusion policy{Color.RESET}")
    print()


def print_terminal_report(findings: List[Finding], verbose: bool = False):
    """Print an msfconsole-style terminal report grouped by severity."""
    if not findings:
        print(f"  {Color.GREEN}{Color.BOLD}[+]{Color.RESET} No findings detected.\n")
        _print_footer()
        return

    # Group by severity
    by_severity: Dict[Severity, List[Finding]] = defaultdict(list)
    for f in findings:
        by_severity[f.severity].append(f)

    total = len(findings)
    unique_files = len({f.file_url for f in findings})
    bar_width = 24

    # Summary table
    _msf_section("Scan Results Summary")
    print(f"  {Color.DIM}{'Severity':<12} {'Distribution':<26} {'Count':>5}  {'Share'}{Color.RESET}")
    print(f"  {Color.CYAN}{'--------':<12} {'------------':<26} {'-----':>5}  {'-----'}{Color.RESET}")

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
        print(f"  {badge}  {bar}  {Color.BOLD}{count:>5}{Color.RESET}  {Color.DIM}{pct:5.1f}%{Color.RESET}")

    print()
    print(
        f"  {Color.BLUE}{Color.BOLD}[*]{Color.RESET} Total: {Color.WHITE}{Color.BOLD}{total}{Color.RESET} finding{'s' if total != 1 else ''}"
        f" across {Color.WHITE}{Color.BOLD}{unique_files}{Color.RESET} script(s)\n"
    )

    # Detailed findings
    _msf_section("Detailed Findings")

    idx = 0
    for sev in SEVERITY_ORDER:
        sev_findings = by_severity.get(sev, [])
        if not sev_findings:
            continue

        for f in sev_findings:
            idx += 1
            prefix = SEVERITY_PREFIX[sev]
            badge = _severity_badge(sev)
            show_snippet = verbose or sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)

            print(f"  {prefix} {Color.BOLD}#{idx:<3}{Color.RESET} {badge} {Color.WHITE}{Color.BOLD}{f.category.value}{Color.RESET}")
            print(f"      {Color.DIM}Location :{Color.RESET} {Color.CYAN}{f.file_url}:{f.line_number}{Color.RESET}")
            print(
                f"      {Color.DIM}Module   :{Color.RESET} {f.detector}"
                f"  {Color.DIM}|{Color.RESET}  {Color.DIM}Confidence:{Color.RESET} {f.confidence.value}"
            )
            print(f"      {Color.DIM}Detail   :{Color.RESET} {f.explanation}")
            if show_snippet:
                print(f"      {Color.DIM}Snippet  :{Color.RESET} {Color.GRAY}{_truncate(f.snippet, 110)}{Color.RESET}")
            print()

    # Endpoint summary
    _print_endpoint_summary(findings)

    # Secret summary
    _print_secret_summary(findings)

    # Footer
    _print_footer()


def _print_endpoint_summary(findings: List[Finding]):
    """Print an msfconsole-style table of extracted endpoints."""
    endpoints = [
        f for f in findings
        if f.category in (Category.ENDPOINT, Category.ADMIN_ROUTE, Category.IDOR_CANDIDATE)
    ]
    if not endpoints:
        return

    _msf_section(f"Extracted Endpoints ({len(endpoints)})")
    print(f"  {Color.DIM}{'Tag':<9} {'Endpoint':<54} {'Source'}{Color.RESET}")
    print(f"  {Color.CYAN}{'---':<9} {'--------':<54} {'------'}{Color.RESET}")

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
        padded_path = f"{_truncate(path, 52):<54}"
        print(f"  {tag}   {path_color}{padded_path}{Color.RESET} {Color.DIM}{f.file_url}:{f.line_number}{Color.RESET}")
    print()


def _print_secret_summary(findings: List[Finding]):
    """Print an msfconsole-style table of detected secrets & infra leaks."""
    secrets = [
        f for f in findings
        if f.category in (Category.SECRET_EXPOSURE, Category.INTERNAL_INFRA)
    ]
    if not secrets:
        return

    _msf_section(f"Detected Secrets & Infra Leaks ({len(secrets)})")
    print(f"  {Color.DIM}{'Sev':<8} {'Finding':<54} {'Source'}{Color.RESET}")
    print(f"  {Color.CYAN}{'---':<8} {'-------':<54} {'------'}{Color.RESET}")

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

        padded_detail = f"{_truncate(f.explanation, 52):<54}"
        print(f"  {tag}   {text_color}{padded_detail}{Color.RESET} {Color.DIM}{f.file_url}:{f.line_number}{Color.RESET}")
    print()


def _print_footer():
    print(f"  {Color.DIM}jsstrike v{__version__}  |  {GITHUB_URL}  |  Authorized testing only{Color.RESET}\n")


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
