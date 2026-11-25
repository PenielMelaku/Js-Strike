#!/usr/bin/env python3
"""JS Strike — JavaScript static analysis CLI for authorized security testing.

Usage:
    python -m jsstrike <target_url> [options]
    python -m jsstrike http://localhost:8888 --json
    python -m jsstrike https://example.com --include-third-party --verbose
"""

import argparse
import sys
import threading
import time

from .fetcher import run_fetcher
from .xss import run_xss_detectors
from .secrets import run_secret_detectors
from .endpoints import run_endpoint_detectors
from .libraries import run_library_detectors
from .report import (
    print_terminal_report,
    print_json_report,
    print_banner,
    print_scan_target,
    print_usage_guide,
    Color,
)
from .models import Finding, Severity


class _Spinner:
    """Lightweight stderr progress spinner for interactive terminals."""

    FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")

    def __init__(self, message: str, enabled: bool = True):
        self.message = message
        self.enabled = enabled and sys.stderr.isatty()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._start = time.monotonic()

    def _spin(self):
        idx = 0
        while not self._stop_event.is_set():
            frame = self.FRAMES[idx % len(self.FRAMES)]
            elapsed = time.monotonic() - self._start
            sys.stderr.write(f"\r  {Color.BLUE}{Color.BOLD}[*]{Color.RESET} {self.message} {Color.CYAN}{frame}{Color.RESET} {Color.DIM}({elapsed:.1f}s){Color.RESET}")
            sys.stderr.flush()
            idx += 1
            self._stop_event.wait(0.08)

    def __enter__(self):
        self._start = time.monotonic()
        if self.enabled:
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.enabled and self._thread is not None:
            self._stop_event.set()
            self._thread.join()
            clear_len = len(f"  x {self.message} (000.0s)") + 4
            sys.stderr.write("\r" + " " * clear_len + "\r")
            sys.stderr.flush()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jsstrike",
        description="JS Strike — JavaScript static analysis for authorized security testing & bug bounty recon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m jsstrike http://target.com
  python -m jsstrike http://target.com --json > report.json
  python -m jsstrike http://target.com --include-third-party --verbose
  python -m jsstrike http://target.com --only-xss
  python -m jsstrike http://target.com --skip-secrets --skip-libraries

⚠️  For authorized security testing only. Never use against targets without permission.
""",
    )

    # Target / Guide
    parser.add_argument("target", nargs="?", help="Target URL to analyze")
    parser.add_argument("--guide", "-g", action="store_true",
                        help="Show animated step-by-step usage guide")

    # Scope
    scope_group = parser.add_argument_group("Scope control")
    scope_group.add_argument("--include-third-party", action="store_true",
                             help="Include third-party (cross-domain) scripts")
    scope_group.add_argument("--allow-domain", action="append", default=[],
                             metavar="DOMAIN",
                             help="Additional domain(s) to include in scope (repeatable)")

    # Output
    output_group = parser.add_argument_group("Output")
    output_group.add_argument("--json", action="store_true",
                              help="Output structured JSON instead of terminal report")
    output_group.add_argument("--verbose", "-v", action="store_true",
                              help="Show snippets for all severity levels")
    output_group.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"],
                              default="info",
                              help="Minimum severity to display (default: info)")

    # Module toggles — skip individual detectors
    toggle_group = parser.add_argument_group("Module toggles (skip)")
    toggle_group.add_argument("--skip-xss", action="store_true",
                              help="Skip DOM XSS detection")
    toggle_group.add_argument("--skip-postmessage", action="store_true",
                              help="Skip postMessage handler detection")
    toggle_group.add_argument("--skip-redirect", action="store_true",
                              help="Skip open redirect detection")
    toggle_group.add_argument("--skip-pollution", action="store_true",
                              help="Skip prototype pollution detection")
    toggle_group.add_argument("--skip-storage", action="store_true",
                              help="Skip browser storage detection")
    toggle_group.add_argument("--skip-secrets", action="store_true",
                              help="Skip secret/credential scanning")
    toggle_group.add_argument("--skip-infra", action="store_true",
                              help="Skip internal infrastructure leakage detection")
    toggle_group.add_argument("--skip-endpoints", action="store_true",
                              help="Skip endpoint extraction")
    toggle_group.add_argument("--skip-admin", action="store_true",
                              help="Skip admin route detection")
    toggle_group.add_argument("--skip-idor", action="store_true",
                              help="Skip IDOR candidate detection")
    toggle_group.add_argument("--skip-client-validation", action="store_true",
                              help="Skip client-side validation detection")
    toggle_group.add_argument("--skip-libraries", action="store_true",
                              help="Skip library fingerprinting and CVE checks")

    # Module toggles — only run specific detectors
    only_group = parser.add_argument_group("Module toggles (only)")
    only_group.add_argument("--only-xss", action="store_true",
                            help="Run only DOM XSS / client-side execution flaw detectors")
    only_group.add_argument("--only-secrets", action="store_true",
                            help="Run only secret/credential scanning")
    only_group.add_argument("--only-endpoints", action="store_true",
                            help="Run only endpoint extraction")
    only_group.add_argument("--only-libraries", action="store_true",
                            help="Run only library fingerprinting")

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.guide:
        print_usage_guide(animate=True)
        return

    if not args.target:
        parser.print_help()
        sys.exit(2)

    # Determine which modules to run
    only_mode = any([args.only_xss, args.only_secrets, args.only_endpoints, args.only_libraries])

    run_xss = (args.only_xss or not only_mode) and not all([
        args.skip_xss, args.skip_postmessage, args.skip_redirect,
        args.skip_pollution, args.skip_storage
    ])
    run_secrets = (args.only_secrets or not only_mode) and not all([
        args.skip_secrets, args.skip_infra
    ])
    run_endpoints = (args.only_endpoints or not only_mode) and not all([
        args.skip_endpoints, args.skip_admin, args.skip_idor, args.skip_client_validation
    ])
    run_libs = (args.only_libraries or not only_mode) and not args.skip_libraries

    if not args.json:
        with _Spinner("Starting the JS Strike console...", enabled=True):
            if sys.stderr.isatty():
                time.sleep(0.28)
        print_banner(animate=True)
        print_scan_target(
            args.target,
            include_third_party=args.include_third_party,
            allow_domain=args.allow_domain,
        )

    # --- Phase 1: Fetch ---
    t_fetch = time.monotonic()
    try:
        with _Spinner("Fetching target page and scripts...", enabled=not args.json):
            scripts, source_map_findings = run_fetcher(
                args.target,
                include_third_party=args.include_third_party,
                allowed_domains=args.allow_domain,
            )
    except Exception as e:
        if not args.json:
            print(f"\n  {Color.RED}[!] Fatal: Could not fetch target — {e}{Color.RESET}", file=sys.stderr)
        else:
            import json
            print(json.dumps({"error": str(e), "findings": []}))
        sys.exit(1)

    if not args.json:
        fetch_elapsed = time.monotonic() - t_fetch
        inline_count = sum(1 for s in scripts if s.is_inline)
        external_count = sum(1 for s in scripts if not s.is_inline)
        print(
            f"  {Color.GREEN}{Color.BOLD}[+]{Color.RESET} Found {Color.BOLD}{len(scripts)}{Color.RESET} script(s) "
            f"({external_count} external, {inline_count} inline) {Color.DIM}[{fetch_elapsed:.2f}s]{Color.RESET}",
            file=sys.stderr,
        )

    all_findings: list[Finding] = list(source_map_findings)

    # --- Phase 2: Detection ---
    t_detect = time.monotonic()
    with _Spinner("Running security detectors...", enabled=not args.json):
        if run_xss:
            all_findings.extend(run_xss_detectors(
                scripts,
                skip_xss=args.skip_xss if not args.only_xss else False,
                skip_postmessage=args.skip_postmessage if not args.only_xss else False,
                skip_redirect=args.skip_redirect if not args.only_xss else False,
                skip_pollution=args.skip_pollution if not args.only_xss else False,
                skip_storage=args.skip_storage if not args.only_xss else False,
            ))

        if run_secrets:
            all_findings.extend(run_secret_detectors(
                scripts,
                skip_secrets=args.skip_secrets if not args.only_secrets else False,
                skip_infra=args.skip_infra if not args.only_secrets else False,
            ))

        if run_endpoints:
            all_findings.extend(run_endpoint_detectors(
                scripts,
                skip_endpoints=args.skip_endpoints if not args.only_endpoints else False,
                skip_admin=args.skip_admin if not args.only_endpoints else False,
                skip_idor=args.skip_idor if not args.only_endpoints else False,
                skip_client_validation=args.skip_client_validation if not args.only_endpoints else False,
            ))

        if run_libs:
            all_findings.extend(run_library_detectors(
                scripts,
                skip_libraries=False,
            ))

    # --- Phase 3: Filter by minimum severity ---
    min_sev_map = {
        "info": Severity.INFO,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }
    min_sev = min_sev_map[args.min_severity]
    sev_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    min_idx = sev_order.index(min_sev)
    all_findings = [f for f in all_findings if sev_order.index(f.severity) >= min_idx]

    # --- Phase 4: Report ---
    if not args.json:
        detect_elapsed = time.monotonic() - t_detect
        print(
            f"  {Color.GREEN}{Color.BOLD}[+]{Color.RESET} Analysis complete — {Color.BOLD}{len(all_findings)}{Color.RESET} finding(s) "
            f"{Color.DIM}[{detect_elapsed:.2f}s]{Color.RESET}\n",
            file=sys.stderr,
        )
        print_terminal_report(all_findings, verbose=args.verbose)
    else:
        print_json_report(all_findings)


if __name__ == "__main__":
    main()

