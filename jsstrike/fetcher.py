"""Fetcher module: HTML retrieval, script extraction, JS download, source map detection."""

import re
import sys
from urllib.parse import urljoin, urlparse
from typing import List, Optional, Tuple

import requests
from bs4 import BeautifulSoup

from .models import ScriptInfo, Finding, Category, Confidence, Severity

DEFAULT_TIMEOUT = 15
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


def _get_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    s.verify = True
    return s


def _is_in_scope(url: str, target_domain: str, include_third_party: bool,
                 allowed_domains: List[str]) -> bool:
    """Check if a URL is in scope based on domain filtering rules."""
    parsed = urlparse(url)
    host = parsed.hostname or ""

    if include_third_party:
        return True

    # Same domain or subdomain
    if host == target_domain or host.endswith("." + target_domain):
        return True

    # Allowed domains
    for ad in allowed_domains:
        if host == ad or host.endswith("." + ad):
            return True

    return False


def fetch_page(url: str, session: Optional[requests.Session] = None) -> Tuple[str, str]:
    """Fetch the HTML content of a page. Returns (html_content, final_url)."""
    s = session or _get_session()
    try:
        resp = s.get(url, timeout=DEFAULT_TIMEOUT)
        resp.raise_for_status()
        return resp.text, resp.url
    except requests.RequestException as e:
        print(f"[!] Failed to fetch {url}: {e}", file=sys.stderr)
        raise


def extract_scripts(html: str, base_url: str, target_domain: str,
                    include_third_party: bool = False,
                    allowed_domains: Optional[List[str]] = None) -> List[ScriptInfo]:
    """Extract all script references from HTML."""
    allowed_domains = allowed_domains or []
    scripts: List[ScriptInfo] = []
    soup = BeautifulSoup(html, "html.parser")

    inline_idx = 0
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            abs_url = urljoin(base_url, src)
            if _is_in_scope(abs_url, target_domain, include_third_party, allowed_domains):
                scripts.append(ScriptInfo(url=abs_url, content="", is_inline=False))
        else:
            text = tag.string
            if text and text.strip():
                inline_idx += 1
                scripts.append(ScriptInfo(
                    url=base_url,
                    content=text,
                    is_inline=True,
                    inline_index=inline_idx,
                ))

    return scripts


def download_js(script: ScriptInfo, session: Optional[requests.Session] = None) -> ScriptInfo:
    """Download an external JS file and populate its content."""
    if script.is_inline:
        return script

    s = session or _get_session()
    try:
        resp = s.get(script.url, timeout=DEFAULT_TIMEOUT)
        resp.raise_for_status()
        script.content = resp.text
    except requests.RequestException as e:
        print(f"[!] Failed to download {script.url}: {e}", file=sys.stderr)
        script.content = ""

    return script


SOURCE_MAP_RE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)")


def check_source_map(script: ScriptInfo,
                     session: Optional[requests.Session] = None) -> List[Finding]:
    """Check for source map references and attempt to fetch them."""
    findings: List[Finding] = []
    if not script.content:
        return findings

    match = SOURCE_MAP_RE.search(script.content)
    if not match:
        return findings

    map_ref = match.group(1)
    # Resolve relative URLs
    if map_ref.startswith("data:"):
        return findings

    map_url = urljoin(script.url, map_ref)
    script.source_map_url = map_url

    # Flag the existence
    line_no = script.content[:match.start()].count("\n") + 1
    findings.append(Finding(
        file_url=script.display_name,
        line_number=line_no,
        category=Category.SOURCE_MAP,
        snippet=f"//# sourceMappingURL={map_ref}",
        explanation=f"Source map reference found pointing to {map_url}",
        confidence=Confidence.HIGH,
        severity=Severity.MEDIUM,
        detector="source_map",
    ))

    # Try to fetch
    s = session or _get_session()
    try:
        resp = s.get(map_url, timeout=DEFAULT_TIMEOUT)
        if resp.status_code == 200:
            script.source_map_content = resp.text
            # Try to parse file list
            try:
                import json
                sm = json.loads(resp.text)
                sources = sm.get("sources", [])
                script.source_map_files = sources
                if sources:
                    findings.append(Finding(
                        file_url=script.display_name,
                        line_number=line_no,
                        category=Category.SOURCE_MAP,
                        snippet=f"Source map contains {len(sources)} source files",
                        explanation=f"Reconstructed source tree: {', '.join(sources[:10])}{'...' if len(sources) > 10 else ''}",
                        confidence=Confidence.HIGH,
                        severity=Severity.HIGH,
                        detector="source_map",
                    ))
            except (json.JSONDecodeError, KeyError):
                pass
    except requests.RequestException:
        pass  # Map not fetchable, that's fine — we still flagged its existence

    return findings


def run_fetcher(target_url: str, include_third_party: bool = False,
                allowed_domains: Optional[List[str]] = None) -> Tuple[List[ScriptInfo], List[Finding]]:
    """Main fetcher pipeline: fetch page, extract scripts, download JS, check maps."""
    allowed_domains = allowed_domains or []
    session = _get_session()

    parsed = urlparse(target_url)
    target_domain = parsed.hostname or ""

    html, final_url = fetch_page(target_url, session)
    scripts = extract_scripts(html, final_url, target_domain, include_third_party, allowed_domains)

    if not scripts:
        print("[*] No scripts found on the page.", file=sys.stderr)

    findings: List[Finding] = []

    for i, script in enumerate(scripts):
        if not script.is_inline:
            download_js(script, session)
            if script.content:
                sm_findings = check_source_map(script, session)
                findings.extend(sm_findings)
        else:
            sm_findings = check_source_map(script, session)
            findings.extend(sm_findings)

    # Filter out scripts with no content
    scripts = [s for s in scripts if s.content]

    return scripts, findings

