"""Endpoint and route extraction, admin/IDOR flagging, client-side validation detection."""

import re
from typing import List, Set

from .models import Finding, ScriptInfo, Category, Confidence, Severity


# ---------------------------------------------------------------------------
# LinkFinder-style endpoint extraction
# ---------------------------------------------------------------------------

# Broad JS string regex for paths/URLs — adapted from LinkFinder
ENDPOINT_PATTERNS = [
    # Quoted strings that look like API paths
    re.compile(
        r"""(?:"|'|`)"""                          # opening quote
        r"""("""
        r"""(?:[a-zA-Z]{1,10}://|//)"""           # scheme or protocol-relative
        r"""[^"'`\s]{5,}"""                        # rest of URL
        r"""|"""
        r"""(?:/(?:[a-zA-Z0-9_\-.]/?)+)"""        # absolute path like /api/v1/users
        r"""|"""
        r"""(?:[a-zA-Z0-9_\-.]+/[a-zA-Z0-9_\-./?&=]+)"""  # relative path with /
        r""")"""
        r"""(?:"|'|`)""",                          # closing quote
        re.MULTILINE,
    ),
    # fetch/axios/XMLHttpRequest URL arguments
    re.compile(
        r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|\.open)\s*\(\s*(?:'|"|`)([^'"`\s]+)(?:'|"|`)""",
        re.MULTILINE,
    ),
]

# Interesting path keywords for escalated flagging
ADMIN_KEYWORDS = re.compile(
    r"(?:admin|internal|debug|swagger|graphql|console|dashboard|manage|config|settings|staff|super)",
    re.IGNORECASE,
)

IDOR_PATTERNS = re.compile(
    r"(?:/(?:user|account|profile|order|invoice|document|file|message|report)s?/)"
    r"(?:\{[^}]+\}|:\w+|[0-9]+)",
    re.IGNORECASE,
)

API_VERSION_PATTERN = re.compile(r"/(?:api/)?v[0-9]+/", re.IGNORECASE)


def _get_line_number(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def _snippet(content: str, pos: int, length: int = 120) -> str:
    start = max(0, pos - 20)
    end = min(len(content), pos + length)
    snip = content[start:end].replace("\n", "\\n").strip()
    if len(snip) > 150:
        snip = snip[:150] + "..."
    return snip


def _is_noise(path: str) -> bool:
    """Filter out common noise like file extensions for images, CSS, etc."""
    noise_ext = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.css',
                 '.woff', '.woff2', '.ttf', '.eot', '.map', '.webp', '.mp4',
                 '.mp3', '.pdf', '.zip', '.gz')
    if path.lower().endswith(noise_ext):
        return True
    # Too short to be meaningful
    if len(path.rstrip("/")) < 4:
        return True
    # Skip things that are clearly just version numbers or hashes
    if re.fullmatch(r"[0-9a-f]{6,}", path.strip("/")):
        return True
    return False


def extract_endpoints(script: ScriptInfo) -> List[Finding]:
    """Extract paths/routes referenced in JS strings (LinkFinder-style)."""
    findings: List[Finding] = []
    content = script.content
    if not content:
        return findings

    seen: Set[str] = set()

    for pattern in ENDPOINT_PATTERNS:
        for m in pattern.finditer(content):
            path = m.group(1)
            if path in seen or _is_noise(path):
                continue
            seen.add(path)

            line = _get_line_number(content, m.start())
            severity = Severity.INFO
            confidence = Confidence.MEDIUM
            explanation = f"Extracted endpoint: {path}"

            # Upgrade severity for interesting patterns
            if ADMIN_KEYWORDS.search(path):
                severity = Severity.MEDIUM
                explanation = f"Admin/internal route found: {path}"

            if API_VERSION_PATTERN.search(path):
                confidence = Confidence.HIGH

            findings.append(Finding(
                file_url=script.display_name,
                line_number=line,
                category=Category.ENDPOINT,
                snippet=_snippet(content, m.start()),
                explanation=explanation,
                confidence=confidence,
                severity=severity,
                detector="endpoints",
            ))

    return findings


def detect_admin_routes(script: ScriptInfo) -> List[Finding]:
    """Flag routes containing admin, internal, debug, etc."""
    findings: List[Finding] = []
    content = script.content
    if not content:
        return findings

    # Look for string references to admin-like paths
    admin_path_re = re.compile(
        r"""(?:"|'|`)(/[a-zA-Z0-9_\-./]*(?:admin|internal|debug|swagger|graphql|console|dashboard|manage|config|staff)[a-zA-Z0-9_\-./]*)(?:"|'|`)""",
        re.IGNORECASE,
    )

    seen: Set[str] = set()
    for m in admin_path_re.finditer(content):
        path = m.group(1)
        if path in seen:
            continue
        seen.add(path)

        line = _get_line_number(content, m.start())
        findings.append(Finding(
            file_url=script.display_name,
            line_number=line,
            category=Category.ADMIN_ROUTE,
            snippet=_snippet(content, m.start()),
            explanation=f"Admin/internal/debug route reference: {path}",
            confidence=Confidence.HIGH,
            severity=Severity.MEDIUM,
            detector="admin_routes",
        ))

    return findings


def detect_idor_candidates(script: ScriptInfo) -> List[Finding]:
    """Flag routes with ID-like parameters (/user/{id}, /order/:id, etc.)."""
    findings: List[Finding] = []
    content = script.content
    if not content:
        return findings

    # Match paths that contain resource-name + ID pattern (concatenation, template, or literal)
    # e.g. "/api/v2/users/" + id, "/orders/{orderId}", "/invoices/:id/download"
    idor_re = re.compile(
        r"""(?:"|'|`)([a-zA-Z0-9_\-./]*"""
        r"""(?:/(?:user|account|profile|order|invoice|document|file|message|report|item|project|team|org|workspace|payment)s?/)"""
        r"""(?:\{[^}]+\}|:\w+|[0-9]+)?"""
        r"""[a-zA-Z0-9_\-./]*)(?:"|'|`)""",
        re.IGNORECASE,
    )

    seen: Set[str] = set()
    for m in idor_re.finditer(content):
        path = m.group(1)
        if path in seen:
            continue
        seen.add(path)

        line = _get_line_number(content, m.start())
        findings.append(Finding(
            file_url=script.display_name,
            line_number=line,
            category=Category.IDOR_CANDIDATE,
            snippet=_snippet(content, m.start()),
            explanation=f"IDOR/BAC candidate — route with object ID: {path}",
            confidence=Confidence.MEDIUM,
            severity=Severity.MEDIUM,
            detector="idor_candidates",
        ))

    return findings


# ---------------------------------------------------------------------------
# Client-side validation detection
# ---------------------------------------------------------------------------

CLIENT_VALIDATION_PATTERNS = [
    # Price / amount computed client-side
    (re.compile(
        r"(?:price|amount|total|cost|subtotal|discount|balance)\s*(?:=|\+=|-=)\s*",
        re.IGNORECASE,
    ), "Client-side price/amount computation"),

    # Role / permission check in JS
    (re.compile(
        r"""(?:role|permission|isAdmin|is_admin|isStaff|is_staff|isModerator|hasPermission|canAccess|authorized)\s*(?:===?\s*['"]|!==?\s*['"]|\?\.)""",
        re.IGNORECASE,
    ), "Client-side role/permission check"),

    # Conditional on user role
    (re.compile(
        r"""if\s*\(\s*(?:user|currentUser|auth|session)\s*\.\s*(?:role|admin|is[A-Z]\w*|permission|level)\b""",
        re.IGNORECASE,
    ), "Client-side authorization conditional"),
]


def detect_client_validation(script: ScriptInfo) -> List[Finding]:
    """Flag logic blocks computing price/role/permission checks purely in JS."""
    findings: List[Finding] = []
    content = script.content
    if not content:
        return findings

    for pattern, label in CLIENT_VALIDATION_PATTERNS:
        for m in pattern.finditer(content):
            line = _get_line_number(content, m.start())
            findings.append(Finding(
                file_url=script.display_name,
                line_number=line,
                category=Category.CLIENT_VALIDATION,
                snippet=_snippet(content, m.start()),
                explanation=f"{label} — verify server-side enforcement exists",
                confidence=Confidence.MEDIUM,
                severity=Severity.MEDIUM,
                detector="client_validation",
            ))

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_endpoint_detectors(scripts: List[ScriptInfo],
                           skip_endpoints=False, skip_admin=False,
                           skip_idor=False, skip_client_validation=False) -> List[Finding]:
    """Run all endpoint/route detectors."""
    findings: List[Finding] = []
    for script in scripts:
        if not skip_endpoints:
            findings.extend(extract_endpoints(script))
        if not skip_admin:
            findings.extend(detect_admin_routes(script))
        if not skip_idor:
            findings.extend(detect_idor_candidates(script))
        if not skip_client_validation:
            findings.extend(detect_client_validation(script))
    return findings
