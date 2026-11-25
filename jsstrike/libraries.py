"""Library fingerprinting and version-based vulnerability detection."""

import re
from typing import List, Dict, Tuple, Optional

from .models import Finding, ScriptInfo, Category, Confidence, Severity


# ---------------------------------------------------------------------------
# Library fingerprinting signatures
# ---------------------------------------------------------------------------

# (regex_pattern, library_name, version_group_index)
LIBRARY_SIGNATURES = [
    # jQuery — prefer the more specific patterns first
    (r"jQuery\s+(?:JavaScript\s+Library\s+)?v(\d+\.\d+(?:\.\d+)?)", "jQuery"),
    (r'jquery:\s*["\'](\d+\.\d+\.\d+)["\']', "jQuery"),
    (r"jquery\.min\.js\?v=(\d+\.\d+(?:\.\d+)?)", "jQuery"),
    (r"jquery[^\n]{0,20}v(\d+\.\d+\.\d+)", "jQuery"),

    # Angular (1.x)
    (r"angular(?:\.min)?\.js[^\n]{0,30}v?(\d+\.\d+(?:\.\d+)?)", "AngularJS"),
    (r"angular\s*\.\s*version\s*[:=]\s*\{[^}]*full\s*:\s*['\"](\d+\.\d+(?:\.\d+)?)['\"]", "AngularJS"),

    # React
    (r"react(?:\.production|\.development)?\.min\.js[^\n]{0,20}v?(\d+\.\d+(?:\.\d+)?)", "React"),
    (r"React\.version\s*=\s*['\"](\d+\.\d+(?:\.\d+)?)['\"]", "React"),

    # Vue
    (r"vue(?:\.min|\.runtime)?\.js[^\n]{0,30}v?(\d+\.\d+(?:\.\d+)?)", "Vue.js"),
    (r"Vue\.version\s*=\s*['\"](\d+\.\d+(?:\.\d+)?)['\"]", "Vue.js"),

    # Lodash
    (r"lodash(?:\.min)?\.js[^\n]{0,20}v?(\d+\.\d+(?:\.\d+)?)", "Lodash"),
    (r"lodash\s+(\d+\.\d+(?:\.\d+)?)", "Lodash"),
    (r"VERSION\s*=\s*['\"](\d+\.\d+\.\d+)['\"];\s*\n.*lodash", "Lodash"),

    # Underscore
    (r"underscore(?:\.min)?\.js[^\n]{0,20}v?(\d+\.\d+(?:\.\d+)?)", "Underscore.js"),

    # Bootstrap
    (r"bootstrap(?:\.min)?\.js[^\n]{0,30}v?(\d+\.\d+(?:\.\d+)?)", "Bootstrap"),
    (r"Bootstrap\s+v(\d+\.\d+(?:\.\d+)?)", "Bootstrap"),

    # Moment.js
    (r"moment(?:\.min)?\.js[^\n]{0,20}v?(\d+\.\d+(?:\.\d+)?)", "Moment.js"),
    (r"momentjs\.com[^\n]{0,20}(\d+\.\d+(?:\.\d+)?)", "Moment.js"),

    # D3
    (r"d3(?:\.min)?\.js[^\n]{0,20}v?(\d+\.\d+(?:\.\d+)?)", "D3.js"),

    # Handlebars
    (r"handlebars(?:\.min)?\.js[^\n]{0,20}v?(\d+\.\d+(?:\.\d+)?)", "Handlebars.js"),

    # Backbone
    (r"backbone(?:\.min)?\.js[^\n]{0,20}v?(\d+\.\d+(?:\.\d+)?)", "Backbone.js"),

    # Ember
    (r"ember(?:\.min)?\.js[^\n]{0,20}v?(\d+\.\d+(?:\.\d+)?)", "Ember.js"),

    # Knockout
    (r"knockout(?:\.min)?\.js[^\n]{0,20}v?(\d+\.\d+(?:\.\d+)?)", "Knockout.js"),

    # Axios
    (r"axios(?:\.min)?\.js[^\n]{0,20}v?(\d+\.\d+(?:\.\d+)?)", "Axios"),

    # Socket.io
    (r"socket\.io(?:\.min)?\.js[^\n]{0,20}v?(\d+\.\d+(?:\.\d+)?)", "Socket.io"),

    # DOMPurify
    (r"DOMPurify[^\n]{0,20}(\d+\.\d+(?:\.\d+)?)", "DOMPurify"),

    # CKEditor
    (r"ckeditor[^\n]{0,20}(\d+\.\d+(?:\.\d+)?)", "CKEditor"),

    # TinyMCE
    (r"tinymce[^\n]{0,20}(\d+\.\d+(?:\.\d+)?)", "TinyMCE"),

    # Prototype.js
    (r"prototype(?:\.min)?\.js[^\n]{0,20}v?(\d+\.\d+(?:\.\d+)?)", "Prototype.js"),
]

# ---------------------------------------------------------------------------
# CVE/vulnerability lookup table (extensible)
# ---------------------------------------------------------------------------

# Format: library_name -> [(affected_version_range, cve_id, severity, description)]
# Version ranges: ("< 3.5.0", ...) or (">=1.0.0 <1.6.3", ...)
CVE_DATABASE: Dict[str, List[Tuple[str, str, Severity, str]]] = {
    "jQuery": [
        ("<1.9.0", "CVE-2012-6708", Severity.MEDIUM, "XSS via selector interpretation of location.hash"),
        ("<3.5.0", "CVE-2020-11022", Severity.MEDIUM, "XSS in jQuery.htmlPrefilter — passing untrusted HTML to DOM manipulation methods"),
        ("<3.5.0", "CVE-2020-11023", Severity.MEDIUM, "XSS when passing <option> elements to DOM methods"),
        ("<3.0.0", "CVE-2015-9251", Severity.MEDIUM, "XSS vulnerability in cross-domain Ajax request handling"),
    ],
    "AngularJS": [
        ("<1.6.9", "CVE-2019-10768", Severity.HIGH, "Prototype pollution in merge function"),
        ("<1.8.0", "Multiple", Severity.HIGH, "AngularJS 1.x is EOL — multiple known XSS via template injection"),
    ],
    "Lodash": [
        ("<4.17.12", "CVE-2019-10744", Severity.CRITICAL, "Prototype pollution in defaultsDeep"),
        ("<4.17.21", "CVE-2021-23337", Severity.HIGH, "Command injection via template function"),
    ],
    "Bootstrap": [
        ("<3.4.0", "CVE-2018-14040", Severity.MEDIUM, "XSS via collapse data-parent attribute"),
        ("<3.4.0", "CVE-2018-14041", Severity.MEDIUM, "XSS via tooltip data-container attribute"),
        ("<3.4.0", "CVE-2018-14042", Severity.MEDIUM, "XSS via data-target attribute"),
        ("<3.4.1", "CVE-2019-8331", Severity.MEDIUM, "XSS in tooltip/popover data-template attribute"),
    ],
    "Moment.js": [
        ("<2.29.4", "CVE-2022-31129", Severity.HIGH, "ReDoS via specially crafted date strings"),
        ("*", "EOL", Severity.LOW, "Moment.js is in maintenance mode / EOL — consider dayjs or date-fns"),
    ],
    "Handlebars.js": [
        ("<4.7.7", "CVE-2021-23369", Severity.CRITICAL, "Remote code execution via template compilation"),
        ("<4.7.7", "CVE-2021-23383", Severity.CRITICAL, "Prototype pollution leading to RCE"),
    ],
    "Underscore.js": [
        ("<1.13.6", "CVE-2021-23358", Severity.HIGH, "Arbitrary code execution via template function"),
    ],
    "DOMPurify": [
        ("<2.3.6", "CVE-2022-25890", Severity.HIGH, "mXSS bypass via namespace confusion"),
    ],
    "Prototype.js": [
        ("*", "EOL", Severity.MEDIUM, "Prototype.js is EOL / unmaintained — multiple historical XSS and pollution vectors"),
    ],
    "React": [],
    "Vue.js": [],
    "Axios": [],
    "Socket.io": [],
}

# EOL / outdated thresholds (library -> minimum recommended version)
EOL_THRESHOLDS: Dict[str, str] = {
    "jQuery": "3.6.0",
    "AngularJS": "999.0.0",  # All AngularJS 1.x is EOL
    "Bootstrap": "5.0.0",
    "Moment.js": "999.0.0",  # EOL
    "Prototype.js": "999.0.0",  # EOL
    "Underscore.js": "1.13.0",
    "Backbone.js": "999.0.0",  # Effectively EOL
}


def _parse_version(version_str: str) -> Tuple[int, ...]:
    """Parse a version string into a tuple of ints for comparison."""
    try:
        parts = version_str.strip().split(".")
        return tuple(int(p) for p in parts)
    except (ValueError, AttributeError):
        return (0,)


def _version_matches(version: str, constraint: str) -> bool:
    """Check if a version matches a constraint like '<3.5.0' or '*'."""
    if constraint == "*":
        return True

    ver = _parse_version(version)

    # Handle compound: ">=1.0.0 <1.6.3"
    parts = constraint.split()
    for part in parts:
        if part.startswith("<="):
            if not (ver <= _parse_version(part[2:])):
                return False
        elif part.startswith("<"):
            if not (ver < _parse_version(part[1:])):
                return False
        elif part.startswith(">="):
            if not (ver >= _parse_version(part[2:])):
                return False
        elif part.startswith(">"):
            if not (ver > _parse_version(part[1:])):
                return False
        elif part.startswith("=="):
            if not (ver == _parse_version(part[2:])):
                return False

    return True


def _get_line_number(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def _snippet(content: str, pos: int, length: int = 120) -> str:
    start = max(0, pos - 20)
    end = min(len(content), pos + length)
    snip = content[start:end].replace("\n", "\\n").strip()
    if len(snip) > 150:
        snip = snip[:150] + "..."
    return snip


def fingerprint_libraries(script: ScriptInfo) -> List[Finding]:
    """Identify JS libraries and their versions in script content."""
    findings: List[Finding] = []
    content = script.content
    if not content:
        return findings

    detected: Dict[str, str] = {}  # library -> version (keep first/best match)

    for pattern, lib_name in LIBRARY_SIGNATURES:
        if lib_name in detected:
            continue
        m = re.search(pattern, content, re.IGNORECASE)
        if m:
            version = m.group(1) if m.lastindex else "unknown"
            detected[lib_name] = version
            line = _get_line_number(content, m.start())

            findings.append(Finding(
                file_url=script.display_name,
                line_number=line,
                category=Category.LIBRARY_DETECTED,
                snippet=_snippet(content, m.start()),
                explanation=f"{lib_name} v{version} detected",
                confidence=Confidence.HIGH,
                severity=Severity.INFO,
                detector="libraries",
            ))

    # CVE check
    for lib_name, version in detected.items():
        if version == "unknown":
            continue

        cves = CVE_DATABASE.get(lib_name, [])
        for constraint, cve_id, severity, description in cves:
            if _version_matches(version, constraint):
                findings.append(Finding(
                    file_url=script.display_name,
                    line_number=1,
                    category=Category.VULNERABLE_LIBRARY,
                    snippet=f"{lib_name} v{version}",
                    explanation=f"{cve_id}: {description}",
                    confidence=Confidence.HIGH,
                    severity=severity,
                    detector="library_cve",
                ))

        # EOL check
        threshold = EOL_THRESHOLDS.get(lib_name)
        if threshold and _parse_version(version) < _parse_version(threshold):
            # Only add if not already flagged with a CVE at same or higher severity
            already_flagged = any(
                f.category == Category.VULNERABLE_LIBRARY and lib_name in f.snippet
                for f in findings
            )
            if not already_flagged:
                findings.append(Finding(
                    file_url=script.display_name,
                    line_number=1,
                    category=Category.OUTDATED_LIBRARY,
                    snippet=f"{lib_name} v{version}",
                    explanation=f"{lib_name} v{version} is outdated — current recommended minimum is {threshold}",
                    confidence=Confidence.HIGH,
                    severity=Severity.LOW,
                    detector="library_eol",
                ))

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_library_detectors(scripts: List[ScriptInfo],
                          skip_libraries=False) -> List[Finding]:
    """Run library fingerprinting and vulnerability detection."""
    if skip_libraries:
        return []

    findings: List[Finding] = []
    for script in scripts:
        findings.extend(fingerprint_libraries(script))
    return findings
