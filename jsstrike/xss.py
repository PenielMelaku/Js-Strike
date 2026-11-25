"""Client-side execution flaw detectors: DOM XSS, postMessage, open redirect,
prototype pollution, sensitive browser storage."""

import re
from typing import List

from .models import Finding, ScriptInfo, Category, Confidence, Severity


# ---------------------------------------------------------------------------
# DOM-based XSS
# ---------------------------------------------------------------------------

XSS_SOURCES = [
    (r"location\s*\.\s*hash", "location.hash"),
    (r"location\s*\.\s*search", "location.search"),
    (r"location\s*\.\s*href", "location.href (as source)"),
    (r"document\s*\.\s*URL", "document.URL"),
    (r"document\s*\.\s*documentURI", "document.documentURI"),
    (r"document\s*\.\s*referrer", "document.referrer"),
    (r"window\s*\.\s*name", "window.name"),
    (r"document\s*\.\s*cookie", "document.cookie (as source)"),
    (r"(?:event|e|evt|msg)\s*\.\s*data", "postMessage event.data"),
    (r"URLSearchParams\s*\(", "URLSearchParams"),
    (r"location\s*\.\s*pathname", "location.pathname"),
]

XSS_SINKS = [
    (r"\.innerHTML\s*=", "innerHTML assignment"),
    (r"\.outerHTML\s*=", "outerHTML assignment"),
    (r"\beval\s*\(", "eval()"),
    (r"document\s*\.\s*write\s*\(", "document.write()"),
    (r"document\s*\.\s*writeln\s*\(", "document.writeln()"),
    (r"\.insertAdjacentHTML\s*\(", "insertAdjacentHTML()"),
    (r"dangerouslySetInnerHTML", "dangerouslySetInnerHTML"),
    (r"\$\s*\([^)]*\)\s*\.\s*html\s*\(", "jQuery .html()"),
    (r"\$\s*\([^)]*\)\s*\.\s*append\s*\(", "jQuery .append()"),
    (r"\$\s*\([^)]*\)\s*\.\s*prepend\s*\(", "jQuery .prepend()"),
    (r"new\s+Function\s*\(", "new Function()"),
    (r"setTimeout\s*\(\s*['\"]", "setTimeout with string"),
    (r"setInterval\s*\(\s*['\"]", "setInterval with string"),
]

PROXIMITY_WINDOW = 8  # lines


def _get_line_number(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def _snippet(content: str, pos: int, length: int = 120) -> str:
    start = max(0, pos - 20)
    end = min(len(content), pos + length)
    snip = content[start:end].replace("\n", "\\n").strip()
    if len(snip) > 150:
        snip = snip[:150] + "..."
    return snip


def detect_dom_xss(script: ScriptInfo) -> List[Finding]:
    findings: List[Finding] = []
    content = script.content
    if not content:
        return findings

    source_hits = []
    for pattern, name in XSS_SOURCES:
        for m in re.finditer(pattern, content):
            line = _get_line_number(content, m.start())
            source_hits.append((line, m.start(), name, m.group()))

    sink_hits = []
    for pattern, name in XSS_SINKS:
        for m in re.finditer(pattern, content):
            line = _get_line_number(content, m.start())
            sink_hits.append((line, m.start(), name, m.group()))

    # Check for source-sink proximity
    reported_sinks = set()
    for s_line, s_pos, s_name, s_match in source_hits:
        for k_line, k_pos, k_name, k_match in sink_hits:
            if abs(s_line - k_line) <= PROXIMITY_WINDOW:
                confidence = Confidence.HIGH
                severity = Severity.HIGH
            else:
                confidence = Confidence.MEDIUM
                severity = Severity.MEDIUM

            sink_key = (k_line, k_name)
            if sink_key in reported_sinks:
                continue
            reported_sinks.add(sink_key)

            findings.append(Finding(
                file_url=script.display_name,
                line_number=k_line,
                category=Category.DOM_XSS,
                snippet=_snippet(content, k_pos),
                explanation=f"Source '{s_name}' (line {s_line}) flows to sink '{k_name}' (line {k_line})",
                confidence=confidence,
                severity=severity,
                detector="dom_xss",
            ))

    # Standalone sinks (still worth flagging even without nearby source)
    for k_line, k_pos, k_name, k_match in sink_hits:
        if (k_line, k_name) not in reported_sinks:
            findings.append(Finding(
                file_url=script.display_name,
                line_number=k_line,
                category=Category.DOM_XSS,
                snippet=_snippet(content, k_pos),
                explanation=f"Dangerous sink '{k_name}' found — verify if user-controlled data reaches it",
                confidence=Confidence.LOW,
                severity=Severity.LOW,
                detector="dom_xss",
            ))

    return findings


# ---------------------------------------------------------------------------
# Insecure postMessage handlers
# ---------------------------------------------------------------------------

POSTMESSAGE_LISTENER = re.compile(
    r"""addEventListener\s*\(\s*['"]message['"]\s*,\s*(?:function\s*\((\w+)\)|(\w+)\s*=>|\((\w+)\)\s*=>)""",
    re.DOTALL,
)

ORIGIN_CHECK = re.compile(r"""(?:event|e|evt|msg)\s*\.\s*origin""")


def detect_postmessage(script: ScriptInfo) -> List[Finding]:
    findings: List[Finding] = []
    content = script.content
    if not content:
        return findings

    for m in POSTMESSAGE_LISTENER.finditer(content):
        line = _get_line_number(content, m.start())
        # Look for origin check in the next 30 lines
        end_search = min(len(content), m.end() + 2000)
        region = content[m.start():end_search]

        if not ORIGIN_CHECK.search(region):
            findings.append(Finding(
                file_url=script.display_name,
                line_number=line,
                category=Category.POSTMESSAGE,
                snippet=_snippet(content, m.start()),
                explanation="postMessage listener without event.origin validation — any origin can send messages",
                confidence=Confidence.HIGH,
                severity=Severity.HIGH,
                detector="postmessage",
            ))
        else:
            findings.append(Finding(
                file_url=script.display_name,
                line_number=line,
                category=Category.POSTMESSAGE,
                snippet=_snippet(content, m.start()),
                explanation="postMessage listener found with apparent origin check — verify it is strict",
                confidence=Confidence.LOW,
                severity=Severity.INFO,
                detector="postmessage",
            ))

    return findings


# ---------------------------------------------------------------------------
# DOM-based open redirect
# ---------------------------------------------------------------------------

REDIRECT_SINKS = [
    (r"location\s*\.\s*href\s*=\s*", "location.href assignment"),
    (r"location\s*\.\s*assign\s*\(", "location.assign()"),
    (r"location\s*\.\s*replace\s*\(", "location.replace()"),
    (r"window\s*\.\s*open\s*\(", "window.open()"),
]

URL_SOURCES = [
    r"location\s*\.\s*hash",
    r"location\s*\.\s*search",
    r"document\s*\.\s*URL",
    r"document\s*\.\s*referrer",
    r"URLSearchParams",
    r"getParameter",
    r"url\s*[\[.]",
    r"params?\s*[\[.]",
    r"query\s*[\[.]",
    r"redirect",
    r"next",
    r"return_?to",
    r"redir",
    r"goto",
]


def detect_open_redirect(script: ScriptInfo) -> List[Finding]:
    findings: List[Finding] = []
    content = script.content
    if not content:
        return findings

    for pattern, name in REDIRECT_SINKS:
        for m in re.finditer(pattern, content):
            line = _get_line_number(content, m.start())
            # Check the region around the sink for URL-controlled input
            start = max(0, m.start() - 500)
            end = min(len(content), m.end() + 300)
            region = content[start:end]

            has_source = any(re.search(sp, region) for sp in URL_SOURCES)
            if has_source:
                findings.append(Finding(
                    file_url=script.display_name,
                    line_number=line,
                    category=Category.OPEN_REDIRECT,
                    snippet=_snippet(content, m.start()),
                    explanation=f"URL-controlled value flows into redirect sink '{name}'",
                    confidence=Confidence.HIGH,
                    severity=Severity.MEDIUM,
                    detector="open_redirect",
                ))

    return findings


# ---------------------------------------------------------------------------
# Client-side prototype pollution
# ---------------------------------------------------------------------------

PROTO_POLLUTION_PATTERNS = [
    # Recursive merge/clone/extend without __proto__ filtering
    (r"function\s+\w*(?:merge|extend|clone|assign|mixin|deepCopy)\w*\s*\(", "recursive merge/extend function"),
    (r"(?:__proto__|constructor\s*\.\s*prototype|prototype\s*\.\s*constructor)", "direct __proto__/constructor.prototype access"),
    (r"\[\s*['\"]__proto__['\"]\s*\]", "__proto__ bracket access"),
    (r"\bObject\s*\.\s*assign\s*\(", "Object.assign (potential PP if target is prototype)"),
]

PROTO_FILTER_CHECK = re.compile(r"""(?:__proto__|constructor|prototype)\s*[!=]==?\s*|hasOwnProperty|Object\.keys""")


def detect_prototype_pollution(script: ScriptInfo) -> List[Finding]:
    findings: List[Finding] = []
    content = script.content
    if not content:
        return findings

    for pattern, name in PROTO_POLLUTION_PATTERNS:
        for m in re.finditer(pattern, content):
            line = _get_line_number(content, m.start())
            # Check if there's a filter nearby
            start = max(0, m.start() - 300)
            end = min(len(content), m.end() + 500)
            region = content[start:end]

            if "__proto__" in m.group() or "constructor" in m.group():
                confidence = Confidence.HIGH
                severity = Severity.HIGH
            elif PROTO_FILTER_CHECK.search(region):
                confidence = Confidence.LOW
                severity = Severity.LOW
            else:
                confidence = Confidence.MEDIUM
                severity = Severity.MEDIUM

            findings.append(Finding(
                file_url=script.display_name,
                line_number=line,
                category=Category.PROTOTYPE_POLLUTION,
                snippet=_snippet(content, m.start()),
                explanation=f"Potential prototype pollution via {name}",
                confidence=confidence,
                severity=severity,
                detector="prototype_pollution",
            ))

    return findings


# ---------------------------------------------------------------------------
# Sensitive data in browser storage
# ---------------------------------------------------------------------------

STORAGE_PATTERNS = [
    (r"localStorage\s*\.\s*setItem\s*\(\s*['\"]([^'\"]+)['\"]\s*,", "localStorage.setItem"),
    (r"sessionStorage\s*\.\s*setItem\s*\(\s*['\"]([^'\"]+)['\"]\s*,", "sessionStorage.setItem"),
    (r"localStorage\s*\[\s*['\"]([^'\"]+)['\"]\s*\]\s*=", "localStorage bracket assignment"),
    (r"sessionStorage\s*\[\s*['\"]([^'\"]+)['\"]\s*\]\s*=", "sessionStorage bracket assignment"),
]

SENSITIVE_KEY_PATTERNS = re.compile(
    r"(?:token|jwt|auth|session|secret|password|passwd|credential|api[_-]?key|access[_-]?key|private[_-]?key|bearer|refresh[_-]?token|id[_-]?token|ssn|credit[_-]?card|cvv)",
    re.IGNORECASE,
)


def detect_storage_sensitive(script: ScriptInfo) -> List[Finding]:
    findings: List[Finding] = []
    content = script.content
    if not content:
        return findings

    for pattern, storage_type in STORAGE_PATTERNS:
        for m in re.finditer(pattern, content):
            key_name = m.group(1)
            line = _get_line_number(content, m.start())

            if SENSITIVE_KEY_PATTERNS.search(key_name):
                findings.append(Finding(
                    file_url=script.display_name,
                    line_number=line,
                    category=Category.STORAGE_SENSITIVE,
                    snippet=_snippet(content, m.start()),
                    explanation=f"Sensitive value '{key_name}' stored in {storage_type}",
                    confidence=Confidence.HIGH,
                    severity=Severity.HIGH,
                    detector="storage_sensitive",
                ))

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_xss_detectors(scripts: List[ScriptInfo],
                      skip_xss=False, skip_postmessage=False,
                      skip_redirect=False, skip_pollution=False,
                      skip_storage=False) -> List[Finding]:
    """Run all client-side execution flaw detectors."""
    findings: List[Finding] = []
    for script in scripts:
        if not skip_xss:
            findings.extend(detect_dom_xss(script))
        if not skip_postmessage:
            findings.extend(detect_postmessage(script))
        if not skip_redirect:
            findings.extend(detect_open_redirect(script))
        if not skip_pollution:
            findings.extend(detect_prototype_pollution(script))
        if not skip_storage:
            findings.extend(detect_storage_sensitive(script))
    return findings
