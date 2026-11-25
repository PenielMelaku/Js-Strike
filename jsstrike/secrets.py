"""Secret scanner and internal infrastructure leakage detector."""

import re
from typing import List

from .models import Finding, ScriptInfo, Category, Confidence, Severity


# ---------------------------------------------------------------------------
# Secret / credential regex patterns
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    # AWS
    (r"(?<![A-Za-z0-9/+=])AKIA[0-9A-Z]{16}(?![A-Za-z0-9/+=])", "AWS Access Key ID", Severity.CRITICAL),
    (r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])", None, None),  # skip raw 40-char (too noisy)
    (r"aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"]([^'\"]{20,})['\"]", "AWS Secret Access Key", Severity.CRITICAL),

    # Google / GCP
    (r"AIza[0-9A-Za-z_-]{35}", "Google API Key", Severity.HIGH),
    (r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com", "Google OAuth Client ID", Severity.MEDIUM),

    # Firebase
    (r"(?:apiKey|authDomain|databaseURL|storageBucket|messagingSenderId|appId|measurementId)\s*:\s*['\"]([^'\"]+)['\"]",
     "Firebase Config Value", Severity.MEDIUM),

    # Stripe
    (r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}", "Stripe API Key", Severity.CRITICAL),

    # Slack
    (r"xox[bporas]-[0-9A-Za-z-]{10,}", "Slack Token", Severity.CRITICAL),
    (r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", "Slack Webhook URL", Severity.HIGH),

    # GitHub
    (r"gh[ps]_[A-Za-z0-9_]{30,}", "GitHub Token", Severity.CRITICAL),
    (r"github_pat_[A-Za-z0-9_]{22,}", "GitHub Fine-Grained PAT", Severity.CRITICAL),

    # JWT
    (r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JSON Web Token (JWT)", Severity.HIGH),

    # Generic API keys/tokens
    (r"""(?:api[_-]?key|api[_-]?secret|app[_-]?key|app[_-]?secret|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key)\s*[:=]\s*['\"]([^'\"]{8,})['\"]""",
     "Generic API Key / Token", Severity.HIGH),

    # Hardcoded passwords
    (r"""(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{4,})['\"]""", "Hardcoded Password", Severity.HIGH),

    # Database connection strings
    (r"(?:mongodb|postgres|postgresql|mysql|redis|amqp|mssql)://[^\s'\"]+", "Database Connection String", Severity.CRITICAL),

    # Private keys
    (r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)\s+PRIVATE\s+KEY-----", "Private Key", Severity.CRITICAL),

    # Twilio
    (r"SK[0-9a-fA-F]{32}", "Twilio API Key", Severity.HIGH),

    # SendGrid
    (r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "SendGrid API Key", Severity.CRITICAL),

    # Mailgun
    (r"key-[0-9a-zA-Z]{32}", "Mailgun API Key", Severity.HIGH),

    # Heroku
    (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
     None, None),  # skip UUIDs, too noisy

    # NPM token
    (r"npm_[A-Za-z0-9]{36}", "NPM Access Token", Severity.CRITICAL),

    # Square
    (r"sq0[a-z]{3}-[0-9A-Za-z_-]{22,}", "Square Access Token", Severity.HIGH),

    # Shopify
    (r"shpat_[a-fA-F0-9]{32}", "Shopify Admin API Token", Severity.CRITICAL),
    (r"shpss_[a-fA-F0-9]{32}", "Shopify Shared Secret", Severity.CRITICAL),
]

# Filter out entries with None label (skipped / too noisy)
ACTIVE_SECRET_PATTERNS = [(p, l, s) for p, l, s in SECRET_PATTERNS if l is not None]


def _get_line_number(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def _snippet(content: str, pos: int, length: int = 120) -> str:
    start = max(0, pos - 20)
    end = min(len(content), pos + length)
    snip = content[start:end].replace("\n", "\\n").strip()
    if len(snip) > 150:
        snip = snip[:150] + "..."
    return snip


def detect_secrets(script: ScriptInfo) -> List[Finding]:
    """Scan JS content for hardcoded secrets and credentials."""
    findings: List[Finding] = []
    content = script.content
    if not content:
        return findings

    for pattern, label, severity in ACTIVE_SECRET_PATTERNS:
        try:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                line = _get_line_number(content, m.start())
                matched = m.group()
                # Truncate the displayed secret for safety
                if len(matched) > 20:
                    display = matched[:10] + "..." + matched[-6:]
                else:
                    display = matched

                findings.append(Finding(
                    file_url=script.display_name,
                    line_number=line,
                    category=Category.SECRET_EXPOSURE,
                    snippet=_snippet(content, m.start()),
                    explanation=f"{label} detected: {display}",
                    confidence=Confidence.HIGH,
                    severity=severity,
                    detector="secrets",
                ))
        except re.error:
            continue

    return findings


# ---------------------------------------------------------------------------
# Internal infrastructure leakage
# ---------------------------------------------------------------------------

INFRA_PATTERNS = [
    # Private IPs
    (r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "Private IP (10.x.x.x)", Severity.MEDIUM),
    (r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b", "Private IP (172.16-31.x.x)", Severity.MEDIUM),
    (r"\b192\.168\.\d{1,3}\.\d{1,3}\b", "Private IP (192.168.x.x)", Severity.MEDIUM),

    # Internal hostnames
    (r"https?://[a-zA-Z0-9._-]+\.(?:internal|local|corp|intra|private|lan)\b[^\s'\"]*",
     "Internal hostname", Severity.HIGH),

    # S3 buckets
    (r"[a-zA-Z0-9._-]+\.s3\.amazonaws\.com", "S3 Bucket URL", Severity.MEDIUM),
    (r"s3://[a-zA-Z0-9._-]+", "S3 Bucket URI", Severity.MEDIUM),
    (r"arn:aws:s3:::[a-zA-Z0-9._-]+", "S3 Bucket ARN", Severity.MEDIUM),

    # Staging/dev URLs
    (r"https?://(?:staging|dev|test|qa|uat|preprod|sandbox|debug|internal)[.-][a-zA-Z0-9._-]+\.[a-zA-Z]{2,}",
     "Staging/Dev URL", Severity.MEDIUM),

    # Developer emails
    (r"\b[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9-]+\.)*(?:internal|corp|local|dev)\.[a-zA-Z]{2,}\b",
     "Internal Email Address", Severity.LOW),

    # CI/CD metadata
    (r"(?:jenkins|gitlab-ci|circleci|travis-ci|github-actions|buildkite|drone|teamcity)[^\s'\"]{0,80}",
     "CI/CD Reference", Severity.LOW),

    # Cloud metadata endpoints
    (r"169\.254\.169\.254", "Cloud Metadata Endpoint (IMDS)", Severity.HIGH),
    (r"metadata\.google\.internal", "GCP Metadata Endpoint", Severity.HIGH),
]


def detect_internal_infra(script: ScriptInfo) -> List[Finding]:
    """Detect internal infrastructure leakage in JS content."""
    findings: List[Finding] = []
    content = script.content
    if not content:
        return findings

    for pattern, label, severity in INFRA_PATTERNS:
        for m in re.finditer(pattern, content, re.IGNORECASE):
            line = _get_line_number(content, m.start())
            findings.append(Finding(
                file_url=script.display_name,
                line_number=line,
                category=Category.INTERNAL_INFRA,
                snippet=_snippet(content, m.start()),
                explanation=f"{label} found: {m.group()[:80]}",
                confidence=Confidence.MEDIUM,
                severity=severity,
                detector="internal_infra",
            ))

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_secret_detectors(scripts: List[ScriptInfo],
                         skip_secrets=False, skip_infra=False) -> List[Finding]:
    """Run all secret/infra detectors."""
    findings: List[Finding] = []
    for script in scripts:
        if not skip_secrets:
            findings.extend(detect_secrets(script))
        if not skip_infra:
            findings.extend(detect_internal_infra(script))
    return findings
