"""Shared data models for JS Strike findings."""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
import json


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other):
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other):
        return self == other or self < other


class Confidence(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Category(Enum):
    DOM_XSS = "DOM-based XSS"
    POSTMESSAGE = "Insecure postMessage Handler"
    OPEN_REDIRECT = "DOM-based Open Redirect"
    PROTOTYPE_POLLUTION = "Client-side Prototype Pollution"
    STORAGE_SENSITIVE = "Sensitive Data in Browser Storage"
    SECRET_EXPOSURE = "Secret / Credential Exposure"
    INTERNAL_INFRA = "Internal Infrastructure Leakage"
    SOURCE_MAP = "Exposed Source Map"
    ENDPOINT = "Extracted Endpoint"
    ADMIN_ROUTE = "Admin / Internal Route"
    IDOR_CANDIDATE = "IDOR / BAC Candidate"
    CLIENT_VALIDATION = "Client-side-only Validation"
    VULNERABLE_LIBRARY = "Vulnerable Library"
    OUTDATED_LIBRARY = "Outdated / EOL Library"
    LIBRARY_DETECTED = "Library Detected"


@dataclass
class Finding:
    file_url: str
    line_number: int
    category: Category
    snippet: str
    explanation: str
    confidence: Confidence
    severity: Severity
    detector: str = ""

    def to_dict(self) -> dict:
        return {
            "file_url": self.file_url,
            "line_number": self.line_number,
            "category": self.category.value,
            "snippet": self.snippet,
            "explanation": self.explanation,
            "confidence": self.confidence.value,
            "severity": self.severity.value,
            "detector": self.detector,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class ScriptInfo:
    """Represents a discovered JavaScript resource."""
    url: str
    content: str
    is_inline: bool = False
    inline_index: int = 0
    source_map_url: Optional[str] = None
    source_map_content: Optional[str] = None
    source_map_files: list = field(default_factory=list)

    @property
    def display_name(self) -> str:
        if self.is_inline:
            return f"inline-script-{self.inline_index}"
        return self.url
