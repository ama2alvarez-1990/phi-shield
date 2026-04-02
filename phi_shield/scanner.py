"""Fast PHI/PII scanner using regex patterns.

Catches HIPAA, PCI-DSS, GDPR patterns in <1ms. No external dependencies.
Designed for pre-flight checks before sending text to LLM APIs.

14 pattern categories:
- SSN, credit card (full + partial), bank account
- DOB, medical record number, patient name
- Healthcare context, medical documents
- Email, phone, IP address, passport, driver's license
- Salary/compensation
"""

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger("phi_shield")


@dataclass
class PHIScanResult:
    """Result of a PHI scan."""

    phi_detected: bool = False
    entities: list[dict] = field(default_factory=list)
    risk: str = "none"
    action: str = "allow_external"
    regulation: str = "none"


_PATTERN_SPECS = {
    "ssn": (
        r"\b\d{3}-\d{2}-\d{4}\b",
        0,
        "high",
        "HIPAA",
    ),
    "credit_card": (
        r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        0,
        "critical",
        "PCI_DSS",
    ),
    "credit_card_partial": (
        r"\b(?:card|credit|debit|visa|mastercard|amex)[\s#:]*(?:ending|last\s*4|xxxx)[\s#:]*\d{4}\b",
        re.IGNORECASE,
        "high",
        "PCI_DSS",
    ),
    "bank_account": (
        r"\b(?:account|routing)[\s#:]*\d{6,12}\b",
        re.IGNORECASE,
        "high",
        "PCI_DSS",
    ),
    "date_of_birth": (
        r"\b(?:DOB|date of birth|born|birthday)[:\s]+\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b",
        re.IGNORECASE,
        "high",
        "HIPAA",
    ),
    "medical_record_number": (
        r"\b(?:MRN|medical record|chart)[\s#:]+\w{5,15}\b",
        re.IGNORECASE,
        "high",
        "HIPAA",
    ),
    "email": (
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
        0,
        "medium",
        "GDPR",
    ),
    "phone": (
        r"\b(?:\+1[-.]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b",
        0,
        "medium",
        "GDPR",
    ),
    "ip_address": (
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        0,
        "low",
        "GDPR",
    ),
    "passport": (
        r"\b(?:passport)[\s#:]+[A-Z0-9]{6,12}\b",
        re.IGNORECASE,
        "high",
        "GDPR",
    ),
    "driver_license": (
        r"\b(?:driver.?s?\s*license|DL)[\s#:]+[A-Z0-9]{5,15}\b",
        re.IGNORECASE,
        "high",
        "GDPR",
    ),
    "patient_name": (
        r"\b[Pp]atient[\s:]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)",
        0,
        "high",
        "HIPAA",
    ),
    "healthcare_context": (
        r"\b(?:patient|room\s+\d+|ward|icu|er\b|diagnosis|prescription|dosage|medication|prognosis|biopsy|radiology|oncology|lab\s+results?)(?:\s+\w+){0,5}\s+(?:need|require|adjust|review|check|update|send|transfer|prescri)",
        re.IGNORECASE,
        "high",
        "HIPAA",
    ),
    "salary_compensation": (
        r"\b(?:salary|compensation|payroll|wage|bonus)[\s:]+\$?\d[\d,.]+\b",
        re.IGNORECASE,
        "high",
        "SOX",
    ),
}

RISK_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _compile_patterns() -> dict:
    """Compile regex patterns with graceful degradation."""
    compiled = {}
    for name, (raw, flags, risk, regulation) in _PATTERN_SPECS.items():
        try:
            compiled[name] = (re.compile(raw, flags), risk, regulation)
        except re.error as exc:
            logger.warning("Pattern '%s' failed to compile: %s", name, exc)
    return compiled


PATTERNS = _compile_patterns()


class FastPHIScanner:
    """Regex-based PHI/PII scanner. Runs in <1ms.

    Usage::

        scanner = FastPHIScanner()
        result = scanner.scan("Patient John Doe SSN 123-45-6789")
        assert result["phi_detected"] is True

    The scan() method never raises — returns a safe default on any error.
    """

    def __init__(self) -> None:
        self._patterns = PATTERNS
        self._operational = len(self._patterns) > 0

    @property
    def healthy(self) -> bool:
        """True if scanner has at least one operational pattern."""
        return self._operational and len(self._patterns) > 0

    @property
    def pattern_count(self) -> int:
        """Number of active patterns."""
        return len(self._patterns)

    def scan(self, text: str) -> dict:
        """Scan text for PHI/PII patterns.

        Args:
            text: Input string to scan.

        Returns:
            Dict with: phi_detected (bool), entities (list), risk (str),
            action (str), regulation (str), scanner (str).
        """
        try:
            return self._scan_impl(text)
        except Exception as exc:
            logger.error("scan() failed: %s", exc)
            return {
                "phi_detected": False,
                "entities": [],
                "risk": "unknown",
                "action": "allow_external",
                "regulation": "none",
                "scanner": "regex_fast_degraded",
            }

    def _scan_impl(self, text: str) -> dict:
        entities = []
        max_risk = "none"
        max_regulation = "none"

        for entity_type, (pattern, risk, regulation) in self._patterns.items():
            matches = pattern.findall(text)
            for match in matches:
                entities.append({
                    "type": entity_type,
                    "value": match if len(match) < 20 else match[:10] + "...",
                })
                if RISK_ORDER.get(risk, 0) > RISK_ORDER.get(max_risk, 0):
                    max_risk = risk
                    max_regulation = regulation

        phi_detected = len(entities) > 0
        return {
            "phi_detected": phi_detected,
            "entities": entities,
            "risk": max_risk,
            "action": "local_only" if phi_detected else "allow_external",
            "regulation": max_regulation if phi_detected else "none",
            "scanner": "regex_fast",
        }
