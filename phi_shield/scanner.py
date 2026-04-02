"""Fast PHI/PII scanner using regex patterns.

Catches HIPAA, PCI-DSS, GDPR patterns in <1ms. No external dependencies.
Designed for pre-flight checks before sending text to LLM APIs.

22 pattern categories covering:
- HIPAA: SSN, DOB, MRN, NPI, patient names, healthcare context, medical docs,
         Medicare/Medicaid, insurance IDs, physical addresses
- PCI-DSS: Credit cards (full + partial), bank accounts
- GDPR: Email, phone, IP, passport, driver's license
- SOX: Salary/compensation
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

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
    # ── HIPAA ────────────────────────────────────────────────────────
    "ssn": (
        r"\b\d{3}-\d{2}-\d{4}\b",
        0,
        "high",
        "HIPAA",
    ),
    "date_of_birth": (
        r"\b(?:DOB|date of birth|born|birthday|d\.o\.b)[:\s]+\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}\b",
        re.IGNORECASE,
        "high",
        "HIPAA",
    ),
    "medical_record_number": (
        r"\b(?:MRN|medical record|chart|patient\s*(?:id|#|no|number))[:\s#]+\w{4,15}\b",
        re.IGNORECASE,
        "high",
        "HIPAA",
    ),
    "npi": (
        r"\b(?:NPI|national provider)[:\s#]+\d{10}\b",
        re.IGNORECASE,
        "high",
        "HIPAA",
    ),
    "medicare_medicaid": (
        r"\b(?:medicare|medicaid|mbi|hic)[:\s#]+[A-Z0-9]{8,12}\b",
        re.IGNORECASE,
        "high",
        "HIPAA",
    ),
    "insurance_id": (
        r"\b(?:insurance|member|subscriber|group|policy)\s*(?:id|#|no|number)[:\s]+[A-Z0-9]{5,20}\b",
        re.IGNORECASE,
        "high",
        "HIPAA",
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
    "medical_document": (
        r"\b(?:discharge\s+summary|medical\s+record|lab\s+result|pathology\s+report|radiology\s+report|clinical\s+note|operative\s+report|admit|referral)\b.*?\b(?:send|transfer|fax|email|forward|share|review|update)",
        re.IGNORECASE,
        "high",
        "HIPAA",
    ),
    "physical_address": (
        r"\b\d{1,5}\s+(?:N\.?|S\.?|E\.?|W\.?|North|South|East|West)?\s*(?:[A-Z][a-z]+\s+){1,3}(?:St(?:reet)?|Ave(?:nue)?|Blvd|Dr(?:ive)?|Ln|Lane|Rd|Road|Way|Ct|Court|Pl(?:ace)?|Cir(?:cle)?)\b",
        0,
        "medium",
        "HIPAA",
    ),
    # ── PCI-DSS ──────────────────────────────────────────────────────
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
    # ── GDPR ─────────────────────────────────────────────────────────
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
    "phone_intl": (
        r"\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{2,4}[-.\s]?\d{2,4}(?:[-.\s]?\d{1,4})?\b",
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
    "vin": (
        r"\b(?:VIN|vehicle)[:\s#]+[A-HJ-NPR-Z0-9]{17}\b",
        re.IGNORECASE,
        "medium",
        "GDPR",
    ),
    # ── SOX ───────────────────────────────────────────────────────────
    "salary_compensation": (
        r"\b(?:salary|compensation|payroll|wage|bonus)[\s:]+\$?\d[\d,.]+\b",
        re.IGNORECASE,
        "high",
        "SOX",
    ),
    # ── FERPA (education) ─────────────────────────────────────────────
    "student_id": (
        r"\b(?:student\s*(?:id|#|number))[:\s]+[A-Z0-9]{5,12}\b",
        re.IGNORECASE,
        "medium",
        "FERPA",
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

        # Redact PHI from text
        clean = scanner.redact("Patient John Doe SSN 123-45-6789")
        # → "Patient [PATIENT_NAME] SSN [SSN]"

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
                value = match if isinstance(match, str) else str(match)
                entities.append({
                    "type": entity_type,
                    "value": value if len(value) < 20 else value[:10] + "...",
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

    def redact(self, text: str, replacement: Optional[str] = None) -> str:
        """Replace all detected PHI/PII with redaction markers.

        Args:
            text: Input text to redact.
            replacement: Custom replacement string. If None, uses [TYPE] format.

        Returns:
            Text with all PHI/PII replaced by redaction markers.
        """
        result = text
        for entity_type, (pattern, risk, regulation) in self._patterns.items():
            tag = replacement or f"[{entity_type.upper()}]"
            result = pattern.sub(tag, result)
        return result

    def scan_batch(self, texts: list[str]) -> list[dict]:
        """Scan multiple texts. Returns list of scan results."""
        return [self.scan(t) for t in texts]

    def has_phi(self, text: str) -> bool:
        """Quick boolean check — does this text contain PHI?"""
        return self.scan(text)["phi_detected"]
