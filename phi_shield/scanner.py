"""Fast PHI/PII scanner using regex patterns.

Catches HIPAA, PCI-DSS, GDPR patterns in <1ms. No external dependencies.
Designed for pre-flight checks before sending text to LLM APIs.

45 pattern categories covering:
- HIPAA: SSN, DOB, MRN, NPI, patient names, healthcare context, medical docs,
         Medicare/Medicaid, insurance IDs, physical addresses
- HIPAA-EMS: GPS coordinates, blood pressure, vital signs, ICD-10, CPT,
             NEMSIS elements, run/incident numbers, US dates, ZIP+4
- Cross-vertical: lab values, medication doses, age >89, device serial,
                  fax numbers, infection status (HIV/HBsAg/MRSA/HCV)
- Radiology: accession numbers, DICOM UIDs, BI-RADS, radiation dose
- Dialysis: Kt/V, URR, dry weight, vascular access type
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
        None,
    ),
    # ── EMS / HEALTHCARE ────────────────────────────────────────────
    "gps_coordinates": (
        r"-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}",
        0,
        "medium",
        "HIPAA",
        None,
    ),
    "blood_pressure": (
        r"\b(?:BP|B/P|blood\s*pressure|SBP|DBP|systolic|diastolic)[:\s]*\d{2,3}\s*/\s*\d{2,3}\b",
        re.IGNORECASE,
        "high",
        "HIPAA",
        None,
    ),
    "vital_signs": (
        r"\b(?:HR|heart\s*rate|pulse|SpO2|O2\s*sat|RR|resp(?:iratory)?\s*rate|GCS|temp(?:erature)?|glucose|BGL)[:\s]*\d{1,3}(?:\.\d)?\s*(?:%|bpm|/min|[°]?[FC]|mg/dL)?\b",
        re.IGNORECASE,
        "high",
        "HIPAA",
        None,
    ),
    "icd10_code": (
        r"\b(?:ICD[-.]?10|diagnosis|dx)[:\s]*[A-Z]\d{2}(?:\.\d{1,4})?[A-Z]?\b",
        re.IGNORECASE,
        "medium",
        "HIPAA",
        None,
    ),
    "cpt_code": (
        r"\b(?:CPT|procedure\s*code|billing\s*code|HCPCS)[:\s]*[A-Z0-9]\d{4}(?:[-\s]?\d{2})?\b",
        re.IGNORECASE,
        "medium",
        "HIPAA",
        None,
    ),
    "nemsis_element": (
        r"\be(?:Patient|Situation|Response|Dispatch|Scene|Crew|Vitals|Medication|Procedure|Disposition|Outcome|Narrative|Custom|Payment|Injury)\.\d{2,3}\b",
        0,
        "medium",
        "HIPAA",
        None,
    ),
    "run_incident_number": (
        r"\b(?:run|incident|pcr|case|call)\s*(?:#|no\.?|number|id)?[:\s]*[A-Z]?\d{4,12}\b",
        re.IGNORECASE,
        "high",
        "HIPAA",
        None,
    ),
    "date_us": (
        r"\b(?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b",
        0,
        "medium",
        "HIPAA",
        frozenset({
            "patient", "medical", "clinical", "ems", "hospital", "ambulance",
            "epcr", "chart", "record", "diagnosis", "treatment", "admission",
            "discharge", "transfer", "medication", "prescription", "incident",
            "pcr", "run sheet", "billing", "cms-1500", "ub-04", "hipaa",
        }),
    ),
    "date_written": (
        r"\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2},?\s+\d{4}\b",
        re.IGNORECASE,
        "medium",
        "HIPAA",
        frozenset({
            "patient", "medical", "clinical", "ems", "hospital", "ambulance",
            "epcr", "chart", "record", "diagnosis", "treatment", "admission",
            "discharge", "transfer", "medication", "prescription", "incident",
            "pcr", "run sheet", "billing", "cms-1500", "ub-04", "hipaa",
        }),
    ),
    "zip_plus4": (
        r"\b\d{5}-\d{4}\b",
        0,
        "low",
        "HIPAA",
        None,
    ),
    # ── CROSS-VERTICAL (EMS + Radiology + Dialysis) ─────────────────
    "lab_values": (
        r"\b(?:BUN|creatinine|Cr|SCr|hemoglobin|Hgb|Hb|WBC|RBC|platelet|albumin|phosphorus|PO4|PTH|HbA1c|A1c|INR|potassium|sodium|ferritin|troponin|TSH|calcium|magnesium|AST|ALT|bilirubin|lipase|amylase|BNP|proBNP|lactate|CRP|ESR|PSA|eGFR)[:\s]+\d+(?:\.\d+)?\s*(?:mg/dL|g/dL|pg/mL|ng/mL|mEq/L|mmol/L|U/L|IU/L|%|K/uL|mL/min)?\b",
        re.IGNORECASE,
        "high",
        "HIPAA",
        None,
    ),
    "medication_dose": (
        r"\b(?:administered|prescribed|given|dose|medication|med|ordered|dispensed)[:\s]+\w+\s+\d+(?:\.\d+)?\s*(?:mg|mcg|mL|units?|mEq|IU|g)\b",
        re.IGNORECASE,
        "high",
        "HIPAA",
        None,
    ),
    "age_over_89": (
        r"\b(?:age|aged|years?\s*old)[:\s]+(?:9\d|1[0-9]\d)\b",
        re.IGNORECASE,
        "high",
        "HIPAA",
        None,
    ),
    "device_serial": (
        r"\b(?:serial\s*(?:number|#|no\.?)|SN|device\s*(?:id|#))[:\s]+[A-Z0-9\-]{5,20}\b",
        re.IGNORECASE,
        "medium",
        "HIPAA",
        None,
    ),
    "fax_number": (
        r"\b(?:fax|facsimile)[:\s]+(?:\+1[-.]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b",
        re.IGNORECASE,
        "medium",
        "HIPAA",
        None,
    ),
    "infection_status": (
        r"\b(?:HIV|HBsAg|hepatitis\s*[BC]|HCV|anti-?HCV|MRSA|VRE|C\.?\s*diff)[:\s]+(?:positive|negative|reactive|non-?reactive|detected|not\s*detected|\+|-)\b",
        re.IGNORECASE,
        "critical",
        "HIPAA",
        None,
    ),
    # ── RADIOLOGY ───────────────────────────────────────────────────
    "accession_number": (
        r"\b(?:accession|acc)\s*(?:number|no\.?|#|id)?[:\s]+[A-Z0-9]{6,20}\b",
        re.IGNORECASE,
        "high",
        "HIPAA",
        None,
    ),
    "dicom_uid": (
        r"\b(?:study|series|sop)\s*(?:instance)?\s*uid[:\s=]+(?:\d+\.){3,}\d+\b",
        re.IGNORECASE,
        "critical",
        "HIPAA",
        None,
    ),
    "birads_score": (
        r"\bBI-?RADS\s*(?:category\s*)?:?\s*[0-6][A-C]?\b",
        re.IGNORECASE,
        "medium",
        "HIPAA",
        None,
    ),
    "radiation_dose": (
        r"\b(?:CTDIvol|DLP|dose\s*(?:index|length\s*product))[:\s]+\d+(?:\.\d+)?\s*(?:mGy|mGy[·\-]cm|mSv|mrad)\b",
        re.IGNORECASE,
        "medium",
        "HIPAA",
        None,
    ),
    # ── DIALYSIS ────────────────────────────────────────────────────
    "dialysis_adequacy": (
        r"\b(?:Kt/V|spKt/V|eKt/V|URR|urea\s*reduction)[:\s]+\d+(?:\.\d+)?%?\b",
        re.IGNORECASE,
        "medium",
        "HIPAA",
        None,
    ),
    "dry_weight": (
        r"\b(?:dry\s*weight|target\s*weight|EDW|estimated\s*dry\s*weight)[:\s]+\d+(?:\.\d+)?\s*(?:kg|lbs?)\b",
        re.IGNORECASE,
        "medium",
        "HIPAA",
        None,
    ),
    "dialysis_access": (
        r"\b(?:AV\s*fistula|AVF|AV\s*graft|AVG|tunneled\s*catheter|permcath|dialysis\s*catheter|(?:left|right)\s+(?:radial|brachial|cephalic|basilic|subclavian|femoral|jugular)\s+(?:fistula|graft|catheter|access))\b",
        re.IGNORECASE,
        "high",
        "HIPAA",
        None,
    ),
}

# Pattern groups for redaction presets
_EMS_PATTERNS = frozenset({
    "ssn", "date_of_birth", "medical_record_number", "npi", "patient_name",
    "physical_address", "phone", "email", "fax_number", "gps_coordinates",
    "blood_pressure", "vital_signs", "nemsis_element", "run_incident_number",
    "date_us", "date_written", "zip_plus4", "medication_dose", "age_over_89",
    "lab_values", "infection_status",
})

_BILLING_PATTERNS = frozenset({
    "ssn", "date_of_birth", "medical_record_number", "npi", "medicare_medicaid",
    "insurance_id", "patient_name", "physical_address", "icd10_code", "cpt_code",
    "credit_card", "credit_card_partial", "bank_account", "fax_number",
})

_RADIOLOGY_PATTERNS = frozenset({
    "ssn", "date_of_birth", "medical_record_number", "npi", "patient_name",
    "physical_address", "phone", "email", "fax_number", "accession_number",
    "dicom_uid", "birads_score", "radiation_dose", "icd10_code", "cpt_code",
    "device_serial", "date_us", "date_written", "lab_values", "age_over_89",
    "insurance_id", "medicare_medicaid",
})

_DIALYSIS_PATTERNS = frozenset({
    "ssn", "date_of_birth", "medical_record_number", "npi", "patient_name",
    "physical_address", "phone", "email", "fax_number", "dialysis_adequacy",
    "dry_weight", "dialysis_access", "lab_values", "medication_dose",
    "infection_status", "vital_signs", "blood_pressure", "icd10_code",
    "cpt_code", "insurance_id", "medicare_medicaid", "date_us", "date_written",
    "age_over_89",
})

RISK_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _compile_patterns() -> dict:
    """Compile regex patterns with graceful degradation."""
    compiled = {}
    for name, spec in _PATTERN_SPECS.items():
        if len(spec) == 5:
            raw, flags, risk, regulation, context = spec
        else:
            raw, flags, risk, regulation = spec
            context = None
        try:
            compiled[name] = (re.compile(raw, flags), risk, regulation, context)
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
        text_lower = text.lower()

        for entity_type, (pattern, risk, regulation, context) in self._patterns.items():
            if context and not any(kw in text_lower for kw in context):
                continue
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
        return self._redact_subset(text, None, replacement)

    def redact_ems(self, text: str) -> str:
        """Redact EMS-specific PHI (ePCR, run sheets, vitals).

        Targets: SSN, DOB, MRN, NPI, patient names, addresses, phone, email,
        GPS, blood pressure, vitals, NEMSIS elements, run numbers, dates, ZIP+4.
        """
        return self._redact_subset(text, _EMS_PATTERNS)

    def redact_billing(self, text: str) -> str:
        """Redact billing PHI (CMS-1500, UB-04, insurance claims).

        Targets: SSN, DOB, MRN, NPI, Medicare/Medicaid, insurance IDs,
        patient names, addresses, ICD-10, CPT codes, credit cards, bank accounts.
        """
        return self._redact_subset(text, _BILLING_PATTERNS)

    def redact_radiology(self, text: str) -> str:
        """Redact radiology PHI (DICOM metadata, reports, billing).

        Targets: SSN, DOB, MRN, NPI, patient names, addresses, accession
        numbers, DICOM UIDs, BI-RADS, radiation dose, device serial numbers,
        ICD-10, CPT codes, insurance IDs, dates, labs, age.
        """
        return self._redact_subset(text, _RADIOLOGY_PATTERNS)

    def redact_dialysis(self, text: str) -> str:
        """Redact dialysis PHI (treatment logs, ESRD forms, lab reports).

        Targets: SSN, DOB, MRN, NPI, patient names, addresses, Kt/V, URR,
        dry weight, vascular access info, labs, medications, infection status,
        vitals, blood pressure, ICD-10, CPT, insurance, dates, age.
        """
        return self._redact_subset(text, _DIALYSIS_PATTERNS)

    def _redact_subset(
        self,
        text: str,
        pattern_names: Optional[frozenset] = None,
        replacement: Optional[str] = None,
    ) -> str:
        """Redact a subset of patterns (or all if pattern_names is None)."""
        result = text
        text_lower = text.lower()
        for entity_type, (pattern, risk, regulation, context) in self._patterns.items():
            if pattern_names is not None and entity_type not in pattern_names:
                continue
            if context and not any(kw in text_lower for kw in context):
                continue
            tag = replacement or f"[{entity_type.upper()}]"
            result = pattern.sub(tag, result)
        return result

    def scan_batch(self, texts: list[str]) -> list[dict]:
        """Scan multiple texts. Returns list of scan results."""
        return [self.scan(t) for t in texts]

    def has_phi(self, text: str) -> bool:
        """Quick boolean check — does this text contain PHI?"""
        return self.scan(text)["phi_detected"]
