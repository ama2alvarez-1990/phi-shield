"""Tests for phi-shield scanner."""

from phi_shield import scan
from phi_shield.scanner import FastPHIScanner


# ── HIPAA ────────────────────────────────────────────────────────

def test_detects_ssn():
    result = scan("Patient SSN 123-45-6789")
    assert result["phi_detected"] is True
    assert any(e["type"] == "ssn" for e in result["entities"])
    assert result["risk"] == "high"


def test_detects_dob():
    result = scan("DOB 04/08/1990 confirmed")
    assert result["phi_detected"] is True
    assert any(e["type"] == "date_of_birth" for e in result["entities"])


def test_detects_dob_dot_format():
    result = scan("d.o.b 12.25.1985 on file")
    assert result["phi_detected"] is True


def test_detects_mrn():
    result = scan("MRN MR-12345 chart review")
    assert result["phi_detected"] is True
    assert any(e["type"] == "medical_record_number" for e in result["entities"])


def test_detects_patient_id():
    result = scan("Patient ID: A12345678")
    assert result["phi_detected"] is True


def test_detects_npi():
    result = scan("NPI: 1234567890 for Dr. Smith")
    assert result["phi_detected"] is True
    assert any(e["type"] == "npi" for e in result["entities"])


def test_detects_medicare():
    result = scan("Medicare MBI: 1EG4TE5MK73")
    assert result["phi_detected"] is True
    assert any(e["type"] == "medicare_medicaid" for e in result["entities"])


def test_detects_insurance_id():
    result = scan("Insurance Member ID: XYZ123456789")
    assert result["phi_detected"] is True
    assert any(e["type"] == "insurance_id" for e in result["entities"])


def test_detects_patient_name():
    result = scan("Patient John Doe admitted today")
    assert result["phi_detected"] is True
    assert any(e["type"] == "patient_name" for e in result["entities"])


def test_detects_address():
    result = scan("Lives at 123 Main Street")
    assert result["phi_detected"] is True
    assert any(e["type"] == "physical_address" for e in result["entities"])


# ── PCI-DSS ──────────────────────────────────────────────────────

def test_detects_credit_card():
    result = scan("Card 4111 1111 1111 1111 charged")
    assert result["phi_detected"] is True
    assert any(e["type"] == "credit_card" for e in result["entities"])
    assert result["risk"] == "critical"


def test_detects_credit_card_partial():
    result = scan("Visa ending 4242")
    assert result["phi_detected"] is True


# ── GDPR ─────────────────────────────────────────────────────────

def test_detects_email():
    result = scan("Contact user@example.com for details")
    assert result["phi_detected"] is True
    assert any(e["type"] == "email" for e in result["entities"])


def test_detects_phone():
    result = scan("Call 555-123-4567 now")
    assert result["phi_detected"] is True
    assert any(e["type"] == "phone" for e in result["entities"])


def test_detects_intl_phone():
    result = scan("Call +44-20-7946-0958")
    assert result["phi_detected"] is True


def test_detects_ip():
    result = scan("Server at 192.168.1.100")
    assert result["phi_detected"] is True


def test_detects_vin():
    result = scan("VIN: 1HGBH41JXMN109186")
    assert result["phi_detected"] is True
    assert any(e["type"] == "vin" for e in result["entities"])


# ── SOX / FERPA ──────────────────────────────────────────────────

def test_detects_salary():
    result = scan("salary: $150,000 per year")
    assert result["phi_detected"] is True
    assert any(e["type"] == "salary_compensation" for e in result["entities"])


def test_detects_student_id():
    result = scan("Student ID: STU2024001")
    assert result["phi_detected"] is True
    assert any(e["type"] == "student_id" for e in result["entities"])


# ── EMS / HEALTHCARE PATTERNS ───────────────────────────────────

def test_detects_gps_coordinates():
    result = scan("Scene location 40.7128, -74.0060")
    assert result["phi_detected"] is True
    assert any(e["type"] == "gps_coordinates" for e in result["entities"])


def test_detects_gps_negative():
    result = scan("GPS: -33.8688, 151.2093")
    assert result["phi_detected"] is True
    assert any(e["type"] == "gps_coordinates" for e in result["entities"])


def test_detects_blood_pressure():
    result = scan("BP: 120/80 mmHg taken at scene")
    assert result["phi_detected"] is True
    assert any(e["type"] == "blood_pressure" for e in result["entities"])


def test_detects_blood_pressure_sbp():
    result = scan("SBP 140/90 elevated")
    assert result["phi_detected"] is True
    assert any(e["type"] == "blood_pressure" for e in result["entities"])


def test_detects_vital_signs_hr():
    result = scan("HR: 88 bpm regular")
    assert result["phi_detected"] is True
    assert any(e["type"] == "vital_signs" for e in result["entities"])


def test_detects_vital_signs_spo2():
    result = scan("SpO2 97% on room air")
    assert result["phi_detected"] is True
    assert any(e["type"] == "vital_signs" for e in result["entities"])


def test_detects_vital_signs_gcs():
    result = scan("GCS: 15 alert and oriented")
    assert result["phi_detected"] is True
    assert any(e["type"] == "vital_signs" for e in result["entities"])


def test_detects_vital_signs_glucose():
    result = scan("glucose: 120 mg/dL")
    assert result["phi_detected"] is True
    assert any(e["type"] == "vital_signs" for e in result["entities"])


def test_detects_vital_signs_temp():
    result = scan("temp 98.6 F oral")
    assert result["phi_detected"] is True
    assert any(e["type"] == "vital_signs" for e in result["entities"])


def test_detects_icd10():
    result = scan("Dx: S72.001A right femur fracture")
    assert result["phi_detected"] is True
    assert any(e["type"] == "icd10_code" for e in result["entities"])


def test_detects_icd10_with_prefix():
    result = scan("ICD-10: J18.9 pneumonia unspecified")
    assert result["phi_detected"] is True
    assert any(e["type"] == "icd10_code" for e in result["entities"])


def test_detects_cpt_code():
    result = scan("CPT: 99285 level 5 ED visit")
    assert result["phi_detected"] is True
    assert any(e["type"] == "cpt_code" for e in result["entities"])


def test_detects_hcpcs():
    result = scan("HCPCS: A0427 ALS emergency")
    assert result["phi_detected"] is True
    assert any(e["type"] == "cpt_code" for e in result["entities"])


def test_detects_nemsis_element():
    result = scan("ePatient.02 first name field required")
    assert result["phi_detected"] is True
    assert any(e["type"] == "nemsis_element" for e in result["entities"])


def test_detects_nemsis_vitals():
    result = scan("eVitals.06 systolic blood pressure documented")
    assert result["phi_detected"] is True
    assert any(e["type"] == "nemsis_element" for e in result["entities"])


def test_detects_run_number():
    result = scan("Run #2024001234 completed")
    assert result["phi_detected"] is True
    assert any(e["type"] == "run_incident_number" for e in result["entities"])


def test_detects_incident_number():
    result = scan("Incident: 20240415001")
    assert result["phi_detected"] is True
    assert any(e["type"] == "run_incident_number" for e in result["entities"])


def test_detects_pcr_number():
    result = scan("PCR number: 12345678")
    assert result["phi_detected"] is True
    assert any(e["type"] == "run_incident_number" for e in result["entities"])


def test_detects_zip_plus4():
    result = scan("Mailing address ZIP 33186-2204")
    assert result["phi_detected"] is True
    assert any(e["type"] == "zip_plus4" for e in result["entities"])


# ── CONTEXTUAL DATE PATTERNS ────────────────────────────────────

def test_date_us_with_medical_context():
    result = scan("Patient admitted on 04/08/2024 to hospital ICU")
    assert result["phi_detected"] is True
    assert any(e["type"] == "date_us" for e in result["entities"])


def test_date_us_without_medical_context():
    """US dates should NOT trigger without healthcare keywords."""
    result = scan("Meeting scheduled 04/08/2024 in conference room")
    # Should not have date_us entity (no healthcare context)
    date_entities = [e for e in result["entities"] if e["type"] == "date_us"]
    assert len(date_entities) == 0


def test_date_written_with_medical_context():
    result = scan("Patient discharge January 15, 2024 from hospital")
    assert result["phi_detected"] is True
    assert any(e["type"] == "date_written" for e in result["entities"])


def test_date_written_without_medical_context():
    """Written dates should NOT trigger without healthcare keywords."""
    result = scan("Project deadline is January 15, 2024")
    date_entities = [e for e in result["entities"] if e["type"] == "date_written"]
    assert len(date_entities) == 0


def test_date_us_epcr_context():
    result = scan("ePCR created 03/15/2024 for transport")
    assert any(e["type"] == "date_us" for e in result["entities"])


def test_date_us_billing_context():
    result = scan("CMS-1500 filed 06/01/2024")
    assert any(e["type"] == "date_us" for e in result["entities"])


# ── Safe text ────────────────────────────────────────────────────

def test_safe_text_no_phi():
    result = scan("The weather is sunny today")
    assert result["phi_detected"] is False
    assert result["risk"] == "none"
    assert result["action"] == "allow_external"


def test_empty_string():
    result = scan("")
    assert result["phi_detected"] is False


def test_none_input_doesnt_crash():
    scanner = FastPHIScanner()
    result = scanner.scan(None)
    assert "phi_detected" in result


# ── Multiple entities ────────────────────────────────────────────

def test_multiple_entities():
    result = scan("Patient John Smith DOB 04/08/1990 SSN 123-45-6789 MRN: MR12345")
    assert result["phi_detected"] is True
    assert len(result["entities"]) >= 3


# ── Redaction ────────────────────────────────────────────────────

def test_redact_ssn():
    scanner = FastPHIScanner()
    text = "SSN is 123-45-6789"
    clean = scanner.redact(text)
    assert "123-45-6789" not in clean
    assert "[SSN]" in clean


def test_redact_email():
    scanner = FastPHIScanner()
    clean = scanner.redact("Email: user@example.com")
    assert "user@example.com" not in clean
    assert "[EMAIL]" in clean


def test_redact_multiple():
    scanner = FastPHIScanner()
    text = "Patient John Smith SSN 123-45-6789 email user@test.com"
    clean = scanner.redact(text)
    assert "123-45-6789" not in clean
    assert "user@test.com" not in clean


def test_redact_custom_replacement():
    scanner = FastPHIScanner()
    clean = scanner.redact("SSN 123-45-6789", replacement="***")
    assert clean == "SSN ***"


# ── Redaction presets ────────────────────────────────────────────

def test_redact_ems_vitals():
    scanner = FastPHIScanner()
    text = "Patient John Doe BP: 120/80 HR: 88 bpm SpO2 97% GPS 40.7128, -74.0060"
    clean = scanner.redact_ems(text)
    assert "120/80" not in clean
    assert "88" not in clean
    assert "40.7128" not in clean
    assert "[BLOOD_PRESSURE]" in clean
    assert "[GPS_COORDINATES]" in clean


def test_redact_ems_run_number():
    scanner = FastPHIScanner()
    text = "Run #2024001234 Patient John Smith SSN 123-45-6789"
    clean = scanner.redact_ems(text)
    assert "2024001234" not in clean
    assert "123-45-6789" not in clean


def test_redact_ems_ignores_billing():
    scanner = FastPHIScanner()
    text = "CPT: 99285 ICD-10: J18.9 credit card 4111 1111 1111 1111"
    clean = scanner.redact_ems(text)
    # EMS preset should NOT redact CPT, ICD-10, or credit cards
    assert "99285" in clean
    assert "J18.9" in clean


def test_redact_billing_codes():
    scanner = FastPHIScanner()
    text = "Dx: S72.001A CPT: 99285 Medicare MBI: 1EG4TE5MK73 SSN 123-45-6789"
    clean = scanner.redact_billing(text)
    assert "S72.001A" not in clean
    assert "99285" not in clean
    assert "1EG4TE5MK73" not in clean
    assert "123-45-6789" not in clean


def test_redact_billing_ignores_vitals():
    scanner = FastPHIScanner()
    text = "BP: 120/80 HR: 88 bpm GPS 40.7128, -74.0060"
    clean = scanner.redact_billing(text)
    # Billing preset should NOT redact vitals or GPS
    assert "120/80" in clean
    assert "40.7128" in clean


# ── Synthetic ePCR ───────────────────────────────────────────────

def test_synthetic_epcr():
    """Full synthetic ePCR document scan."""
    epcr = """
    EMS Patient Care Report
    Run #2024050789
    Incident: 20240507001
    Unit: Medic 42

    Patient: Maria Garcia
    DOB: 03/15/1965
    SSN: 234-56-7890
    MRN: MR-98765
    Medicare MBI: 2FG5TH6NK84
    Insurance Member ID: BCBS12345678

    Scene GPS: 25.7617, -80.1918
    Address: 456 N Ocean Drive

    Vitals:
    BP: 160/95
    HR: 104 bpm
    SpO2 94%
    RR: 22 /min
    GCS: 14
    glucose: 245 mg/dL
    temp 101.2 F

    Assessment: Dx: I10 hypertensive crisis
    ICD-10: E11.65 type 2 diabetes with hyperglycemia

    Procedures: CPT: 99285

    NEMSIS: ePatient.02 eVitals.06 eProcedure.03

    Narrative: Patient found alert, diaphoretic. Administered NTG 0.4mg SL.
    Transport to Memorial Hospital. PCR number: 20240507890
    """
    result = scan(epcr)
    assert result["phi_detected"] is True
    types = {e["type"] for e in result["entities"]}
    # Should detect multiple EMS-specific types
    assert "run_incident_number" in types
    assert "patient_name" in types
    assert "date_of_birth" in types
    assert "ssn" in types
    assert "gps_coordinates" in types
    assert "blood_pressure" in types
    assert "vital_signs" in types
    assert "icd10_code" in types
    assert "cpt_code" in types
    assert "nemsis_element" in types
    assert result["action"] == "local_only"


def test_synthetic_epcr_redact_ems():
    """Redact EMS preset removes all identifiers from ePCR."""
    scanner = FastPHIScanner()
    epcr = "Patient Maria Garcia DOB: 03/15/1965 SSN: 234-56-7890 Run #2024050789 BP: 160/95 HR: 104 bpm GPS 25.7617, -80.1918"
    clean = scanner.redact_ems(epcr)
    assert "Maria Garcia" not in clean
    assert "234-56-7890" not in clean
    assert "2024050789" not in clean
    assert "160/95" not in clean
    assert "25.7617" not in clean


# ── Synthetic CMS-1500 ──────────────────────────────────────────

def test_synthetic_cms1500():
    """Full synthetic CMS-1500 billing form scan."""
    cms = """
    CMS-1500 Health Insurance Claim Form
    Patient: Roberto Hernandez
    DOB: 11/22/1978
    SSN: 345-67-8901
    Medicare MBI: 3HJ6KL7PM95
    Insurance Member ID: UHC98765432
    NPI: 9876543210
    Address: 789 W Palm Avenue

    Diagnosis: ICD-10: M54.5 low back pain
    Dx: S83.511A sprain of ACL right knee

    Procedures:
    CPT: 99213 office visit
    CPT: 97110 therapeutic exercises
    HCPCS: L1832 knee brace

    Total charges: $450.00
    """
    result = scan(cms)
    assert result["phi_detected"] is True
    types = {e["type"] for e in result["entities"]}
    assert "patient_name" in types
    assert "date_of_birth" in types
    assert "ssn" in types
    assert "medicare_medicaid" in types
    assert "npi" in types
    assert "icd10_code" in types
    assert "cpt_code" in types


def test_synthetic_cms1500_redact_billing():
    """Redact billing preset removes billing identifiers."""
    scanner = FastPHIScanner()
    cms = "Patient Roberto Hernandez SSN: 345-67-8901 Medicare MBI: 3HJ6KL7PM95 NPI: 9876543210 Dx: M54.5 CPT: 99213"
    clean = scanner.redact_billing(cms)
    assert "Roberto Hernandez" not in clean
    assert "345-67-8901" not in clean
    assert "3HJ6KL7PM95" not in clean
    assert "9876543210" not in clean
    assert "M54.5" not in clean
    assert "99213" not in clean


# ── Convenience methods ──────────────────────────────────────────

def test_has_phi():
    scanner = FastPHIScanner()
    assert scanner.has_phi("SSN 123-45-6789") is True
    assert scanner.has_phi("sunny weather") is False


def test_scan_batch():
    scanner = FastPHIScanner()
    results = scanner.scan_batch(["SSN 123-45-6789", "sunny day", "DOB 01/01/1990"])
    assert len(results) == 3
    assert results[0]["phi_detected"] is True
    assert results[1]["phi_detected"] is False
    assert results[2]["phi_detected"] is True


# ── Meta ─────────────────────────────────────────────────────────

def test_scanner_healthy():
    scanner = FastPHIScanner()
    assert scanner.healthy is True
    assert scanner.pattern_count == 32


def test_action_local_only_when_phi():
    result = scan("Patient SSN 123-45-6789")
    assert result["action"] == "local_only"
