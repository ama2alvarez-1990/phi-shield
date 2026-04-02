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
    assert scanner.pattern_count == 22


def test_action_local_only_when_phi():
    result = scan("Patient SSN 123-45-6789")
    assert result["action"] == "local_only"
