"""Tests for phi-shield scanner."""

from phi_shield import scan
from phi_shield.scanner import FastPHIScanner


def test_detects_ssn():
    result = scan("Patient SSN 123-45-6789")
    assert result["phi_detected"] is True
    assert any(e["type"] == "ssn" for e in result["entities"])
    assert result["risk"] == "high"


def test_detects_credit_card():
    result = scan("Card 4111 1111 1111 1111 charged")
    assert result["phi_detected"] is True
    assert any(e["type"] == "credit_card" for e in result["entities"])
    assert result["risk"] == "critical"


def test_detects_patient_name():
    result = scan("Patient John Doe admitted today")
    assert result["phi_detected"] is True
    assert any(e["type"] == "patient_name" for e in result["entities"])


def test_detects_dob():
    result = scan("DOB 04/08/1990 confirmed")
    assert result["phi_detected"] is True
    assert any(e["type"] == "date_of_birth" for e in result["entities"])


def test_detects_email():
    result = scan("Contact user@example.com for details")
    assert result["phi_detected"] is True
    assert any(e["type"] == "email" for e in result["entities"])


def test_detects_phone():
    result = scan("Call 555-123-4567 now")
    assert result["phi_detected"] is True
    assert any(e["type"] == "phone" for e in result["entities"])


def test_detects_mrn():
    result = scan("MRN MR-12345 chart review")
    assert result["phi_detected"] is True
    assert any(e["type"] == "medical_record_number" for e in result["entities"])


def test_safe_text_no_phi():
    result = scan("The weather is sunny today")
    assert result["phi_detected"] is False
    assert result["risk"] == "none"
    assert result["action"] == "allow_external"


def test_multiple_entities():
    result = scan("Patient John Smith DOB 04/08/1990 SSN 123-45-6789")
    assert result["phi_detected"] is True
    assert len(result["entities"]) >= 2


def test_empty_string():
    result = scan("")
    assert result["phi_detected"] is False


def test_none_input_doesnt_crash():
    scanner = FastPHIScanner()
    result = scanner.scan(None)
    assert "phi_detected" in result


def test_scanner_healthy():
    scanner = FastPHIScanner()
    assert scanner.healthy is True
    assert scanner.pattern_count == 14


def test_action_local_only_when_phi():
    result = scan("Patient SSN 123-45-6789")
    assert result["action"] == "local_only"


def test_salary_detection():
    result = scan("salary: $150,000 per year")
    assert result["phi_detected"] is True
    assert any(e["type"] == "salary_compensation" for e in result["entities"])
