# phi-shield

Fast PHI/PII scanner for LLM pipelines. HIPAA, PCI-DSS, GDPR compliance in <1ms.

## Install

```bash
pip install phi-shield
```

## Usage

```python
from phi_shield import scan

result = scan("Patient John Doe SSN 123-45-6789")
if result["phi_detected"]:
    print(f"PHI found! Risk: {result['risk']}")
    print(f"Action: {result['action']}")  # "local_only"
    for entity in result["entities"]:
        print(f"  {entity['type']}: {entity['value']}")
```

### Redaction

```python
from phi_shield.scanner import FastPHIScanner

scanner = FastPHIScanner()

# Redact all PHI
clean = scanner.redact("Patient John Doe SSN 123-45-6789")
# → "Patient [PATIENT_NAME] SSN [SSN]"

# EMS preset — redacts vitals, GPS, run numbers, patient identifiers
clean = scanner.redact_ems(epcr_text)

# Billing preset — redacts ICD-10, CPT, insurance IDs, financial data
clean = scanner.redact_billing(cms1500_text)
```

### Contextual scanning

Date patterns (`date_us`, `date_written`) only trigger when healthcare keywords are present in the text, reducing false positives in non-medical documents.

## What it detects

### HIPAA (10 core patterns)

| Pattern | Risk |
|---|---|
| SSN (XXX-XX-XXXX) | High |
| Date of birth | High |
| Medical record number | High |
| NPI (National Provider ID) | High |
| Medicare/Medicaid MBI | High |
| Insurance ID | High |
| Patient name | High |
| Healthcare context | High |
| Medical documents | High |
| Physical address | Medium |

### HIPAA-EMS (10 patterns)

| Pattern | Risk |
|---|---|
| GPS coordinates | Medium |
| Blood pressure (BP, SBP, DBP) | High |
| Vital signs (HR, SpO2, RR, GCS, temp, glucose) | High |
| ICD-10 codes | Medium |
| CPT/HCPCS codes | Medium |
| NEMSIS element references | Medium |
| Run/incident/PCR numbers | High |
| US dates (with medical context) | Medium |
| Written dates (with medical context) | Medium |
| ZIP+4 codes | Low |

### Other regulations

| Pattern | Regulation | Risk |
|---|---|---|
| Credit card (full + partial) | PCI-DSS | Critical |
| Bank account/routing | PCI-DSS | High |
| Email address | GDPR | Medium |
| Phone (US + international) | GDPR | Medium |
| IP address | GDPR | Low |
| Passport/Driver's license | GDPR | High |
| VIN | GDPR | Medium |
| Salary/compensation | SOX | High |
| Student ID | FERPA | Medium |

## Key features

- **Zero dependencies** — stdlib only (`re`, `dataclasses`)
- **<1ms** scan time on any text
- **32 patterns** covering HIPAA, PCI-DSS, GDPR, SOX, FERPA
- **Contextual scanning** — date patterns require healthcare keywords
- **Redaction presets** — `redact_ems()` and `redact_billing()` for EMS/billing workflows
- **Never raises** — graceful degradation on any error
- **Pre-flight check** — scan before sending to Claude/OpenAI/any LLM API
- **65 tests** passing

## License

MIT

## Author

Amado Alvarez Sueiras
