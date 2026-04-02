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

### Redaction presets

```python
from phi_shield.scanner import FastPHIScanner

scanner = FastPHIScanner()

# Redact all PHI
clean = scanner.redact("Patient John Doe SSN 123-45-6789")

# Vertical-specific presets
clean = scanner.redact_ems(epcr_text)          # ePCR, run sheets, vitals
clean = scanner.redact_billing(cms1500_text)    # CMS-1500, UB-04, claims
clean = scanner.redact_radiology(report_text)   # DICOM metadata, rad reports
clean = scanner.redact_dialysis(treatment_log)  # Treatment logs, ESRD forms
```

### Contextual scanning

Date patterns (`date_us`, `date_written`) only trigger when healthcare keywords are present, reducing false positives in non-medical documents.

## What it detects (45 patterns)

### HIPAA Core (10 patterns)

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

### Cross-vertical (6 patterns)

| Pattern | Risk |
|---|---|
| Lab values (BUN, creatinine, Hgb, PTH, 30+ labs) | High |
| Medication doses (with context) | High |
| Age > 89 (HIPAA special) | High |
| Device serial numbers | Medium |
| Fax numbers | Medium |
| Infection status (HIV, HBsAg, MRSA, HCV) | Critical |

### Radiology (4 patterns)

| Pattern | Risk |
|---|---|
| Accession numbers | High |
| DICOM UIDs (Study/Series/SOP) | Critical |
| BI-RADS classifications | Medium |
| Radiation dose (CTDIvol, DLP) | Medium |

### Dialysis (3 patterns)

| Pattern | Risk |
|---|---|
| Dialysis adequacy (Kt/V, URR) | Medium |
| Dry weight / target weight | Medium |
| Vascular access (AVF, AVG, catheter) | High |

### Other regulations (12 patterns)

| Pattern | Regulation | Risk |
|---|---|---|
| Credit card (full + partial) | PCI-DSS | Critical |
| Bank account/routing | PCI-DSS | High |
| Email address | GDPR | Medium |
| Phone (US + international) | GDPR | Medium |
| IP address | GDPR | Low |
| Passport | GDPR | High |
| Driver's license | GDPR | High |
| VIN | GDPR | Medium |
| Salary/compensation | SOX | High |
| Student ID | FERPA | Medium |

## Key features

- **Zero dependencies** — stdlib only (`re`, `dataclasses`)
- **<1ms** scan time on any text
- **45 patterns** covering HIPAA, PCI-DSS, GDPR, SOX, FERPA
- **4 healthcare verticals** — EMS, radiology, dialysis, billing
- **Contextual scanning** — date patterns require healthcare keywords
- **5 redaction presets** — `redact()`, `redact_ems()`, `redact_billing()`, `redact_radiology()`, `redact_dialysis()`
- **Never raises** — graceful degradation on any error
- **Pre-flight check** — scan before sending to Claude/OpenAI/any LLM API
- **101 tests** passing

## License

MIT

## Author

Amado Alvarez Sueiras
