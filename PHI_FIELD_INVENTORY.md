# PHI Field Inventory — EMS + Hospital Documents

Research from NEMSIS 3.5, PCS, DNR/POLST, Face Sheet, Discharge Summary,
CMS-1500, UB-04, Run Sheet. 200+ PHI fields identified.

## HIPAA 18 Official Identifiers
1. Names  2. Geographic (sub-state)  3. Dates  4. Phone  5. Fax
6. Email  7. SSN  8. MRN  9. Health plan IDs  10. Account numbers
11. License numbers  12. Vehicle IDs  13. Device IDs  14. Web URLs
15. IP addresses  16. Biometrics  17. Photos  18. Any other unique ID

## Priority Patterns to Implement

### CRITICAL (regex-detectable, EMS-specific)
- NEMSIS element references (ePatient.XX)
- Run/Incident numbers (agency-specific alphanumeric)
- NPI: \b\d{10}\b with context "NPI|provider|physician"
- Medicare MBI: \b[1-9][A-Z0-9]{2}\d[A-Z][A-Z0-9]\d[A-Z]{2}\d\b
- GPS coordinates: \b\d{1,3}\.\d{4,8},\s*-?\d{1,3}\.\d{4,8}\b
- Blood pressure: \b\d{2,3}/\d{2,3}\b with context "BP|blood pressure"
- ICD-10: \b[A-Z]\d{2}(\.\d{1,4})?\b with context
- CPT codes: \b\d{5}\b with context "CPT|procedure|service"
- Dates (all formats): MM/DD/YYYY, MMDDYYYY, ISO 8601
- ZIP+4: \b\d{5}-\d{4}\b

### HIGH (needs context keywords)
- Patient names without "Patient" prefix (needs NER, not just regex)
- Addresses (street patterns)
- Insurance/Policy/Group IDs
- Physician/Crew names
- Hospital/Facility names
- Drug names + dosages

### MEDIUM (quasi-identifiers, contextual)
- Age > 89
- Race + gender + ZIP combination
- Employer information

## Document-Specific Field Counts
- ePCR (NEMSIS 3.5): ~120 PHI fields
- Hospital Face Sheet: ~40 fields
- CMS-1500: ~33 boxes, ~25 with PHI
- UB-04: ~81 form locators, ~50 with PHI
- Discharge Summary: ~30 sections
- PCS Form: ~25 fields
- DNR/POLST: ~15 fields
- Run Sheet: ~60 fields

## Implementation Plan (next session)
1. Add 15-20 EMS-specific regex patterns (GPS, BP, NPI, MBI, ICD-10, etc.)
2. Add contextual scanning (keyword + pattern combo)
3. Add redaction presets: redact_ems(), redact_hospital(), redact_billing()
4. Test against synthetic ePCR, discharge summary, and CMS-1500
