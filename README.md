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

## What it detects

| Pattern | Regulation | Risk |
|---|---|---|
| SSN (XXX-XX-XXXX) | HIPAA | High |
| Credit card (full + partial) | PCI-DSS | Critical |
| Date of birth | HIPAA | High |
| Medical record number | HIPAA | High |
| Patient name | HIPAA | High |
| Healthcare context | HIPAA | High |
| Email address | GDPR | Medium |
| Phone number | GDPR | Medium |
| IP address | GDPR | Low |
| Passport/Driver's license | GDPR | High |
| Salary/compensation | SOX | High |

## Key features

- **Zero dependencies** — stdlib only (`re`, `dataclasses`)
- **<1ms** scan time on any text
- **14 patterns** covering HIPAA, PCI-DSS, GDPR, SOX
- **Never raises** — graceful degradation on any error
- **Pre-flight check** — scan before sending to Claude/OpenAI/any LLM API

## License

MIT

## Author

Amado Alvarez Sueiras
