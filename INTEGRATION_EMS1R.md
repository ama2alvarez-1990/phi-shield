# phi-shield Integration Guide for EMS1R

## What is phi-shield

Regex-based PHI/PII scanner. 45 patterns. <1ms. Zero external dependencies.
Scans text before it goes to any LLM API (Claude, OpenAI, etc.) and blocks
or redacts protected health information.

## Deploy as microservice

```bash
# Install
pip install fastapi uvicorn
cd phi-shield/
uvicorn server:app --host 0.0.0.0 --port 8900

# Verify
curl http://localhost:8900/health
# {"status":"ok","healthy":true,"pattern_count":45}
```

## API Endpoints

### POST /scan — Check text for PHI

```bash
curl -X POST http://localhost:8900/scan \
  -H "Content-Type: application/json" \
  -d '{"text": "Patient John Doe SSN 123-45-6789 BP: 120/80"}'
```

Response:
```json
{
  "phi_detected": true,
  "entities": [
    {"type": "patient_name", "value": "John Doe"},
    {"type": "ssn", "value": "123-45-67..."},
    {"type": "blood_pressure", "value": "BP: 120/80"}
  ],
  "risk": "high",
  "action": "local_only",
  "regulation": "HIPAA",
  "scanner": "regex_fast",
  "latency_ms": 0.15
}
```

### POST /redact — Remove PHI from text

```bash
curl -X POST http://localhost:8900/redact \
  -H "Content-Type: application/json" \
  -d '{"text": "Patient John Doe SSN 123-45-6789", "preset": "ems"}'
```

Response:
```json
{
  "redacted_text": "Patient [PATIENT_NAME] SSN [SSN]",
  "preset": "ems",
  "latency_ms": 0.12
}
```

Presets: `ems`, `billing`, `radiology`, `dialysis`, or omit for all patterns.

### GET /health — Health check

### GET /patterns — List all 45 active patterns

## Where to integrate in EMS1R (Spring Boot)

### 1. Create a PHI Shield client service

```java
@Service
public class PhiShieldService {

    private final RestTemplate rest = new RestTemplate();
    private static final String PHI_URL = "http://localhost:8900";

    public PhiScanResult scan(String text) {
        var req = Map.of("text", text);
        return rest.postForObject(PHI_URL + "/scan", req, PhiScanResult.class);
    }

    public String redact(String text, String preset) {
        var req = Map.of("text", text, "preset", preset);
        var resp = rest.postForObject(PHI_URL + "/redact", req, Map.class);
        return (String) resp.get("redacted_text");
    }

    public boolean hasPhi(String text) {
        return scan(text).isPhiDetected();
    }
}
```

### 2. Integration points (in priority order)

#### A. Before ANY LLM API call (CRITICAL)
If EMS1R sends text to Claude/OpenAI for narrative generation:

```java
// In NarrativeService or wherever LLM is called
String narrative = buildNarrativePrompt(epcr);
PhiScanResult result = phiShield.scan(narrative);
if (result.isPhiDetected()) {
    // Option 1: Block the call entirely
    throw new PhiDetectedException("PHI found, cannot send to external API");
    // Option 2: Redact before sending
    narrative = phiShield.redact(narrative, "ems");
}
String response = claudeApi.generate(narrative);
```

#### B. Before data export (HIGH)
Any time patient data leaves the system (PDF export, CSV, API response to third party):

```java
// In ExportService
String exportText = generateExportContent(records);
exportText = phiShield.redact(exportText, "ems");
```

#### C. In audit/compliance logging (MEDIUM)
Log the scan results for HIPAA audit trail:

```java
// In AuditService
PhiScanResult result = phiShield.scan(incomingData);
auditLog.save(new AuditEntry(
    "phi_scan", result.getRisk(), result.getEntities().size(),
    result.isPhiDetected() ? "BLOCKED" : "ALLOWED"
));
```

#### D. In API responses (MEDIUM)
Before returning patient data in API responses, scan to prevent accidental PHI leakage:

```java
// In a ResponseBodyAdvice or interceptor
@ControllerAdvice
public class PhiResponseFilter implements ResponseBodyAdvice<Object> {
    // Scan outgoing JSON responses for PHI
}
```

## What phi-shield detects (EMS-relevant)

| Category | Patterns | Examples |
|---|---|---|
| Patient identifiers | SSN, DOB, MRN, patient name, NPI, Medicare MBI | "SSN: 123-45-6789" |
| Contact info | Phone, email, fax, address, ZIP+4 | "Fax: 305-555-1234" |
| EMS-specific | GPS, BP, vitals, NEMSIS, run/incident #, ICD-10, CPT | "BP: 120/80", "Run #2024001" |
| Clinical | Lab values (30+ types), medication doses, infection status | "BUN: 68 mg/dL" |
| Financial | Credit card, bank account, insurance ID | "Card 4111..." |
| Special | Age >89, device serial numbers, DICOM UIDs | "Age: 92" |

## Docker deployment

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY phi_shield/ phi_shield/
COPY server.py .
RUN pip install --no-cache-dir fastapi uvicorn
EXPOSE 8900
USER nobody
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8900"]
```

```yaml
# docker-compose.yml addition
services:
  phi-shield:
    build: ./phi-shield
    ports:
      - "8900:8900"
    restart: unless-stopped
    mem_limit: 128m
    cpus: 0.5
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8900/health"]
      interval: 30s
      timeout: 5s
      retries: 3
```

## Performance

- Scan latency: <1ms (regex only, no ML)
- Memory: ~20MB
- No GPU needed
- No external API calls — everything local
- Never crashes — graceful degradation on any error
