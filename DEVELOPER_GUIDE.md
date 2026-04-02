# phi-shield — Guia para el Developer de EMS1R

## Que es phi-shield

phi-shield es un scanner de PHI (Protected Health Information) que detecta
informacion protegida de pacientes en texto ANTES de que ese texto salga del
sistema. Funciona con regex patterns — no usa inteligencia artificial, no
necesita internet, no envia data a ningun servidor externo.

## Por que existe

HIPAA (la ley federal de privacidad de salud en USA) prohibe enviar
informacion identificable de pacientes a sistemas externos sin autorizacion.
Cuando EMS1R usa AI (Claude, OpenAI, etc.) para generar narrativas de ePCR
o procesar data de pacientes, esa data pasa por servidores externos.

phi-shield escanea el texto ANTES de enviarlo al AI y:
1. **Detecta** si hay PHI (nombres, SSN, vitals, GPS, run numbers, etc.)
2. **Bloquea** el envio si detecta PHI
3. **Redacta** (reemplaza) el PHI con marcadores como [SSN], [PATIENT_NAME]

Sin esto, EMS1R estaria violando HIPAA cada vez que usa AI con data real.

## Como funciona (diagrama simple)

```
Texto del ePCR
    |
    v
phi-shield.scan(texto)
    |
    +-- PHI detectado? --YES--> BLOQUEAR envio al AI
    |                           (o redactar primero, luego enviar)
    |
    +-- No PHI ----------YES--> Enviar al AI normalmente
```

## Que detecta (45 patterns)

### Identificadores de paciente (lo basico)
- SSN (123-45-6789)
- Fecha de nacimiento (DOB: 04/08/1990)
- Numero de record medico (MRN: MR12345)
- Nombre del paciente (Patient John Doe)
- NPI del proveedor (NPI: 1234567890)
- Medicare/Medicaid ID
- Insurance ID
- Direccion fisica
- Telefono, email, fax

### Datos clinicos EMS (esto es lo que diferencia phi-shield)
- GPS del incidente (40.7128, -74.0060)
- Presion arterial (BP: 120/80)
- Signos vitales (HR: 88 bpm, SpO2 97%, GCS: 15, temp, glucose)
- Codigos ICD-10 (S72.001A)
- Codigos CPT/HCPCS (99285)
- Elementos NEMSIS (ePatient.02, eVitals.06)
- Numero de run/incidente (Run #2024001234)
- Fechas en contexto medico
- ZIP+4

### Valores de laboratorio (30+ tipos)
- BUN, creatinine, hemoglobin, albumin, PTH, HbA1c, INR, troponin,
  ferritin, TSH, AST, ALT, PSA, eGFR, y mas

### Otros
- Status de infeccion (HIV, Hepatitis B/C, MRSA) — CRITICAL risk
- Dosis de medicamentos
- Edad >89 (HIPAA requiere proteccion especial)
- Numeros de serie de dispositivos medicos
- Tarjetas de credito, cuentas bancarias
- DICOM UIDs (imagenes radiologicas)
- BI-RADS (clasificacion de mamografia)
- Dosis de radiacion
- Kt/V, URR (dialisis)
- Acceso vascular (fistula, graft, cateter)

## Implementacion en EMS1R (Spring Boot)

### Paso 1: Agregar los archivos Java

Copiar estos 2 archivos a tu proyecto:

```
src/main/java/com/phishield/PhiShield.java
src/main/java/com/phishield/PhiScanResult.java
```

No necesita Maven dependencies adicionales. Solo usa `java.util.regex`.

### Paso 2: Crear el servicio de Spring

```java
package com.ems1r.service;

import com.phishield.PhiShield;
import com.phishield.PhiScanResult;
import org.springframework.stereotype.Service;

@Service
public class PhiShieldService {

    private final PhiShield shield = new PhiShield();

    /**
     * Escanea texto y retorna si contiene PHI.
     * Usar ANTES de enviar cualquier texto a APIs externas.
     */
    public PhiScanResult scan(String text) {
        return shield.scan(text);
    }

    /**
     * Retorna true si el texto contiene PHI.
     */
    public boolean hasPhi(String text) {
        return shield.hasPhi(text);
    }

    /**
     * Redacta TODO el PHI del texto con marcadores [TIPO].
     * Ejemplo: "Patient John Doe SSN 123-45-6789"
     *       -> "Patient [PATIENT_NAME] SSN [SSN]"
     */
    public String redact(String text) {
        return shield.redact(text);
    }

    /**
     * Redacta solo PHI relevante a EMS (vitals, GPS, run numbers, etc.)
     */
    public String redactEms(String text) {
        return shield.redactEms(text);
    }

    /**
     * Redacta solo PHI de billing (ICD-10, CPT, insurance, etc.)
     */
    public String redactBilling(String text) {
        return shield.redactBilling(text);
    }
}
```

### Paso 3: Usar en los puntos criticos

#### 3A. ANTES de llamar a cualquier API de AI (Claude, OpenAI, etc.)

Este es el punto MAS CRITICO. Si EMS1R genera narrativas con AI:

```java
@Service
public class NarrativeService {

    private final PhiShieldService phiShield;
    private final ClaudeApiClient claude;

    public NarrativeService(PhiShieldService phiShield, ClaudeApiClient claude) {
        this.phiShield = phiShield;
        this.claude = claude;
    }

    public String generateNarrative(EpcrData epcr) {
        String prompt = buildPrompt(epcr);

        // PASO CRITICO: escanear antes de enviar
        PhiScanResult result = phiShield.scan(prompt);

        if (result.isPhiDetected()) {
            // Opcion A: Redactar y enviar version limpia
            String cleanPrompt = phiShield.redactEms(prompt);
            return claude.generate(cleanPrompt);

            // Opcion B: Bloquear completamente
            // throw new PhiDetectedException("PHI found: " + result.getRisk());
        }

        return claude.generate(prompt);
    }
}
```

#### 3B. En exports de data (PDF, CSV, reportes)

```java
public byte[] exportReport(Long reportId) {
    String content = buildReportContent(reportId);
    // Redactar antes de exportar
    String clean = phiShield.redactEms(content);
    return generatePdf(clean);
}
```

#### 3C. En el audit log (para compliance HIPAA)

```java
// Registrar cada escaneo en el audit trail
PhiScanResult result = phiShield.scan(text);
auditRepository.save(new AuditLog(
    "phi_scan",
    result.isPhiDetected() ? "BLOCKED" : "ALLOWED",
    result.getRisk(),
    result.getEntities().size()
));
```

### Paso 4: Tests

Compilar y correr `PhiShieldTest.java`:

```bash
javac -d out src/main/java/com/phishield/*.java src/test/java/com/phishield/*.java
java -ea -cp out com.phishield.PhiShieldTest
# Esperado: 40 passed, 0 failed
```

## Presets de redaccion

phi-shield tiene 5 modos de redaccion. Cada uno solo redacta los patterns
relevantes a ese contexto:

| Metodo | Que redacta | Cuando usar |
|---|---|---|
| `redact()` | TODO (45 patterns) | Cuando no sabes que tipo de texto es |
| `redactEms()` | Vitals, GPS, run#, paciente, contacto | ePCR, run sheets, PCR |
| `redactBilling()` | ICD-10, CPT, insurance, financiero | CMS-1500, UB-04, claims |
| `redactRadiology()` | DICOM, accession, BI-RADS, dosis | Reportes de radiologia |
| `redactDialysis()` | Kt/V, dry weight, access, labs, infeccion | Logs de dialisis |

## Performance

- **Velocidad**: <1ms por escaneo (es solo regex, no AI)
- **Memoria**: ~5MB (los patterns compilados)
- **Dependencias**: CERO — solo `java.util.regex`
- **Errores**: NUNCA lanza excepcion — retorna resultado seguro por defecto
- **Thread-safe**: Si — los patterns son inmutables despues de construccion

## Preguntas frecuentes

**P: Esto reemplaza el compliance HIPAA?**
No. HIPAA requiere policies, training, BAAs, controles fisicos, y mas.
phi-shield es UNA capa tecnica que previene leaks accidentales de PHI.

**P: Que pasa si no detecta algo?**
Los patterns cubren los 18 identificadores HIPAA mas 27 patterns adicionales
especificos de healthcare. No es 100% — nombres sin contexto "Patient" no
se detectan (eso requiere NLP/AI). Pero cubre la gran mayoria de formatos
estructurados de PHI.

**P: Puedo agregar patterns propios?**
Si, pero requiere modificar PhiShield.java y agregar el pattern en buildPatterns().
Contactar a Amado para patterns adicionales.
