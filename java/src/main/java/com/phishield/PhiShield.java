package com.phishield;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Fast PHI/PII scanner using regex patterns. &lt;1ms. Zero dependencies.
 *
 * <p>45 patterns covering HIPAA (core + EMS + radiology + dialysis),
 * PCI-DSS, GDPR, SOX, FERPA.
 *
 * <pre>{@code
 * PhiShield shield = new PhiShield();
 * PhiScanResult result = shield.scan("Patient John Doe SSN 123-45-6789");
 * if (result.isPhiDetected()) {
 *     // block or redact
 * }
 * String clean = shield.redact("Patient John Doe SSN 123-45-6789");
 * String emsClean = shield.redactEms(epcrText);
 * }</pre>
 *
 * @author Amado Alvarez Sueiras
 */
public class PhiShield {

    /** Risk levels ordered by severity. */
    private enum Risk {
        NONE, LOW, MEDIUM, HIGH, CRITICAL;

        static Risk from(String s) {
            try { return valueOf(s.toUpperCase()); } catch (Exception e) { return NONE; }
        }
    }

    private record PatternDef(Pattern pattern, Risk risk, String regulation, Set<String> context) {}

    private final Map<String, PatternDef> patterns;

    // ── Redaction preset groups ─────────────────────────────────

    private static final Set<String> EMS_PATTERNS = Set.of(
        "ssn", "date_of_birth", "medical_record_number", "npi", "patient_name",
        "physical_address", "phone", "email", "fax_number", "gps_coordinates",
        "blood_pressure", "vital_signs", "nemsis_element", "run_incident_number",
        "date_us", "date_written", "zip_plus4", "medication_dose", "age_over_89",
        "lab_values", "infection_status"
    );

    private static final Set<String> BILLING_PATTERNS = Set.of(
        "ssn", "date_of_birth", "medical_record_number", "npi", "medicare_medicaid",
        "insurance_id", "patient_name", "physical_address", "icd10_code", "cpt_code",
        "credit_card", "credit_card_partial", "bank_account", "fax_number"
    );

    private static final Set<String> RADIOLOGY_PATTERNS = Set.of(
        "ssn", "date_of_birth", "medical_record_number", "npi", "patient_name",
        "physical_address", "phone", "email", "fax_number", "accession_number",
        "dicom_uid", "birads_score", "radiation_dose", "icd10_code", "cpt_code",
        "device_serial", "date_us", "date_written", "lab_values", "age_over_89",
        "insurance_id", "medicare_medicaid"
    );

    private static final Set<String> DIALYSIS_PATTERNS = Set.of(
        "ssn", "date_of_birth", "medical_record_number", "npi", "patient_name",
        "physical_address", "phone", "email", "fax_number", "dialysis_adequacy",
        "dry_weight", "dialysis_access", "lab_values", "medication_dose",
        "infection_status", "vital_signs", "blood_pressure", "icd10_code",
        "cpt_code", "insurance_id", "medicare_medicaid", "date_us", "date_written",
        "age_over_89"
    );

    private static final Set<String> HEALTHCARE_CONTEXT_KEYWORDS = Set.of(
        "patient", "medical", "clinical", "ems", "hospital", "ambulance",
        "epcr", "chart", "record", "diagnosis", "treatment", "admission",
        "discharge", "transfer", "medication", "prescription", "incident",
        "pcr", "run sheet", "billing", "cms-1500", "ub-04", "hipaa"
    );

    public PhiShield() {
        this.patterns = buildPatterns();
    }

    /** Number of active patterns. */
    public int patternCount() { return patterns.size(); }

    /** True if scanner loaded patterns successfully. */
    public boolean isHealthy() { return !patterns.isEmpty(); }

    // ── Scan ────────────────────────────────────────────────────

    /**
     * Scan text for PHI/PII. Never throws.
     */
    public PhiScanResult scan(String text) {
        try {
            return scanImpl(text);
        } catch (Exception e) {
            return new PhiScanResult(false, List.of(), "unknown", "allow_external", "none");
        }
    }

    /** Quick boolean check. */
    public boolean hasPhi(String text) {
        return scan(text).isPhiDetected();
    }

    private PhiScanResult scanImpl(String text) {
        if (text == null || text.isEmpty()) {
            return new PhiScanResult(false, List.of(), "none", "allow_external", "none");
        }

        List<Map<String, String>> entities = new ArrayList<>();
        Risk maxRisk = Risk.NONE;
        String maxRegulation = "none";
        String textLower = text.toLowerCase();

        for (var entry : patterns.entrySet()) {
            String type = entry.getKey();
            PatternDef def = entry.getValue();

            if (def.context != null && !def.context.isEmpty()) {
                if (def.context.stream().noneMatch(textLower::contains)) {
                    continue;
                }
            }

            Matcher m = def.pattern.matcher(text);
            while (m.find()) {
                String value = m.group();
                if (value.length() > 20) value = value.substring(0, 10) + "...";
                entities.add(Map.of("type", type, "value", value));
                if (def.risk.ordinal() > maxRisk.ordinal()) {
                    maxRisk = def.risk;
                    maxRegulation = def.regulation;
                }
            }
        }

        boolean detected = !entities.isEmpty();
        return new PhiScanResult(
            detected, entities,
            maxRisk.name().toLowerCase(),
            detected ? "local_only" : "allow_external",
            detected ? maxRegulation : "none"
        );
    }

    // ── Redact ──────────────────────────────────────────────────

    /** Redact all PHI with [TYPE] markers. */
    public String redact(String text) {
        return redactSubset(text, null);
    }

    /** Redact EMS-specific PHI (ePCR, run sheets, vitals). */
    public String redactEms(String text) {
        return redactSubset(text, EMS_PATTERNS);
    }

    /** Redact billing PHI (CMS-1500, UB-04, claims). */
    public String redactBilling(String text) {
        return redactSubset(text, BILLING_PATTERNS);
    }

    /** Redact radiology PHI (DICOM metadata, reports). */
    public String redactRadiology(String text) {
        return redactSubset(text, RADIOLOGY_PATTERNS);
    }

    /** Redact dialysis PHI (treatment logs, ESRD forms). */
    public String redactDialysis(String text) {
        return redactSubset(text, DIALYSIS_PATTERNS);
    }

    private String redactSubset(String text, Set<String> subset) {
        if (text == null || text.isEmpty()) return text;
        String result = text;
        String textLower = text.toLowerCase();

        for (var entry : patterns.entrySet()) {
            String type = entry.getKey();
            PatternDef def = entry.getValue();

            if (subset != null && !subset.contains(type)) continue;
            if (def.context != null && !def.context.isEmpty()) {
                if (def.context.stream().noneMatch(textLower::contains)) continue;
            }

            result = def.pattern.matcher(result).replaceAll("[" + type.toUpperCase() + "]");
        }
        return result;
    }

    // ── Pattern definitions ─────────────────────────────────────

    private static Map<String, PatternDef> buildPatterns() {
        Map<String, PatternDef> map = new LinkedHashMap<>();
        int ci = Pattern.CASE_INSENSITIVE;

        // ── HIPAA core ──
        map.put("ssn", p("\\b\\d{3}-\\d{2}-\\d{4}\\b", 0, Risk.HIGH, "HIPAA", null));
        map.put("date_of_birth", p("\\b(?:DOB|date of birth|born|birthday|d\\.o\\.b)[:\\s]+\\d{1,2}[/\\-.]\\d{1,2}[/\\-.]\\d{2,4}\\b", ci, Risk.HIGH, "HIPAA", null));
        map.put("medical_record_number", p("\\b(?:MRN|medical record|chart|patient\\s*(?:id|#|no|number))[:\\s#]+\\w{4,15}\\b", ci, Risk.HIGH, "HIPAA", null));
        map.put("npi", p("\\b(?:NPI|national provider)[:\\s#]+\\d{10}\\b", ci, Risk.HIGH, "HIPAA", null));
        map.put("medicare_medicaid", p("\\b(?:medicare|medicaid|mbi|hic)[:\\s#]+[A-Z0-9]{8,12}\\b", ci, Risk.HIGH, "HIPAA", null));
        map.put("insurance_id", p("\\b(?:insurance|member|subscriber|group|policy)\\s*(?:id|#|no|number)[:\\s]+[A-Z0-9]{5,20}\\b", ci, Risk.HIGH, "HIPAA", null));
        map.put("patient_name", p("\\b[Pp]atient[\\s:]+([A-Z][a-z]+(?:\\s+[A-Z][a-z]+)+)", 0, Risk.HIGH, "HIPAA", null));
        map.put("healthcare_context", p("\\b(?:patient|room\\s+\\d+|ward|icu|er\\b|diagnosis|prescription|dosage|medication|prognosis|biopsy|radiology|oncology|lab\\s+results?)(?:\\s+\\w+){0,5}\\s+(?:need|require|adjust|review|check|update|send|transfer|prescri)", ci, Risk.HIGH, "HIPAA", null));
        map.put("medical_document", p("\\b(?:discharge\\s+summary|medical\\s+record|lab\\s+result|pathology\\s+report|radiology\\s+report|clinical\\s+note|operative\\s+report|admit|referral)\\b.*?\\b(?:send|transfer|fax|email|forward|share|review|update)", ci, Risk.HIGH, "HIPAA", null));
        map.put("physical_address", p("\\b\\d{1,5}\\s+(?:N\\.?|S\\.?|E\\.?|W\\.?|North|South|East|West)?\\s*(?:[A-Z][a-z]+\\s+){1,3}(?:St(?:reet)?|Ave(?:nue)?|Blvd|Dr(?:ive)?|Ln|Lane|Rd|Road|Way|Ct|Court|Pl(?:ace)?|Cir(?:cle)?)\\b", 0, Risk.MEDIUM, "HIPAA", null));

        // ── PCI-DSS ──
        map.put("credit_card", p("\\b(?:\\d{4}[-\\s]?){3}\\d{4}\\b", 0, Risk.CRITICAL, "PCI_DSS", null));
        map.put("credit_card_partial", p("\\b(?:card|credit|debit|visa|mastercard|amex)[\\s#:]*(?:ending|last\\s*4|xxxx)[\\s#:]*\\d{4}\\b", ci, Risk.HIGH, "PCI_DSS", null));
        map.put("bank_account", p("\\b(?:account|routing)[\\s#:]*\\d{6,12}\\b", ci, Risk.HIGH, "PCI_DSS", null));

        // ── GDPR ──
        map.put("email", p("\\b[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}\\b", 0, Risk.MEDIUM, "GDPR", null));
        map.put("phone", p("\\b(?:\\+1[-.]?)?\\(?\\d{3}\\)?[-.\\s]\\d{3}[-.\\s]\\d{4}\\b", 0, Risk.MEDIUM, "GDPR", null));
        map.put("phone_intl", p("\\+\\d{1,3}[-.\\s]?\\d{1,4}[-.\\s]?\\d{2,4}[-.\\s]?\\d{2,4}(?:[-.\\s]?\\d{1,4})?\\b", 0, Risk.MEDIUM, "GDPR", null));
        map.put("ip_address", p("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", 0, Risk.LOW, "GDPR", null));
        map.put("passport", p("\\b(?:passport)[\\s#:]+[A-Z0-9]{6,12}\\b", ci, Risk.HIGH, "GDPR", null));
        map.put("driver_license", p("\\b(?:driver.?s?\\s*license|DL)[\\s#:]+[A-Z0-9]{5,15}\\b", ci, Risk.HIGH, "GDPR", null));
        map.put("vin", p("\\b(?:VIN|vehicle)[:\\s#]+[A-HJ-NPR-Z0-9]{17}\\b", ci, Risk.MEDIUM, "GDPR", null));

        // ── SOX / FERPA ──
        map.put("salary_compensation", p("\\b(?:salary|compensation|payroll|wage|bonus)[\\s:]+\\$?\\d[\\d,.]+\\b", ci, Risk.HIGH, "SOX", null));
        map.put("student_id", p("\\b(?:student\\s*(?:id|#|number))[:\\s]+[A-Z0-9]{5,12}\\b", ci, Risk.MEDIUM, "FERPA", null));

        // ── EMS / HEALTHCARE ──
        map.put("gps_coordinates", p("-?\\d{1,3}\\.\\d{4,},\\s*-?\\d{1,3}\\.\\d{4,}", 0, Risk.MEDIUM, "HIPAA", null));
        map.put("blood_pressure", p("\\b(?:BP|B/P|blood\\s*pressure|SBP|DBP|systolic|diastolic)[:\\s]*\\d{2,3}\\s*/\\s*\\d{2,3}\\b", ci, Risk.HIGH, "HIPAA", null));
        map.put("vital_signs", p("\\b(?:HR|heart\\s*rate|pulse|SpO2|O2\\s*sat|RR|resp(?:iratory)?\\s*rate|GCS|temp(?:erature)?|glucose|BGL)[:\\s]*\\d{1,3}(?:\\.\\d)?\\s*(?:%|bpm|/min|[°]?[FC]|mg/dL)?\\b", ci, Risk.HIGH, "HIPAA", null));
        map.put("icd10_code", p("\\b(?:ICD[\\-.]?10|diagnosis|dx)[:\\s]*[A-Z]\\d{2}(?:\\.\\d{1,4})?[A-Z]?\\b", ci, Risk.MEDIUM, "HIPAA", null));
        map.put("cpt_code", p("\\b(?:CPT|procedure\\s*code|billing\\s*code|HCPCS)[:\\s]*[A-Z0-9]\\d{4}(?:[-\\s]?\\d{2})?\\b", ci, Risk.MEDIUM, "HIPAA", null));
        map.put("nemsis_element", p("\\be(?:Patient|Situation|Response|Dispatch|Scene|Crew|Vitals|Medication|Procedure|Disposition|Outcome|Narrative|Custom|Payment|Injury)\\.\\d{2,3}\\b", 0, Risk.MEDIUM, "HIPAA", null));
        map.put("run_incident_number", p("\\b(?:run|incident|pcr|case|call)\\s*(?:#|no\\.?|number|id)?[:\\s]*[A-Z]?\\d{4,12}\\b", ci, Risk.HIGH, "HIPAA", null));
        map.put("date_us", p("\\b(?:0?[1-9]|1[0-2])[/\\-](?:0?[1-9]|[12]\\d|3[01])[/\\-](?:19|20)\\d{2}\\b", 0, Risk.MEDIUM, "HIPAA", HEALTHCARE_CONTEXT_KEYWORDS));
        map.put("date_written", p("\\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\\s+\\d{1,2},?\\s+\\d{4}\\b", ci, Risk.MEDIUM, "HIPAA", HEALTHCARE_CONTEXT_KEYWORDS));
        map.put("zip_plus4", p("\\b\\d{5}-\\d{4}\\b", 0, Risk.LOW, "HIPAA", null));

        // ── CROSS-VERTICAL ──
        map.put("lab_values", p("\\b(?:BUN|creatinine|Cr|SCr|hemoglobin|Hgb|Hb|WBC|RBC|platelet|albumin|phosphorus|PO4|PTH|HbA1c|A1c|INR|potassium|sodium|ferritin|troponin|TSH|calcium|magnesium|AST|ALT|bilirubin|lipase|amylase|BNP|proBNP|lactate|CRP|ESR|PSA|eGFR)[:\\s]+\\d+(?:\\.\\d+)?\\s*(?:mg/dL|g/dL|pg/mL|ng/mL|mEq/L|mmol/L|U/L|IU/L|%|K/uL|mL/min)?\\b", ci, Risk.HIGH, "HIPAA", null));
        map.put("medication_dose", p("\\b(?:administered|prescribed|given|dose|medication|med|ordered|dispensed)[:\\s]+\\w+\\s+\\d+(?:\\.\\d+)?\\s*(?:mg|mcg|mL|units?|mEq|IU|g)\\b", ci, Risk.HIGH, "HIPAA", null));
        map.put("age_over_89", p("\\b(?:age|aged|years?\\s*old)[:\\s]+(?:9\\d|1[0-9]\\d)\\b", ci, Risk.HIGH, "HIPAA", null));
        map.put("device_serial", p("\\b(?:serial\\s*(?:number|#|no\\.?)|SN|device\\s*(?:id|#))[:\\s]+[A-Z0-9\\-]{5,20}\\b", ci, Risk.MEDIUM, "HIPAA", null));
        map.put("fax_number", p("\\b(?:fax|facsimile)[:\\s]+(?:\\+1[-.]?)?\\(?\\d{3}\\)?[-.\\s]\\d{3}[-.\\s]\\d{4}\\b", ci, Risk.MEDIUM, "HIPAA", null));
        map.put("infection_status", p("\\b(?:HIV|HBsAg|hepatitis\\s*[BC]|HCV|anti-?HCV|MRSA|VRE|C\\.?\\s*diff)[:\\s]+(?:positive|negative|reactive|non-?reactive|detected|not\\s*detected|\\+|-)\\b", ci, Risk.CRITICAL, "HIPAA", null));

        // ── RADIOLOGY ──
        map.put("accession_number", p("\\b(?:accession|acc)\\s*(?:number|no\\.?|#|id)?[:\\s]+[A-Z0-9]{6,20}\\b", ci, Risk.HIGH, "HIPAA", null));
        map.put("dicom_uid", p("\\b(?:study|series|sop)\\s*(?:instance)?\\s*uid[:\\s=]+(?:\\d+\\.){3,}\\d+\\b", ci, Risk.CRITICAL, "HIPAA", null));
        map.put("birads_score", p("\\bBI-?RADS\\s*(?:category\\s*)?:?\\s*[0-6][A-C]?\\b", ci, Risk.MEDIUM, "HIPAA", null));
        map.put("radiation_dose", p("\\b(?:CTDIvol|DLP|dose\\s*(?:index|length\\s*product))[:\\s]+\\d+(?:\\.\\d+)?\\s*(?:mGy|mGy[·\\-]cm|mSv|mrad)\\b", ci, Risk.MEDIUM, "HIPAA", null));

        // ── DIALYSIS ──
        map.put("dialysis_adequacy", p("\\b(?:Kt/V|spKt/V|eKt/V|URR|urea\\s*reduction)[:\\s]+\\d+(?:\\.\\d+)?%?\\b", ci, Risk.MEDIUM, "HIPAA", null));
        map.put("dry_weight", p("\\b(?:dry\\s*weight|target\\s*weight|EDW|estimated\\s*dry\\s*weight)[:\\s]+\\d+(?:\\.\\d+)?\\s*(?:kg|lbs?)\\b", ci, Risk.MEDIUM, "HIPAA", null));
        map.put("dialysis_access", p("\\b(?:AV\\s*fistula|AVF|AV\\s*graft|AVG|tunneled\\s*catheter|permcath|dialysis\\s*catheter|(?:left|right)\\s+(?:radial|brachial|cephalic|basilic|subclavian|femoral|jugular)\\s+(?:fistula|graft|catheter|access))\\b", ci, Risk.HIGH, "HIPAA", null));

        return Collections.unmodifiableMap(map);
    }

    private static PatternDef p(String regex, int flags, Risk risk, String regulation, Set<String> context) {
        return new PatternDef(Pattern.compile(regex, flags), risk, regulation, context);
    }
}
