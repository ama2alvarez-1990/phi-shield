package com.phishield;

/**
 * Tests for PhiShield. Run with JUnit 5 or just main().
 */
public class PhiShieldTest {

    public static void main(String[] args) {
        PhiShield shield = new PhiShield();
        int passed = 0, failed = 0;

        // Pattern count
        assert shield.patternCount() == 45 : "Expected 45 patterns, got " + shield.patternCount();
        passed++;

        // HIPAA core
        passed += check(shield, "SSN 123-45-6789", true, "ssn");
        passed += check(shield, "DOB 04/08/1990", true, "date_of_birth");
        passed += check(shield, "MRN: MR12345", true, "medical_record_number");
        passed += check(shield, "NPI: 1234567890", true, "npi");
        passed += check(shield, "Patient John Doe admitted", true, "patient_name");

        // EMS
        passed += check(shield, "GPS 40.7128, -74.0060", true, "gps_coordinates");
        passed += check(shield, "BP: 120/80 mmHg", true, "blood_pressure");
        passed += check(shield, "HR: 88 bpm", true, "vital_signs");
        passed += check(shield, "SpO2 97%", true, "vital_signs");
        passed += check(shield, "Dx: S72.001A fracture", true, "icd10_code");
        passed += check(shield, "CPT: 99285 ED visit", true, "cpt_code");
        passed += check(shield, "ePatient.02 field", true, "nemsis_element");
        passed += check(shield, "Run #2024001234", true, "run_incident_number");

        // Cross-vertical
        passed += check(shield, "BUN: 68 mg/dL", true, "lab_values");
        passed += check(shield, "Creatinine: 8.2 mg/dL", true, "lab_values");
        passed += check(shield, "Hgb: 11.2 g/dL", true, "lab_values");
        passed += check(shield, "Administered nitroglycerin 0.4 mg", true, "medication_dose");
        passed += check(shield, "Age: 92", true, "age_over_89");
        passed += check(shield, "HIV: negative", true, "infection_status");
        passed += check(shield, "HBsAg: positive", true, "infection_status");
        passed += check(shield, "MRSA: positive", true, "infection_status");
        passed += check(shield, "Fax: 305-555-1234", true, "fax_number");
        passed += check(shield, "Serial Number: GE94850126", true, "device_serial");

        // Radiology
        passed += check(shield, "Accession Number: E01234567", true, "accession_number");
        passed += check(shield, "Study Instance UID: 2.16.124.113543.1154777499.30246.19789", true, "dicom_uid");
        passed += check(shield, "BI-RADS: 4C", true, "birads_score");
        passed += check(shield, "CTDIvol: 45.23 mGy", true, "radiation_dose");

        // Dialysis
        passed += check(shield, "Kt/V: 1.45", true, "dialysis_adequacy");
        passed += check(shield, "URR: 71.2%", true, "dialysis_adequacy");
        passed += check(shield, "Dry weight: 75.0 kg", true, "dry_weight");
        passed += check(shield, "Left cephalic fistula patent", true, "dialysis_access");
        passed += check(shield, "AVG right forearm", true, "dialysis_access");

        // Safe text
        passed += checkNoDetection(shield, "The weather is sunny today");
        passed += checkNoDetection(shield, "");

        // Redaction
        String clean = shield.redact("SSN is 123-45-6789");
        if (!clean.contains("123-45-6789") && clean.contains("[SSN]")) { passed++; }
        else { failed++; System.out.println("FAIL: redact SSN"); }

        // Redact EMS
        clean = shield.redactEms("Patient John Doe BP: 120/80 GPS 40.7128, -74.0060");
        if (!clean.contains("120/80") && !clean.contains("40.7128")) { passed++; }
        else { failed++; System.out.println("FAIL: redactEms"); }

        // Redact billing
        clean = shield.redactBilling("Dx: S72.001A CPT: 99285 SSN 123-45-6789");
        if (!clean.contains("S72.001A") && !clean.contains("99285")) { passed++; }
        else { failed++; System.out.println("FAIL: redactBilling"); }

        // Contextual date — with medical context
        var r = shield.scan("Patient admitted on 04/08/2024 to hospital");
        if (r.getEntities().stream().anyMatch(e -> e.get("type").equals("date_us"))) { passed++; }
        else { failed++; System.out.println("FAIL: date_us with context"); }

        // Contextual date — without medical context (should NOT detect)
        r = shield.scan("Meeting scheduled 04/08/2024 in conference room");
        if (r.getEntities().stream().noneMatch(e -> e.get("type").equals("date_us"))) { passed++; }
        else { failed++; System.out.println("FAIL: date_us without context should not detect"); }

        System.out.println("\n" + passed + " passed, " + failed + " failed, " + (passed + failed) + " total");
        if (failed > 0) System.exit(1);
    }

    private static int check(PhiShield shield, String text, boolean expectPhi, String expectType) {
        var r = shield.scan(text);
        if (r.isPhiDetected() == expectPhi &&
            r.getEntities().stream().anyMatch(e -> e.get("type").equals(expectType))) {
            return 1;
        }
        System.out.println("FAIL: '" + text + "' expected " + expectType);
        return 0;
    }

    private static int checkNoDetection(PhiShield shield, String text) {
        var r = shield.scan(text);
        if (!r.isPhiDetected()) return 1;
        System.out.println("FAIL: '" + text + "' should not detect PHI");
        return 0;
    }
}
