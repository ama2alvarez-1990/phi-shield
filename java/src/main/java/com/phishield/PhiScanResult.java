package com.phishield;

import java.util.List;
import java.util.Map;

/**
 * Result of a PHI scan.
 *
 * @author Amado Alvarez Sueiras
 */
public class PhiScanResult {

    private final boolean phiDetected;
    private final List<Map<String, String>> entities;
    private final String risk;
    private final String action;
    private final String regulation;

    public PhiScanResult(boolean phiDetected, List<Map<String, String>> entities,
                         String risk, String action, String regulation) {
        this.phiDetected = phiDetected;
        this.entities = entities;
        this.risk = risk;
        this.action = action;
        this.regulation = regulation;
    }

    public boolean isPhiDetected() { return phiDetected; }
    public List<Map<String, String>> getEntities() { return entities; }
    public String getRisk() { return risk; }
    public String getAction() { return action; }
    public String getRegulation() { return regulation; }
}
