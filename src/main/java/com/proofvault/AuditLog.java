package com.proofvault;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * ============================================================================
 * JAVA OOP CONCEPT: AUDIT LOG MODEL WITH HASH-CHAINED INTEGRITY
 * ============================================================================
 * AuditLog records forensic events and links each entry to its predecessor
 * using cryptographic hash chaining.
 *
 * Hash-Chain Concept:
 * - Genesis (first entry) prevHash is fixed at 64 zeros.
 * - Each subsequent entry incorporates the previous entry's SHA-256 hash.
 * - Any unauthorized row deletion, insertion, or modification in MySQL breaks
 *   the mathematical linkage of the chain, making tampering detectable.
 */
public class AuditLog {

    public static final String GENESIS_PREV_HASH = "0000000000000000000000000000000000000000000000000000000000000000";
    public static final DateTimeFormatter TIMESTAMP_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // Enums for strongly-typed audit actions and verification statuses
    public enum ActionType {
        EVIDENCE_REGISTER,
        INTEGRITY_CHECK,
        EVIDENCE_MISSING,
        INVALID_UPLOAD
    }

    public enum VerificationStatus {
        VERIFIED,
        TAMPERED,
        RECORDED,
        PENDING
    }

    private Long logId;
    private String evidenceId;
    private ActionType action;
    private String investigatorName;
    private String result;
    private String prevHash;
    private String entryHash;
    private LocalDateTime timestamp;

    public AuditLog() {
        this.timestamp = LocalDateTime.now();
        this.prevHash = GENESIS_PREV_HASH;
    }

    public AuditLog(Long logId, String evidenceId, ActionType action, String investigatorName,
                    String result, String prevHash, LocalDateTime timestamp) {
        this.logId = logId;
        this.evidenceId = evidenceId;
        this.action = action;
        this.investigatorName = investigatorName;
        this.result = result;
        this.prevHash = (prevHash != null && !prevHash.isBlank()) ? prevHash : GENESIS_PREV_HASH;
        this.timestamp = timestamp != null ? timestamp : LocalDateTime.now();
        this.entryHash = computeEntryHash();
    }

    /**
     * Calculates the SHA-256 hash of this audit log entry using a fixed canonical
     * format with second-level timestamp precision:
     * canonicalString = evidenceId + "|" + action + "|" + investigatorName + "|" + result + "|" + prevHash + "|" + formattedTimestamp
     */
    public String computeEntryHash() {
        String formattedTs = timestamp != null ? timestamp.format(TIMESTAMP_FORMATTER) : "";
        String canonical = String.format("%s|%s|%s|%s|%s|%s",
                evidenceId != null ? evidenceId.trim() : "",
                action != null ? action.name() : "",
                investigatorName != null ? investigatorName.trim() : "",
                result != null ? result.trim() : "",
                prevHash != null ? prevHash.trim().toLowerCase() : GENESIS_PREV_HASH,
                formattedTs);

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(canonical.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) sb.append('0');
                sb.append(hex);
            }
            return sb.toString().toLowerCase();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm missing in JVM", e);
        }
    }

    // ========================================================================
    // GETTERS AND SETTERS
    // ========================================================================

    public Long getLogId() {
        return logId;
    }

    public void setLogId(Long logId) {
        this.logId = logId;
    }

    public String getEvidenceId() {
        return evidenceId;
    }

    public void setEvidenceId(String evidenceId) {
        this.evidenceId = evidenceId;
    }

    public ActionType getAction() {
        return action;
    }

    public void setAction(ActionType action) {
        this.action = action;
    }

    public String getInvestigatorName() {
        return investigatorName;
    }

    public void setInvestigatorName(String investigatorName) {
        this.investigatorName = investigatorName;
    }

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }

    public String getPrevHash() {
        return prevHash;
    }

    public void setPrevHash(String prevHash) {
        this.prevHash = prevHash;
    }

    public String getEntryHash() {
        return entryHash;
    }

    public void setEntryHash(String entryHash) {
        this.entryHash = entryHash;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
}
