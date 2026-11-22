package com.proofvault;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the hash-chained audit log integrity system.
 *
 * Tests verify:
 * 1. Genesis entry uses the 64-zero prevHash constant.
 * 2. Each subsequent entry's prevHash equals the preceding entry's entryHash.
 * 3. The chain correctly links N entries in sequence.
 * 4. Altering any field (action, result, investigator, evidenceId) produces a
 *    different entryHash — confirming tamper detection.
 * 5. Genesis hash is consistently 64 lowercase hex characters.
 */
class AuditLogChainTest {

    /**
     * Test 1: First audit log entry must reference the genesis hash (64 zeros).
     */
    @Test
    void testGenesisEntryHasZeroPrevHash() {
        AuditLog genesis = new AuditLog(
                1L, "EV-TEST-001",
                AuditLog.ActionType.EVIDENCE_REGISTER,
                "Agent Zero", "Registered successfully.",
                null, // null prevHash → should default to GENESIS_PREV_HASH
                LocalDateTime.of(2026, 1, 1, 10, 0, 0)
        );

        assertEquals(AuditLog.GENESIS_PREV_HASH, genesis.getPrevHash(),
                "Genesis entry must reference the 64-zero constant as prevHash.");
        assertEquals(64, AuditLog.GENESIS_PREV_HASH.length(),
                "Genesis constant must be exactly 64 hex characters.");
        assertEquals(AuditLog.GENESIS_PREV_HASH, AuditLog.GENESIS_PREV_HASH.toLowerCase(),
                "Genesis constant must be lowercase.");
    }

    /**
     * Test 2: Entry hash must be a valid 64-character lowercase hex string.
     */
    @Test
    void testEntryHashIsValid64CharHex() {
        AuditLog log = new AuditLog(
                1L, "EV-TEST-002",
                AuditLog.ActionType.INTEGRITY_CHECK,
                "Agent Alpha", "PASSED: Bitstream intact.",
                null,
                LocalDateTime.of(2026, 6, 15, 12, 30, 0)
        );

        String hash = log.getEntryHash();
        assertNotNull(hash, "Entry hash must not be null.");
        assertEquals(64, hash.length(), "SHA-256 hex must be exactly 64 characters.");
        assertTrue(hash.matches("[0-9a-f]{64}"), "Entry hash must be lowercase hexadecimal.");
    }

    /**
     * Test 3: Chain linkage — log2.prevHash must equal log1.entryHash.
     */
    @Test
    void testChainLinkageIsCorrect() {
        LocalDateTime t1 = LocalDateTime.of(2026, 3, 10, 9, 0, 0);
        AuditLog log1 = new AuditLog(1L, "EV-CHAIN-001",
                AuditLog.ActionType.EVIDENCE_REGISTER,
                "Agent Vance", "SHA-256 Calculated.",
                null, t1
        );

        LocalDateTime t2 = LocalDateTime.of(2026, 3, 10, 9, 5, 0);
        AuditLog log2 = new AuditLog(2L, "EV-CHAIN-001",
                AuditLog.ActionType.INTEGRITY_CHECK,
                "Agent Vance", "PASSED: Bitstream intact.",
                log1.getEntryHash(), t2
        );

        assertEquals(log1.getEntryHash(), log2.getPrevHash(),
                "log2.prevHash must exactly equal log1.entryHash to form a valid chain link.");
        assertNotEquals(log1.getEntryHash(), log2.getEntryHash(),
                "Two different entries must produce distinct entry hashes.");
    }

    /**
     * Test 4: Three-entry chain — all links verified sequentially.
     */
    @Test
    void testThreeEntryChainIsIntact() {
        LocalDateTime base = LocalDateTime.of(2026, 5, 20, 8, 0, 0);
        AuditLog log1 = new AuditLog(1L, "EV-MULTI-001",
                AuditLog.ActionType.EVIDENCE_REGISTER, "Forensics Team",
                "Registered.", null, base);

        AuditLog log2 = new AuditLog(2L, "EV-MULTI-001",
                AuditLog.ActionType.INTEGRITY_CHECK, "Forensics Team",
                "PASSED: Bitstream intact.", log1.getEntryHash(), base.plusMinutes(5));

        AuditLog log3 = new AuditLog(3L, "EV-MULTI-002",
                AuditLog.ActionType.EVIDENCE_REGISTER, "Forensics Team",
                "Registered.", log2.getEntryHash(), base.plusMinutes(10));

        // Chain: genesis → log1 → log2 → log3
        assertEquals(AuditLog.GENESIS_PREV_HASH, log1.getPrevHash(), "log1 must anchor to genesis.");
        assertEquals(log1.getEntryHash(), log2.getPrevHash(), "log2 must link to log1.");
        assertEquals(log2.getEntryHash(), log3.getPrevHash(), "log3 must link to log2.");
    }

    /**
     * Test 5: Altering the result field must produce a different entry hash
     * (tamper detection).
     */
    @Test
    void testAlteredFieldProducesDifferentHash() {
        LocalDateTime ts = LocalDateTime.of(2026, 8, 1, 14, 0, 0);

        AuditLog original = new AuditLog(1L, "EV-TAMPER-001",
                AuditLog.ActionType.INTEGRITY_CHECK,
                "Agent K", "PASSED: Bitstream intact.",
                null, ts
        );

        // Simulate a tampered row: same fields, but result changed
        AuditLog tampered = new AuditLog(1L, "EV-TAMPER-001",
                AuditLog.ActionType.INTEGRITY_CHECK,
                "Agent K", "PASSED: Everything is fine. Trust me.",
                null, ts
        );

        assertNotEquals(original.getEntryHash(), tampered.getEntryHash(),
                "Any change to any field must produce a different entry hash.");
    }

    /**
     * Test 6: Altering the investigator name must produce a different hash.
     */
    @Test
    void testAlteredInvestigatorProducesDifferentHash() {
        LocalDateTime ts = LocalDateTime.of(2026, 9, 15, 11, 30, 0);

        AuditLog original = new AuditLog(1L, "EV-INVTEST-001",
                AuditLog.ActionType.EVIDENCE_REGISTER,
                "Agent Smith", "Registered.",
                null, ts
        );

        AuditLog modified = new AuditLog(1L, "EV-INVTEST-001",
                AuditLog.ActionType.EVIDENCE_REGISTER,
                "Agent Jones", // different investigator
                "Registered.",
                null, ts
        );

        assertNotEquals(original.getEntryHash(), modified.getEntryHash(),
                "Changing investigator name must change the entry hash.");
    }

    /**
     * Test 7: computeEntryHash() must produce the same value on repeated calls
     * (deterministic hashing).
     */
    @Test
    void testComputeEntryHashIsDeterministic() {
        AuditLog log = new AuditLog(1L, "EV-DET-001",
                AuditLog.ActionType.EVIDENCE_REGISTER,
                "Agent Vance", "Registered.",
                null, LocalDateTime.of(2026, 10, 10, 10, 10, 10)
        );

        String hash1 = log.computeEntryHash();
        String hash2 = log.computeEntryHash();
        String hash3 = log.computeEntryHash();

        assertEquals(hash1, hash2, "computeEntryHash() must be deterministic.");
        assertEquals(hash2, hash3, "computeEntryHash() must be deterministic.");
    }
}
