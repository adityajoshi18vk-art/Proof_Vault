package com.proofvault;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit test validating OOP design, inheritance, polymorphism, and SHA-256 verification.
 */
class ProofVaultOOPTest {

    @Test
    void testInheritanceAndPolymorphism() {
        Evidence doc = new DocumentEvidence(
                "EV-DOC-001", "warrant.pdf", "/vault/warrant.pdf",
                "application/pdf", "hash123", "Agent Smith", LocalDateTime.now()
        );

        Evidence img = new ImageEvidence(
                "EV-IMG-001", "scene.png", "/vault/scene.png",
                "image/png", "hash456", "Agent Vance", LocalDateTime.now()
        );

        assertEquals("DOCUMENT", doc.getEvidenceType());
        assertEquals("IMAGE", img.getEvidenceType());
        assertEquals("warrant.pdf", doc.getFileName());
        assertEquals("scene.png", img.getFileName());
    }

    @Test
    void testSHA256VerifierBytes() {
        EvidenceVerifier verifier = new SHA256Verifier();

        byte[] sample = "ProofVault Test Content".getBytes(StandardCharsets.UTF_8);
        String hash = verifier.calculateHash(sample);

        assertNotNull(hash);
        assertEquals(64, hash.length());
        assertEquals(SHA256Verifier.STATUS_VERIFIED, verifier.verifyIntegrity(sample, hash));
        assertEquals(SHA256Verifier.STATUS_TAMPERED, verifier.verifyIntegrity("Tampered Content".getBytes(StandardCharsets.UTF_8), hash));
    }

    @Test
    void testAuditLogHashChainLinkage() {
        AuditLog log1 = new AuditLog(1L, "EV-001", AuditLog.ActionType.EVIDENCE_REGISTER, "Agent Vance", "PASSED", null, LocalDateTime.now());
        assertEquals(AuditLog.GENESIS_PREV_HASH, log1.getPrevHash());
        assertNotNull(log1.getEntryHash());
        assertEquals(64, log1.getEntryHash().length());

        AuditLog log2 = new AuditLog(2L, "EV-001", AuditLog.ActionType.INTEGRITY_CHECK, "Agent Vance", "PASSED", log1.getEntryHash(), LocalDateTime.now());
        assertEquals(log1.getEntryHash(), log2.getPrevHash());
        assertNotNull(log2.getEntryHash());
        assertNotEquals(log1.getEntryHash(), log2.getEntryHash());
    }
}
