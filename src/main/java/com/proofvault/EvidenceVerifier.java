package com.proofvault;

import java.nio.file.Path;

/**
 * ============================================================================
 * JAVA OOP CONCEPT: INTERFACE CONTRACT FOR FORENSIC HASH VERIFICATION
 * ============================================================================
 * Declares methods to calculate SHA-256 digests and audit evidence integrity.
 */
public interface EvidenceVerifier {

    /**
     * Calculates the cryptographic hash from a file on disk.
     *
     * @param filePath Path to the target evidence file
     * @return 64-character lowercase hexadecimal hash string
     */
    String calculateHash(Path filePath);

    /**
     * Overloaded method to calculate cryptographic hash from an in-memory byte array.
     *
     * @param fileData raw bytes of the evidence file
     * @return 64-character lowercase hexadecimal hash string
     */
    String calculateHash(byte[] fileData);

    /**
     * Verifies candidate file integrity against an expected reference hash.
     *
     * @param filePath Path to the candidate file to audit
     * @param expectedHash Original cryptographic fingerprint stored in the vault
     * @return "VERIFIED" if hashes match identically; "TAMPERED" if modified
     */
    String verifyIntegrity(Path filePath, String expectedHash);

    /**
     * Verifies candidate byte data integrity against an expected reference hash.
     *
     * @param fileData candidate file bytes
     * @param expectedHash Original cryptographic fingerprint stored in the vault
     * @return "VERIFIED" if hashes match identically; "TAMPERED" if modified
     */
    String verifyIntegrity(byte[] fileData, String expectedHash);
}
