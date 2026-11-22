package com.proofvault;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Rigorous forensics test suite testing SHA-256 calculation and verification:
 * 1. Two identical files yield identical hashes and return VERIFIED.
 * 2. Two distinct files yield different hashes and return TAMPERED.
 * 3. A file modified after generating its reference hash returns TAMPERED.
 * 4. Missing file and error scenarios throw expected exceptions.
 * 5. Files are never modified during the hashing procedure.
 */
class SHA256VerifierTest {

    private EvidenceVerifier verifier;

    @BeforeEach
    void setUp() {
        verifier = new SHA256Verifier();
    }

    @Test
    void testIdenticalFilesProduceSameHashAndVerify(@TempDir Path tempDir) throws IOException {
        // Scenario 1: Two identical files
        Path fileA = tempDir.resolve("original_contract.pdf");
        Path fileB = tempDir.resolve("backup_contract.pdf");

        String content = "CONFIDENTIAL CONTRACT EVIDENCE DATA - INVESTIGATION #9042";
        Files.writeString(fileA, content, StandardCharsets.UTF_8);
        Files.writeString(fileB, content, StandardCharsets.UTF_8);

        String hashA = verifier.calculateHash(fileA);
        String hashB = verifier.calculateHash(fileB);

        // Assert 64-char lowercase hex
        assertNotNull(hashA);
        assertEquals(64, hashA.length());
        assertEquals(hashA, hashA.toLowerCase());

        // Identical contents must yield exact same hash
        assertEquals(hashA, hashB);

        // Verification must return "VERIFIED"
        String result = verifier.verifyIntegrity(fileB, hashA);
        assertEquals(SHA256Verifier.STATUS_VERIFIED, result);
    }

    @Test
    void testDifferentFilesProduceDistinctHashesAndReturnTampered(@TempDir Path tempDir) throws IOException {
        // Scenario 2: Two files with different contents
        Path file1 = tempDir.resolve("doc_alpha.txt");
        Path file2 = tempDir.resolve("doc_beta.txt");

        Files.writeString(file1, "Audit log report alpha.", StandardCharsets.UTF_8);
        Files.writeString(file2, "Audit log report beta with alterations.", StandardCharsets.UTF_8);

        String hash1 = verifier.calculateHash(file1);
        String hash2 = verifier.calculateHash(file2);

        assertNotEquals(hash1, hash2);

        // Cross-verification against different file hash must return TAMPERED
        String result = verifier.verifyIntegrity(file2, hash1);
        assertEquals(SHA256Verifier.STATUS_TAMPERED, result);
    }

    @Test
    void testFileModifiedAfterOriginalHashReturnsTampered(@TempDir Path tempDir) throws IOException {
        // Scenario 3: File modified after reference hash generated
        Path evidenceFile = tempDir.resolve("evidence_payload.bin");

        // 1. Initial creation & registration
        byte[] originalBytes = new byte[]{0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
        Files.write(evidenceFile, originalBytes);

        String referenceHash = verifier.calculateHash(evidenceFile);
        assertNotNull(referenceHash);

        // Pre-tamper check should be VERIFIED
        assertEquals(SHA256Verifier.STATUS_VERIFIED, verifier.verifyIntegrity(evidenceFile, referenceHash));

        // 2. Tampering: A single byte is altered
        byte[] tamperedBytes = new byte[]{0x10, 0x20, 0x31, 0x40, 0x50, 0x60}; // 0x30 changed to 0x31
        Files.write(evidenceFile, tamperedBytes);

        // 3. Re-verification against original reference hash
        String resultAfterTampering = verifier.verifyIntegrity(evidenceFile, referenceHash);

        // Must strictly identify tampering
        assertEquals(SHA256Verifier.STATUS_TAMPERED, resultAfterTampering);
    }

    @Test
    void testOriginalFileNeverModifiedDuringHashing(@TempDir Path tempDir) throws IOException {
        Path evidenceFile = tempDir.resolve("immutable_evidence.dat");
        byte[] originalContent = "UNTOUCHED FORENSIC PAYLOAD".getBytes(StandardCharsets.UTF_8);
        Files.write(evidenceFile, originalContent);

        long originalLastModified = Files.getLastModifiedTime(evidenceFile).toMillis();

        // Calculate hash multiple times
        verifier.calculateHash(evidenceFile);
        verifier.calculateHash(evidenceFile);

        // Assert file byte contents remain 100% byte-for-byte identical
        byte[] readBack = Files.readAllBytes(evidenceFile);
        assertArrayEquals(originalContent, readBack);
    }

    @Test
    void testMissingFileThrowsException(@TempDir Path tempDir) {
        Path nonExistent = tempDir.resolve("ghost_file.txt");
        assertThrows(IllegalArgumentException.class, () -> verifier.calculateHash(nonExistent));
    }

    @Test
    void testBlankOrNullExpectedHashReturnsTampered(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("valid.txt");
        Files.writeString(file, "valid content", StandardCharsets.UTF_8);

        assertEquals(SHA256Verifier.STATUS_TAMPERED, verifier.verifyIntegrity(file, null));
        assertEquals(SHA256Verifier.STATUS_TAMPERED, verifier.verifyIntegrity(file, ""));
        assertEquals(SHA256Verifier.STATUS_TAMPERED, verifier.verifyIntegrity(file, "   "));
    }

    @Test
    void testLargeFileChunkingBuffer(@TempDir Path tempDir) throws IOException {
        // Create file larger than 8KB buffer (e.g. 32 KB)
        Path largeFile = tempDir.resolve("large_evidence.bin");
        byte[] data = new byte[32 * 1024];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i % 127);
        }
        Files.write(largeFile, data);

        String fileHash = verifier.calculateHash(largeFile);
        String arrayHash = verifier.calculateHash(data);

        assertEquals(fileHash, arrayHash);
        assertEquals(SHA256Verifier.STATUS_VERIFIED, verifier.verifyIntegrity(largeFile, fileHash));
    }
}
