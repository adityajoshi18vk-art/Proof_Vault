package com.proofvault;

import org.springframework.stereotype.Component;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * ============================================================================
 * FORENSIC CRYPTOGRAPHY IMPLEMENTATION: SHA-256 VERIFIER
 * ============================================================================
 * Implements EvidenceVerifier using Java's standard java.security.MessageDigest.
 *
 * Key Architectural Highlights:
 * 1. Java NIO & InputStream: Reads files via Files.newInputStream() wrapped in
 *    try-with-resources to guarantee safe release of operating system file handles.
 * 2. Memory-Safe Chunking: Reads streams using an 8KB byte buffer (byte[8192])
 *    so large digital evidence files (disk images, video recordings) do not exhaust
 *    heap memory.
 * 3. Immutable Evidence Principle: Operates purely in read-only mode on input streams;
 *    never mutates, overwrites, or locks evidence files.
 * 4. Hexadecimal Conversion: Converts the 32-byte (256-bit) digest array into a
 *    standard 64-character lowercase hex string with 2-digit zero-padding per byte.
 * 5. Robust Integrity Evaluation: Strictly returns "VERIFIED" or "TAMPERED".
 */
@Component
public class SHA256Verifier implements EvidenceVerifier {

    private static final String ALGORITHM = "SHA-256";
    private static final int BUFFER_SIZE = 8192; // 8 KB chunk size

    public static final String STATUS_VERIFIED = "VERIFIED";
    public static final String STATUS_TAMPERED = "TAMPERED";

    /**
     * Obtains a new instance of MessageDigest configured for SHA-256.
     * MessageDigest is stateful and not thread-safe, so a new instance is created
     * per hashing operation.
     */
    private MessageDigest getMessageDigest() {
        try {
            return MessageDigest.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithm '" + ALGORITHM + "' is unavailable in current JVM.", e);
        }
    }

    /**
     * Calculates the SHA-256 cryptographic digest of a file on disk.
     *
     * How it works:
     * - Uses Java NIO Files.newInputStream() to open a read-only stream.
     * - Try-with-resources ensures the InputStream is cleanly closed, preventing resource leaks.
     * - An 8KB byte buffer iteratively reads chunks from the file stream.
     * - digest.update(buffer, 0, bytesRead) feeds each chunk into the SHA-256 engine.
     * - digest.digest() performs final mathematical padding and returns a 32-byte hash.
     *
     * @param filePath Path to the evidence file on disk
     * @return 64-character lowercase hexadecimal hash string
     */
    @Override
    public String calculateHash(Path filePath) {
        if (filePath == null) {
            throw new IllegalArgumentException("Evidence file path cannot be null.");
        }

        if (!Files.exists(filePath)) {
            throw new IllegalArgumentException("Evidence file does not exist: " + filePath, new FileNotFoundException(filePath.toString()));
        }

        if (!Files.isRegularFile(filePath)) {
            throw new IllegalArgumentException("Evidence target is not a regular file: " + filePath);
        }

        if (!Files.isReadable(filePath)) {
            throw new SecurityException("Insufficient permissions to read evidence file: " + filePath);
        }

        MessageDigest digest = getMessageDigest();

        // Safe stream consumption via try-with-resources
        try (InputStream inputStream = Files.newInputStream(filePath)) {
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;

            // Stream chunks sequentially through MessageDigest without loading whole file
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }

            byte[] hashBytes = digest.digest();
            return bytesToHex(hashBytes);

        } catch (NoSuchFileException e) {
            throw new IllegalArgumentException("Evidence file disappeared or cannot be found: " + filePath, e);
        } catch (IOException e) {
            throw new RuntimeException("I/O failure while hashing evidence file: " + filePath, e);
        }
    }

    /**
     * Calculates the SHA-256 cryptographic digest from an in-memory byte array.
     *
     * @param fileData raw bytes of the file
     * @return 64-character lowercase hexadecimal hash string
     */
    @Override
    public String calculateHash(byte[] fileData) {
        if (fileData == null) {
            throw new IllegalArgumentException("File data cannot be null for hash calculation.");
        }

        MessageDigest digest = getMessageDigest();
        byte[] hashBytes = digest.digest(fileData);
        return bytesToHex(hashBytes);
    }

    /**
     * Audits file integrity against an expected baseline hash.
     *
     * Forensic Rule:
     * - Re-computes the candidate file's SHA-256 digest from disk.
     * - Compares the freshly computed hash with expected reference hash.
     * - Comparison is normalized (trimmed, lowercase) and case-insensitive.
     *
     * @param filePath Path to the file being audited
     * @param expectedHash Stored reference SHA-256 hash
     * @return "VERIFIED" if matching; "TAMPERED" if distinct or if expectedHash is invalid
     */
    @Override
    public String verifyIntegrity(Path filePath, String expectedHash) {
        if (expectedHash == null || expectedHash.isBlank()) {
            return STATUS_TAMPERED;
        }

        String calculatedHash = calculateHash(filePath);
        return calculatedHash.equalsIgnoreCase(expectedHash.trim()) ? STATUS_VERIFIED : STATUS_TAMPERED;
    }

    /**
     * Audits in-memory candidate bytes against an expected baseline hash.
     *
     * @param fileData candidate bytes
     * @param expectedHash Stored reference SHA-256 hash
     * @return "VERIFIED" if matching; "TAMPERED" if distinct or if expectedHash is invalid
     */
    @Override
    public String verifyIntegrity(byte[] fileData, String expectedHash) {
        if (fileData == null || expectedHash == null || expectedHash.isBlank()) {
            return STATUS_TAMPERED;
        }

        String calculatedHash = calculateHash(fileData);
        return calculatedHash.equalsIgnoreCase(expectedHash.trim()) ? STATUS_VERIFIED : STATUS_TAMPERED;
    }

    /**
     * Converts a 32-element byte array into a 64-character lowercase hexadecimal string.
     *
     * Technical Explanation:
     * 1. A SHA-256 digest outputs exactly 32 raw bytes (256 bits).
     * 2. In hexadecimal, each 8-bit byte represents two hex characters (00 to ff).
     * 3. (0xff & b) bitwise AND masks sign-extension, treating the signed Java byte
     *    as an unsigned integer (0-255).
     * 4. If the hex representation is a single digit (e.g. 0xa instead of 0x0a),
     *    we prepend '0' to ensure every byte occupies exactly two characters.
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString().toLowerCase();
    }
}
