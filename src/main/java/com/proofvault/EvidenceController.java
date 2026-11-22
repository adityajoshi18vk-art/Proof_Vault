package com.proofvault;

import jakarta.annotation.PreDestroy;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/**
 * ============================================================================
 * PROOFVAULT EVIDENCE & AUDIT CONTROLLER
 * ============================================================================
 * Enhanced with:
 * 1. Java Collections Framework:
 *    - ArrayList: Maintains ordered evidence records retrieved from MySQL.
 *    - HashMap: Provides O(1) in-memory fast-lookup index by Evidence ID.
 * 2. Multithreading with ExecutorService:
 *    - Offloads CPU-intensive file SHA-256 chunked hashing to background threads.
 *    - Uses CompletableFuture/Callable to keep request execution non-blocking and safe.
 *    - Cleanly shuts down via @PreDestroy hook upon application termination.
 * 3. Enums:
 *    - Strongly typed AuditLog.ActionType & AuditLog.VerificationStatus.
 * 4. Java Date & Time API:
 *    - Standardized on LocalDateTime.
 * 5. Tamper-Evident Hash-Chained Audit Logging:
 *    - Cryptographically links each audit record to the preceding entry.
 *    - Verifiable endpoint /api/audit/verify to audit chain integrity.
 */
@Controller
public class EvidenceController {

    private final EvidenceVerifier verifier;
    private final JdbcTemplate jdbcTemplate;

    // Dedicated local storage directory for actual evidence files (never inside MySQL)
    private final Path storageDirectory = Paths.get(System.getProperty("user.dir"), "vault_storage");

    /**
     * MULTITHREADING: Thread pool dedicated to background file cryptographic hashing.
     * Uses a bounded thread pool sized appropriately to available CPU cores.
     */
    private final ExecutorService hashingExecutor = Executors.newFixedThreadPool(
            Math.max(2, Runtime.getRuntime().availableProcessors()),
            new ThreadFactory() {
                private int counter = 0;
                @Override
                public Thread newThread(Runnable r) {
                    Thread t = new Thread(r, "proofvault-hasher-" + (++counter));
                    t.setDaemon(true); // Does not prevent JVM shutdown
                    return t;
                }
            }
    );

    public EvidenceController(EvidenceVerifier verifier, JdbcTemplate jdbcTemplate) {
        this.verifier = verifier;
        this.jdbcTemplate = jdbcTemplate;
        initStorageDirectory();
    }

    private void initStorageDirectory() {
        try {
            if (!Files.exists(storageDirectory)) {
                Files.createDirectories(storageDirectory);
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to initialize vault storage directory: " + storageDirectory, e);
        }
    }

    /**
     * MULTITHREADING LIFECYCLE: Graceful shutdown of ExecutorService on application exit.
     */
    @PreDestroy
    public void cleanup() {
        System.out.println("Shutting down ProofVault Hashing ExecutorService...");
        hashingExecutor.shutdown();
        try {
            if (!hashingExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                hashingExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            hashingExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    // ========================================================================
    // 1. WEB UI ROUTING
    // ========================================================================

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("title", "ProofVault - Digital Forensics & Evidence Integrity");
        model.addAttribute("status", "System Ready");
        return "index";
    }

    // ========================================================================
    // 2. REST API ENDPOINTS
    // ========================================================================

    /**
     * POST /api/evidence/register
     * MULTITHREADED REGISTRATION:
     * - Validates input parameters (logs INVALID_UPLOAD on bad requests).
     * - Writes candidate file safely to local disk.
     * - Dispatches SHA-256 chunked calculation to ExecutorService background worker.
     * - Inserts evidence into MySQL and appends to hash-chained audit log.
     */
    @PostMapping(value = "/api/evidence/register", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @ResponseBody
    public ResponseEntity<?> registerEvidence(
            @RequestParam(value = "file", required = false) MultipartFile file,
            @RequestParam(value = "investigator", required = false) String investigator,
            @RequestParam(value = "category", required = false) String category,
            @RequestParam(value = "notes", required = false) String notes) {

        // Allowed file extensions whitelist (lowercase comparison)
        final Set<String> ALLOWED_EXTENSIONS = new HashSet<>(Arrays.asList(
                ".pdf", ".docx", ".doc", ".txt", ".rtf",
                ".png", ".jpg", ".jpeg", ".tiff", ".tif", ".bmp",
                ".pcap", ".pcapng", ".dmp", ".log", ".csv", ".xml", ".json"
        ));

        // Validate upload attempt
        if (file == null || file.isEmpty()) {
            recordAuditEntry("N/A", AuditLog.ActionType.INVALID_UPLOAD,
                    investigator != null ? investigator : "Unknown", "Rejected: Empty or missing file.");
            return ResponseEntity.badRequest().body(Map.of("error", "An evidence file must be provided."));
        }

        // Validate file size explicitly (50 MB max)
        if (file.getSize() > 50L * 1024 * 1024) {
            recordAuditEntry("N/A", AuditLog.ActionType.INVALID_UPLOAD,
                    investigator != null ? investigator.trim() : "Unknown",
                    "Rejected: File exceeds 50 MB limit (" + file.getSize() + " bytes).");
            return ResponseEntity.badRequest().body(Map.of("error", "File is too large. Maximum allowed size is 50 MB."));
        }

        // Validate file extension against whitelist
        String rawNameCheck = file.getOriginalFilename();
        if (rawNameCheck != null && !rawNameCheck.isBlank()) {
            String lowerName = rawNameCheck.toLowerCase();
            String ext = lowerName.contains(".") ? lowerName.substring(lowerName.lastIndexOf('.')) : "";
            if (!ALLOWED_EXTENSIONS.contains(ext)) {
                recordAuditEntry("N/A", AuditLog.ActionType.INVALID_UPLOAD,
                        investigator != null ? investigator.trim() : "Unknown",
                        "Rejected: File type '" + ext + "' is not permitted.");
                return ResponseEntity.badRequest().body(Map.of(
                        "error", "File type '" + ext + "' is not allowed. Accepted: PDF, DOCX, TXT, PNG, JPG, TIFF, PCAP, DMP, LOG, CSV, XML, JSON."
                ));
            }
        }

        if (investigator == null || investigator.trim().isEmpty()) {
            recordAuditEntry("N/A", AuditLog.ActionType.INVALID_UPLOAD,
                    "Unknown", "Rejected: Missing investigator identity.");
            return ResponseEntity.badRequest().body(Map.of("error", "Investigator name/ID is required."));
        }

        if (category == null || category.trim().isEmpty()) {
            recordAuditEntry("N/A", AuditLog.ActionType.INVALID_UPLOAD,
                    investigator.trim(), "Rejected: Missing evidence category.");
            return ResponseEntity.badRequest().body(Map.of("error", "Evidence category is required."));
        }

        try {
            // Generate unique forensic evidence ID
            String evidenceId = "EV-" + LocalDateTime.now().getYear() + "-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();

            // Sanitize original file name
            String rawFileName = file.getOriginalFilename();
            String originalFileName = (rawFileName != null && !rawFileName.isBlank())
                    ? Paths.get(rawFileName).getFileName().toString()
                    : "artifact.dat";

            String safeStorageName = evidenceId + "_" + originalFileName;
            Path destination = storageDirectory.resolve(safeStorageName).normalize();

            if (Files.exists(destination)) {
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body(Map.of("error", "Evidence file with destination already exists: " + safeStorageName));
            }

            // Stream file to local vault disk (NEVER inside MySQL)
            try (InputStream in = file.getInputStream()) {
                Files.copy(in, destination, StandardCopyOption.REPLACE_EXISTING);
            }

            // MULTITHREADING: Execute SHA-256 chunked calculation asynchronously on ExecutorService
            Callable<String> hashingTask = () -> verifier.calculateHash(destination);
            Future<String> futureHash = hashingExecutor.submit(hashingTask);

            // Wait for background worker completion (handles execution exceptions)
            String calculatedHash = futureHash.get(60, TimeUnit.SECONDS);

            long fileSize = Files.size(destination);
            LocalDateTime now = LocalDateTime.now();
            String normCategory = category.trim().toUpperCase();

            // Insert evidence metadata into MySQL (database remains permanent source of truth)
            String insertEvidenceSql = "INSERT INTO evidence (evidence_id, file_name, file_path, file_type, file_size, sha256_hash, investigator_name, registration_time) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

            jdbcTemplate.update(insertEvidenceSql,
                    evidenceId,
                    originalFileName,
                    destination.toString(),
                    normCategory,
                    fileSize,
                    calculatedHash,
                    investigator.trim(),
                    Timestamp.valueOf(now)
            );

            // Add hash-chained audit log entry into MySQL
            recordAuditEntry(
                    evidenceId,
                    AuditLog.ActionType.EVIDENCE_REGISTER,
                    investigator.trim(),
                    "SHA-256 Calculated: " + calculatedHash.substring(0, 16) + "..."
            );

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("evidenceId", evidenceId);
            response.put("fileName", originalFileName);
            response.put("category", normCategory);
            response.put("sha256Hash", calculatedHash);
            response.put("investigator", investigator.trim());
            response.put("registrationTime", now.toString());
            response.put("fileSize", fileSize);
            response.put("message", "Evidence persisted in MySQL and anchored with SHA-256 via background thread.");

            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (TimeoutException e) {
            return ResponseEntity.status(HttpStatus.REQUEST_TIMEOUT)
                    .body(Map.of("error", "Hashing operation timed out in background thread."));
        } catch (InterruptedException | ExecutionException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Background hashing thread failed: " + e.getMessage()));
        } catch (DataAccessException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Database error: " + (e.getRootCause() != null ? e.getRootCause().getMessage() : e.getMessage())));
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Disk I/O error: " + e.getMessage()));
        }
    }

    /**
     * POST /api/evidence/verify/{evidenceId}
     * MULTITHREADED VERIFICATION:
     * - Recalculates candidate file's SHA-256 on background ExecutorService thread.
     * - Queries MySQL for reference hash.
     * - Records SUCCESSFUL_VERIFICATION, FAILED_VERIFICATION, or MISSING_EVIDENCE into hash chain.
     */
    @PostMapping(value = "/api/evidence/verify/{evidenceId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @ResponseBody
    public ResponseEntity<?> verifyEvidence(
            @PathVariable("evidenceId") String evidenceId,
            @RequestParam(value = "file", required = false) MultipartFile file) {

        if (evidenceId == null || evidenceId.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Evidence ID is required."));
        }

        if (file == null || file.isEmpty()) {
            recordAuditEntry(evidenceId.trim(), AuditLog.ActionType.INVALID_UPLOAD, "System Audit", "Verification rejected: Empty candidate file.");
            return ResponseEntity.badRequest().body(Map.of("error", "Candidate file must be provided."));
        }

        try {
            // Retrieve stored record from MySQL using prepared statement (accepts Evidence ID or reference SHA-256 Hash)
            String selectSql = "SELECT * FROM evidence WHERE evidence_id = ? OR sha256_hash = ?";
            List<Map<String, Object>> rows = jdbcTemplate.queryForList(selectSql, evidenceId.trim(), evidenceId.trim());

            if (rows.isEmpty()) {
                // Record MISSING EVIDENCE in audit log
                recordAuditEntry(evidenceId.trim(), AuditLog.ActionType.EVIDENCE_MISSING, "System Audit", "Lookup failed: Evidence ID or SHA-256 hash not found in database.");
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("error", "Evidence record not found in database with ID or Hash: " + evidenceId));
            }

            Map<String, Object> record = rows.get(0);
            String storedVaultHash = (String) record.get("sha256_hash");
            String fileName = (String) record.get("file_name");
            String actualEvidenceId = (String) record.get("evidence_id");

            // Write temporary file for chunked stream hashing
            Path tempCandidate = Files.createTempFile("proofvault_verify_", ".tmp");
            try (InputStream in = file.getInputStream()) {
                Files.copy(in, tempCandidate, StandardCopyOption.REPLACE_EXISTING);
            }

            // MULTITHREADING: Run candidate file hashing in background thread
            Future<String> futureHash = hashingExecutor.submit(() -> {
                try {
                    return verifier.calculateHash(tempCandidate);
                } finally {
                    Files.deleteIfExists(tempCandidate);
                }
            });

            String candidateHash = futureHash.get(60, TimeUnit.SECONDS);

            // Compare hashes
            boolean isMatch = storedVaultHash != null && storedVaultHash.equalsIgnoreCase(candidateHash.trim());
            AuditLog.VerificationStatus status = isMatch ? AuditLog.VerificationStatus.VERIFIED : AuditLog.VerificationStatus.TAMPERED;
            LocalDateTime now = LocalDateTime.now();

            // Record verification result in hash-chained audit log
            String logResult = isMatch ? "PASSED: Bitstream intact" : "FAILED: Checksum mismatch (Tamper Alert)";
            recordAuditEntry(actualEvidenceId != null ? actualEvidenceId : evidenceId.trim(), AuditLog.ActionType.INTEGRITY_CHECK, "System Audit", logResult);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("evidenceId", actualEvidenceId != null ? actualEvidenceId : evidenceId.trim());
            result.put("fileName", fileName);
            result.put("status", status.name());
            result.put("vaultHash", storedVaultHash);
            result.put("candidateHash", candidateHash);
            result.put("timestamp", now.toString());

            return ResponseEntity.ok(result);

        } catch (TimeoutException e) {
            return ResponseEntity.status(HttpStatus.REQUEST_TIMEOUT)
                    .body(Map.of("error", "Verification hashing timed out."));
        } catch (InterruptedException | ExecutionException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Verification hashing failed: " + e.getMessage()));
        } catch (DataAccessException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Database error: " + (e.getRootCause() != null ? e.getRootCause().getMessage() : e.getMessage())));
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "I/O error during verification: " + e.getMessage()));
        }
    }

    /**
     * GET /api/evidence
     * COLLECTIONS FRAMEWORK:
     * - Uses ArrayList<Map<String, Object>> to collect records ordered from MySQL.
     * - Uses collection iteration to populate metadata.
     */
    @GetMapping("/api/evidence")
    @ResponseBody
    public ResponseEntity<?> getAllEvidence() {
        try {
            String sql = "SELECT * FROM evidence ORDER BY registration_time DESC";
            List<Map<String, Object>> evidenceList = jdbcTemplate.query(sql, new EvidenceRowMapper());

            // Collections Framework: ArrayList maintained from query
            ArrayList<Map<String, Object>> resultList = new ArrayList<>(evidenceList);

            return ResponseEntity.ok(resultList);
        } catch (DataAccessException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Database error: " + (e.getRootCause() != null ? e.getRootCause().getMessage() : e.getMessage())));
        }
    }

    /**
     * GET /api/evidence/{evidenceId}
     * COLLECTIONS FRAMEWORK:
     * - Queries records from MySQL.
     * - Builds an in-memory HashMap<String, Map<String, Object>> for fast indexed retrieval.
     */
    @GetMapping("/api/evidence/{evidenceId}")
    @ResponseBody
    public ResponseEntity<?> getEvidenceById(@PathVariable("evidenceId") String evidenceId) {
        if (evidenceId == null || evidenceId.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Evidence ID is required."));
        }

        try {
            String sql = "SELECT * FROM evidence";
            List<Map<String, Object>> allEvidence = jdbcTemplate.query(sql, new EvidenceRowMapper());

            // Collections Framework: Index evidence records into a HashMap for O(1) lookup by ID or Hash
            Map<String, Map<String, Object>> evidenceIndex = new HashMap<>();
            for (Map<String, Object> item : allEvidence) {
                String id = (String) item.get("evidenceId");
                String hash = (String) item.get("sha256Hash");
                if (id != null) {
                    evidenceIndex.put(id, item);
                    evidenceIndex.put(id.toLowerCase(), item);
                }
                if (hash != null) {
                    evidenceIndex.put(hash, item);
                    evidenceIndex.put(hash.toLowerCase(), item);
                }
            }

            Map<String, Object> match = evidenceIndex.get(evidenceId.trim());
            if (match == null) {
                match = evidenceIndex.get(evidenceId.trim().toLowerCase());
            }
            if (match == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(Map.of("error", "Evidence record not found with ID or Hash: " + evidenceId));
            }

            return ResponseEntity.ok(match);
        } catch (DataAccessException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Database error: " + (e.getRootCause() != null ? e.getRootCause().getMessage() : e.getMessage())));
        }
    }

    /**
     * GET /api/audit
     * Retrieves all audit trail logs from MySQL in descending chronological order.
     */
    @GetMapping("/api/audit")
    @ResponseBody
    public ResponseEntity<?> getAuditLogs() {
        try {
            String sql = "SELECT * FROM audit_logs ORDER BY log_id DESC";
            List<AuditLog> logs = jdbcTemplate.query(sql, new AuditLogRowMapper());
            return ResponseEntity.ok(logs);
        } catch (DataAccessException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Database error: " + (e.getRootCause() != null ? e.getRootCause().getMessage() : e.getMessage())));
        }
    }

    /**
     * GET /api/audit/verify
     * HASH-CHAINED AUDIT AUDITOR:
     * - Traverses the entire audit log sequence from Genesis (first entry) forward.
     * - Verifies that:
     *   1. The first entry links to the genesis block (64 zeros).
     *   2. Each entry's computed hash matches its recorded entry_hash.
     *   3. Each subsequent entry's prev_hash exactly equals the preceding entry's entry_hash.
     * - Pinpoints the exact Log ID where tampering occurred if broken.
     */
    @GetMapping("/api/audit/verify")
    @ResponseBody
    public ResponseEntity<?> verifyAuditChain() {
        try {
            String sql = "SELECT * FROM audit_logs ORDER BY log_id ASC";
            List<AuditLog> chain = jdbcTemplate.query(sql, new AuditLogRowMapper());

            if (chain.isEmpty()) {
                return ResponseEntity.ok(Map.of(
                        "chainStatus", "EMPTY",
                        "totalEntries", 0,
                        "message", "Audit trail is empty. No entries to verify."
                ));
            }

            String expectedPrevHash = AuditLog.GENESIS_PREV_HASH;
            for (int i = 0; i < chain.size(); i++) {
                AuditLog entry = chain.get(i);

                // Check 1: Previous hash linkage
                if (!entry.getPrevHash().equalsIgnoreCase(expectedPrevHash)) {
                    Map<String, Object> err = new LinkedHashMap<>();
                    err.put("chainStatus", "BROKEN");
                    err.put("tamperedLogId", entry.getLogId());
                    err.put("reason", "Broken previous hash pointer in chain.");
                    err.put("recordedPrevHash", entry.getPrevHash());
                    err.put("expectedPrevHash", expectedPrevHash);
                    return ResponseEntity.status(HttpStatus.CONFLICT).body(err);
                }

                // Check 2: Entry re-computed hash validation
                String recomputedHash = entry.computeEntryHash();
                if (!recomputedHash.equalsIgnoreCase(entry.getEntryHash())) {
                    Map<String, Object> err = new LinkedHashMap<>();
                    err.put("chainStatus", "BROKEN");
                    err.put("tamperedLogId", entry.getLogId());
                    err.put("reason", "Entry contents were altered after logging (hash mismatch).");
                    err.put("recordedEntryHash", entry.getEntryHash());
                    err.put("recomputedHash", recomputedHash);
                    return ResponseEntity.status(HttpStatus.CONFLICT).body(err);
                }

                expectedPrevHash = entry.getEntryHash();
            }

            return ResponseEntity.ok(Map.of(
                    "chainStatus", "INTACT",
                    "totalEntries", chain.size(),
                    "latestHash", expectedPrevHash,
                    "message", "Audit log chain verified intact. All cryptographic linkages are unbroken."
            ));

        } catch (DataAccessException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Database error during chain audit: " + (e.getRootCause() != null ? e.getRootCause().getMessage() : e.getMessage())));
        }
    }

    // ========================================================================
    // 3. HASH-CHAINED AUDIT HELPER METHOD
    // ========================================================================

    /**
     * Appends an audit entry to MySQL linking cryptographically to the most recent entry.
     */
    private synchronized void recordAuditEntry(String evidenceId, AuditLog.ActionType action,
                                               String investigator, String result) {
        try {
            // Find the most recent entry_hash from MySQL
            String lastHashSql = "SELECT entry_hash FROM audit_logs ORDER BY log_id DESC LIMIT 1";
            List<String> lastHashes = jdbcTemplate.query(lastHashSql, (rs, rowNum) -> rs.getString("entry_hash"));

            String prevHash = (lastHashes.isEmpty() || lastHashes.get(0) == null || lastHashes.get(0).isBlank())
                    ? AuditLog.GENESIS_PREV_HASH
                    : lastHashes.get(0);

            LocalDateTime now = LocalDateTime.now().withNano(0);
            AuditLog newLog = new AuditLog(null, evidenceId, action, investigator, result, prevHash, now);

            String insertSql = "INSERT INTO audit_logs (evidence_id, action, investigator_name, result, prev_hash, entry_hash, timestamp) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?)";

            jdbcTemplate.update(insertSql,
                    newLog.getEvidenceId(),
                    newLog.getAction().name(),
                    newLog.getInvestigatorName(),
                    newLog.getResult(),
                    newLog.getPrevHash(),
                    newLog.getEntryHash(),
                    Timestamp.valueOf(now)
            );
        } catch (Exception e) {
            System.err.println("Failed to write audit log to MySQL: " + e.getMessage());
        }
    }

    // ========================================================================
    // 4. JDBC ROW MAPPERS
    // ========================================================================

    private class EvidenceRowMapper implements RowMapper<Map<String, Object>> {
        @Override
        public Map<String, Object> mapRow(ResultSet rs, int rowNum) throws SQLException {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("evidenceId", rs.getString("evidence_id"));
            map.put("fileName", rs.getString("file_name"));
            // NOTE: filePath is intentionally NOT returned to the client to avoid exposing server directory structure.
            map.put("category", rs.getString("file_type"));
            map.put("fileType", rs.getString("file_type"));
            long size = rs.getLong("file_size");
            map.put("fileSizeBytes", size);
            map.put("fileSizeFormatted", formatFileSize(size));
            map.put("sha256Hash", rs.getString("sha256_hash"));
            map.put("investigator", rs.getString("investigator_name"));

            Timestamp ts = rs.getTimestamp("registration_time");
            map.put("registrationTime", ts != null ? ts.toLocalDateTime().toString() : "");
            return map;
        }
    }

    private class AuditLogRowMapper implements RowMapper<AuditLog> {
        @Override
        public AuditLog mapRow(ResultSet rs, int rowNum) throws SQLException {
            AuditLog log = new AuditLog();
            log.setLogId(rs.getLong("log_id"));
            log.setEvidenceId(rs.getString("evidence_id"));

            String actionStr = rs.getString("action");
            try {
                log.setAction(AuditLog.ActionType.valueOf(actionStr));
            } catch (Exception e) {
                log.setAction(AuditLog.ActionType.INTEGRITY_CHECK);
            }

            log.setInvestigatorName(rs.getString("investigator_name"));
            log.setResult(rs.getString("result"));
            log.setPrevHash(rs.getString("prev_hash"));
            log.setEntryHash(rs.getString("entry_hash"));

            Timestamp ts = rs.getTimestamp("timestamp");
            if (ts != null) {
                log.setTimestamp(ts.toLocalDateTime());
            }
            return log;
        }
    }

    private String formatFileSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        int exp = (int) (Math.log(bytes) / Math.log(1024));
        char pre = "KMGTPE".charAt(exp - 1);
        return String.format(Locale.US, "%.1f %sB", bytes / Math.pow(1024, exp), pre);
    }
}
