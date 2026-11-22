# ProofVault

A Java Spring Boot application for registering and verifying digital evidence using SHA-256 cryptographic hashing. Each uploaded file receives a deterministic fingerprint stored in MySQL; re-verification at any later point detects even a single-bit modification.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Language | Java 17 |
| Framework | Spring Boot 3.2.5 |
| Build | Maven 3.9.6 |
| Frontend | HTML5 / CSS3 / Vanilla JavaScript |
| Database | MySQL 8.0 via JDBC (JdbcTemplate) |
| Hashing | SHA-256 via `java.security.MessageDigest` |
| Templates | Thymeleaf |

---

## Java Concepts Demonstrated

| Concept | Location |
|---|---|
| Abstract class | `Evidence.java` |
| Inheritance | `DocumentEvidence.java`, `ImageEvidence.java` |
| Interface | `EvidenceVerifier.java` |
| Encapsulation | All model classes (private fields, getters/setters) |
| Method overriding | `getEvidenceType()` in subclasses |
| Runtime polymorphism | Evidence references at registration time |
| Collections: ArrayList | `getAllEvidence()` in `EvidenceController.java` |
| Collections: HashMap | `getEvidenceById()` in `EvidenceController.java` |
| ExecutorService | Background SHA-256 hashing thread pool |
| LocalDateTime | All timestamps in evidence and audit records |
| Enums | `AuditLog.ActionType`, `AuditLog.VerificationStatus` |
| Hash-chained audit log | `AuditLog.java` + `recordAuditEntry()` |

---

## Prerequisites

- JDK 17 or later
- Maven 3.9+ — installed at `C:\Users\user\AppData\Local\Programs\apache-maven-3.9.6\bin`
- MySQL 8.0 running on `localhost:3306`

---

## MySQL Setup

```sql
CREATE DATABASE IF NOT EXISTS proofvault_db;
USE proofvault_db;

CREATE TABLE evidence (
    evidence_id      VARCHAR(50)  PRIMARY KEY,
    file_name        VARCHAR(255) NOT NULL,
    file_path        TEXT         NOT NULL,
    file_type        VARCHAR(50),
    file_size        BIGINT,
    sha256_hash      VARCHAR(64)  NOT NULL,
    investigator_name VARCHAR(255),
    registration_time DATETIME
);

CREATE TABLE audit_logs (
    log_id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    evidence_id       VARCHAR(50),
    action            VARCHAR(50),
    investigator_name VARCHAR(255),
    result            TEXT,
    prev_hash         VARCHAR(64),
    entry_hash        VARCHAR(64),
    timestamp         DATETIME
);
```

---

## Configuration

Edit `src/main/resources/application.properties`:

```properties
spring.datasource.url=jdbc:mysql://localhost:3306/proofvault_db?useSSL=false&serverTimezone=UTC
spring.datasource.username=root
spring.datasource.password=YOUR_PASSWORD
```

> **Security note:** Do not commit your database password to source control.  
> Externalize it via an environment variable instead:
> ```
> spring.datasource.password=${SPRING_DATASOURCE_PASSWORD}
> ```
> Then set `SPRING_DATASOURCE_PASSWORD=yourpassword` in your OS environment before running.

---

## Running

```powershell
# Add Maven to PATH (if not already in system PATH)
$env:PATH = "C:\Users\user\AppData\Local\Programs\apache-maven-3.9.6\bin;" + $env:PATH

cd "d:\Java Project\ProofVault"
mvn spring-boot:run
```

Open `http://localhost:8080` in a browser.

Evidence files are stored in `vault_storage/` inside the project directory.  
This directory is **not** web-accessible (outside `src/main/resources/static/`).

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/evidence/register` | Upload a file, generate SHA-256, store metadata |
| `POST` | `/api/evidence/verify/{evidenceId}` | Re-hash a file and compare against stored digest |
| `GET` | `/api/evidence` | List all registered evidence |
| `GET` | `/api/evidence/{evidenceId}` | Fetch a single evidence record |
| `GET` | `/api/audit` | Retrieve full audit trail |
| `GET` | `/api/audit/verify` | Verify hash-chain integrity of audit log |

### Register Evidence

```
POST /api/evidence/register
Content-Type: multipart/form-data

file         – The evidence file (required)
investigator – Investigator name or ID (required)
category     – DOCUMENT | IMAGE | STORAGE_DUMP | NETWORK_LOG (required)
notes        – Optional case notes
```

**Allowed file types:** `.pdf`, `.docx`, `.doc`, `.txt`, `.rtf`, `.png`, `.jpg`, `.jpeg`, `.tiff`, `.tif`, `.bmp`, `.pcap`, `.pcapng`, `.dmp`, `.log`, `.csv`, `.xml`, `.json`  
**Max file size:** 50 MB

### Verify Integrity

```
POST /api/evidence/verify/{evidenceId}
Content-Type: multipart/form-data

file – The candidate file to verify against the stored hash
```

Returns `VERIFIED` if SHA-256 matches, `TAMPERED` if it does not.

---

## Running Tests

```powershell
mvn clean test
```

**17 tests across 3 test classes — all passing:**

| Test Class | Tests | Coverage |
|---|---|---|
| `SHA256VerifierTest` | 7 | Identical files, different files, modification detection, immutability, missing file, null hash, large file chunking |
| `ProofVaultOOPTest` | 3 | Inheritance/polymorphism, byte[] hashing, audit chain linkage |
| `AuditLogChainTest` | 7 | Genesis hash, 64-char hex format, chain linkage, 3-entry chain, field-change tamper detection, determinism |

---

## Security Notes

- **File paths** are stored in MySQL but never returned to the browser in API responses.
- **Uploaded files** are stored in `vault_storage/` with a unique evidence-ID prefix; original filenames cannot overwrite existing vault files.
- **Path traversal** is prevented via `Paths.get(rawFileName).getFileName().toString()` before constructing the destination path.
- **SQL injection** is prevented by using `JdbcTemplate` with prepared statements throughout.
- **Uploaded files are never executed.** The backend streams them to disk and reads them in chunks for hashing only.
- **File type validation** rejects extensions outside the allowed whitelist at the controller level.
- Externalize `spring.datasource.password` via environment variable for any non-development deployment.

---

## Audit Log Hash Chain

Each entry in `audit_logs` cryptographically links to the previous one:

```
canonical = evidenceId | action | investigatorName | result | prevHash | timestamp
entryHash = SHA-256(canonical)
```

- The first entry uses `prevHash = "0000...0000"` (64 zeros — the genesis block).
- Every subsequent entry uses the preceding row's `entry_hash` as its `prev_hash`.
- `GET /api/audit/verify` traverses the entire chain and reports `INTACT` or `BROKEN` with the exact log ID where tampering was detected.

---

## Project Structure

```
ProofVault/
  src/main/java/com/proofvault/
    ProofVaultApplication.java   – Spring Boot entry point
    Evidence.java                – Abstract base class
    DocumentEvidence.java        – Extends Evidence (DOCUMENT type)
    ImageEvidence.java           – Extends Evidence (IMAGE type)
    EvidenceVerifier.java        – Interface: calculateHash(), verifyIntegrity()
    SHA256Verifier.java          – Implements EvidenceVerifier with MessageDigest
    AuditLog.java                – Audit entry model with hash-chain logic
    EvidenceController.java      – REST API, JdbcTemplate, ExecutorService
  src/main/resources/
    static/style.css             – Dark forensics dashboard CSS
    static/script.js             – Vanilla JS fetch-based frontend
    templates/index.html         – Thymeleaf HTML dashboard
    application.properties       – Server, DB, and upload config
  src/test/java/com/proofvault/
    SHA256VerifierTest.java      – 7 SHA-256 hashing tests
    ProofVaultOOPTest.java       – 3 OOP and audit chain tests
    AuditLogChainTest.java       – 7 hash-chain integrity tests
  vault_storage/                 – Evidence files stored here (gitignore this)
  pom.xml
  README.md
```

---

## Known Limitations

- Single-user; no authentication or role-based access control.
- Evidence records cannot be deleted through the UI (by design — immutable vault).
- `vault_storage/` grows unbounded; no automatic cleanup.
- Verification requires manually providing both the Evidence ID and the original file — there is no automatic re-fetch from vault storage (intentional: the candidate file must come from the verifier's own custody).
