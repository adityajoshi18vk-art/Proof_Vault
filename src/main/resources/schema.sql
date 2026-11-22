CREATE TABLE IF NOT EXISTS evidence (
    evidence_id VARCHAR(64) PRIMARY KEY,
    file_name VARCHAR(255) NOT NULL,
    file_path VARCHAR(512) NOT NULL,
    file_type VARCHAR(64) NOT NULL,
    file_size BIGINT NOT NULL,
    sha256_hash CHAR(64) NOT NULL,
    investigator_name VARCHAR(128) NOT NULL,
    registration_time DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    log_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    evidence_id VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    investigator_name VARCHAR(128) NOT NULL,
    result VARCHAR(255) NOT NULL,
    prev_hash CHAR(64) NOT NULL,
    entry_hash CHAR(64) NOT NULL,
    timestamp DATETIME NOT NULL
);
