-- Initial schema. Portable types only: ids are UUIDv7 text, times are unix milliseconds, booleans are 0/1.

CREATE TABLE endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(64) NOT NULL,
    address VARCHAR(512) NOT NULL,
    enabled BIGINT NOT NULL,
    is_default BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    CONSTRAINT uk_endpoints_name UNIQUE (name)
);

CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(16) NOT NULL,
    enabled BIGINT NOT NULL,
    must_change_password BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    last_login_at BIGINT,
    CONSTRAINT uk_users_username UNIQUE (username)
);

CREATE TABLE sessions (
    id_hash VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    csrf_token VARCHAR(64) NOT NULL,
    created_at BIGINT NOT NULL,
    last_seen_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    ip VARCHAR(64),
    user_agent VARCHAR(255),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

CREATE TABLE api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label VARCHAR(100) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    prefix VARCHAR(16) NOT NULL,
    scopes VARCHAR(512) NOT NULL,
    endpoint_ids TEXT,
    path_roots TEXT,
    created_by VARCHAR(64),
    created_at BIGINT NOT NULL,
    expires_at BIGINT,
    revoked_at BIGINT,
    last_used_at BIGINT,
    CONSTRAINT uk_api_tokens_hash UNIQUE (token_hash)
);

CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at BIGINT NOT NULL,
    username VARCHAR(64),
    action VARCHAR(64) NOT NULL,
    outcome VARCHAR(64),
    details TEXT,
    job_id VARCHAR(36),
    transport VARCHAR(32),
    endpoint_id BIGINT,
    ip VARCHAR(64),
    user_agent VARCHAR(255)
);
CREATE INDEX idx_audit_at ON audit_events(at);
CREATE INDEX idx_audit_job ON audit_events(job_id);

CREATE TABLE scan_schedules (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    cron VARCHAR(128) NOT NULL,
    paths_json TEXT NOT NULL,
    exclusions_json TEXT NOT NULL,
    endpoint_id BIGINT,
    enabled BIGINT NOT NULL,
    window_start_min BIGINT,
    window_end_min BIGINT,
    max_streams BIGINT NOT NULL,
    eicar_check BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    last_run_at BIGINT,
    last_job_id VARCHAR(36),
    agent_id BIGINT,
    CONSTRAINT uk_scan_schedules_name UNIQUE (name),
    CONSTRAINT fk_schedules_endpoint FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE SET NULL
);

CREATE TABLE scan_jobs (
    id VARCHAR(36) PRIMARY KEY,
    kind VARCHAR(16) NOT NULL,
    status VARCHAR(16) NOT NULL,
    verdict VARCHAR(16),
    target TEXT NOT NULL,
    sha256 VARCHAR(64),
    size_bytes BIGINT,
    endpoint_id BIGINT,
    schedule_id VARCHAR(36),
    submitted_by VARCHAR(64),
    transport VARCHAR(32),
    submitted_at BIGINT NOT NULL,
    started_at BIGINT,
    finished_at BIGINT,
    files_scanned BIGINT NOT NULL,
    detections_json TEXT,
    error_code VARCHAR(32),
    error_message TEXT,
    errors_json TEXT,
    quarantine_path TEXT,
    agent_id BIGINT,
    CONSTRAINT fk_jobs_endpoint FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE SET NULL,
    CONSTRAINT fk_jobs_schedule FOREIGN KEY (schedule_id) REFERENCES scan_schedules(id) ON DELETE SET NULL
);
CREATE INDEX idx_jobs_submitted ON scan_jobs(submitted_at);
CREATE INDEX idx_jobs_status ON scan_jobs(status);
CREATE INDEX idx_jobs_schedule ON scan_jobs(schedule_id);
CREATE INDEX idx_jobs_agent ON scan_jobs(agent_id, status);

CREATE TABLE watched_directories (
    id VARCHAR(36) PRIMARY KEY,
    path TEXT NOT NULL,
    endpoint_id BIGINT,
    enabled BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    CONSTRAINT fk_watch_endpoint FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE SET NULL
);

CREATE TABLE processed_files (
    path_sha256 VARCHAR(64) PRIMARY KEY,
    path TEXT NOT NULL,
    modified_ms BIGINT NOT NULL,
    size_bytes BIGINT NOT NULL,
    verdict VARCHAR(16) NOT NULL,
    processed_at BIGINT NOT NULL
);

CREATE TABLE external_identities (
    principal_name VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    source VARCHAR(8) NOT NULL,
    issuer VARCHAR(512) NOT NULL,
    subject VARCHAR(512) NOT NULL,
    first_seen_at BIGINT NOT NULL,
    last_seen_at BIGINT NOT NULL,
    CONSTRAINT fk_identity_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE auth_provider_settings (
    provider VARCHAR(16) PRIMARY KEY,
    settings_json TEXT NOT NULL,
    encrypted_secret TEXT,
    updated_at BIGINT NOT NULL,
    updated_by VARCHAR(255) NOT NULL
);

CREATE TABLE settings (
    name VARCHAR(128) PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at BIGINT NOT NULL,
    updated_by VARCHAR(255)
);

CREATE TABLE agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(64) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    prefix VARCHAR(16) NOT NULL,
    enabled BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    created_by VARCHAR(255),
    last_seen_at BIGINT,
    last_ip VARCHAR(64),
    version VARCHAR(64),
    clamd_version VARCHAR(255),
    roots_json TEXT,
    slots BIGINT NOT NULL,
    online BIGINT NOT NULL,
    CONSTRAINT uk_agents_name UNIQUE (name),
    CONSTRAINT uk_agents_token UNIQUE (token_hash)
);

CREATE TABLE user_totp (
    user_id VARCHAR(36) PRIMARY KEY,
    secret VARCHAR(255) NOT NULL,
    last_step BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    CONSTRAINT fk_totp_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE recovery_codes (
    user_id VARCHAR(36) NOT NULL,
    code_hash VARCHAR(64) NOT NULL,
    used_at BIGINT,
    PRIMARY KEY (user_id, code_hash),
    CONSTRAINT fk_recovery_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE mfa_pending (
    id_hash VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    transport VARCHAR(16) NOT NULL,
    attempts BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    CONSTRAINT fk_mfa_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_mfa_expires ON mfa_pending(expires_at);

CREATE TABLE passkeys (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    cred_id VARCHAR(512) NOT NULL,
    name VARCHAR(64) NOT NULL,
    public_key TEXT NOT NULL,
    sign_count BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    last_used_at BIGINT,
    CONSTRAINT uk_passkeys_cred UNIQUE (cred_id),
    CONSTRAINT fk_passkeys_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_passkeys_user ON passkeys(user_id);

CREATE TABLE webauthn_challenges (
    id_hash VARCHAR(64) PRIMARY KEY,
    purpose VARCHAR(16) NOT NULL,
    user_id VARCHAR(36),
    challenge VARCHAR(64) NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE TABLE detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id VARCHAR(36) NOT NULL,
    found_at BIGINT NOT NULL,
    path TEXT NOT NULL,
    signature VARCHAR(255) NOT NULL,
    kind VARCHAR(16) NOT NULL,
    endpoint_id BIGINT,
    agent_id BIGINT,
    CONSTRAINT fk_detections_job FOREIGN KEY (job_id) REFERENCES scan_jobs(id) ON DELETE CASCADE
);
CREATE INDEX idx_detections_found ON detections(found_at);
CREATE INDEX idx_detections_sig ON detections(signature, found_at);
CREATE INDEX idx_detections_job ON detections(job_id);
CREATE INDEX idx_jobs_verdict ON scan_jobs(verdict, submitted_at);
CREATE INDEX idx_jobs_kind ON scan_jobs(kind, status);
CREATE INDEX idx_processed_at ON processed_files(processed_at);

CREATE TABLE canaries (
    id VARCHAR(36) PRIMARY KEY,
    agent_id BIGINT,
    path TEXT NOT NULL,
    create_file BIGINT NOT NULL,
    armed BIGINT,
    checked_at BIGINT,
    last_tripped_at BIGINT,
    created_at BIGINT NOT NULL,
    created_by VARCHAR(255),
    CONSTRAINT fk_canaries_agent FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
);
CREATE INDEX idx_canaries_agent ON canaries(agent_id);
