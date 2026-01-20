-- Create API Keys table for programmatic access
CREATE TABLE api_keys
(
    id             BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id        BIGINT        NOT NULL,
    key_hash       VARCHAR(255)  NOT NULL UNIQUE,
    key_prefix     VARCHAR(20)   NOT NULL UNIQUE,
    name           VARCHAR(100)  NOT NULL,
    description    TEXT,
    is_active      BOOLEAN       NOT NULL DEFAULT TRUE,
    last_used_at   DATETIME,
    created_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at     DATETIME,
    revoked_at     DATETIME,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    INDEX idx_api_keys_user_id (user_id),
    INDEX idx_api_keys_key_prefix (key_prefix),
    INDEX idx_api_keys_is_active (is_active),
    INDEX idx_api_keys_created_at (created_at)
);
