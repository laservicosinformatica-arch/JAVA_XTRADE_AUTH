CREATE TABLE IF NOT EXISTS auth_security_policy (
    id BIGINT NOT NULL AUTO_INCREMENT,
    access_token_ttl_minutes INT NOT NULL DEFAULT 30,
    max_failed_login_attempts INT NOT NULL DEFAULT 5,
    lock_duration_minutes INT NOT NULL DEFAULT 30,
    password_expiration_days INT NOT NULL DEFAULT 90,
    minimum_password_length INT NOT NULL DEFAULT 10,
    require_uppercase BOOLEAN NOT NULL DEFAULT TRUE,
    require_lowercase BOOLEAN NOT NULL DEFAULT TRUE,
    require_number BOOLEAN NOT NULL DEFAULT TRUE,
    require_special_character BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id)
);

INSERT INTO auth_security_policy (
    access_token_ttl_minutes,
    max_failed_login_attempts,
    lock_duration_minutes,
    password_expiration_days,
    minimum_password_length,
    require_uppercase,
    require_lowercase,
    require_number,
    require_special_character
)
SELECT 30, 5, 30, 90, 10, TRUE, TRUE, TRUE, TRUE
WHERE NOT EXISTS (SELECT 1 FROM auth_security_policy);

ALTER TABLE app_users
    ADD COLUMN failed_login_attempts INT NOT NULL DEFAULT 0,
    ADD COLUMN locked_at TIMESTAMP(6) NULL,
    ADD COLUMN password_changed_at TIMESTAMP(6) NULL;

UPDATE app_users
SET password_changed_at = COALESCE(password_changed_at, created_at)
WHERE id > 0;
