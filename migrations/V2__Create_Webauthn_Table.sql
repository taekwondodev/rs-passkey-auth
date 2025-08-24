CREATE TABLE credentials (
    id BYTEA PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    passkey JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_credentials_user_id ON credentials(user_id);


CREATE OR REPLACE FUNCTION update_last_used()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_used_at = NOW;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_last_used
BEFORE UPDATE ON credentials
FOR EACH ROW
EXECUTE FUNCTION update_last_used();

CREATE TABLE webauthn_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    data JSONB NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('registration', 'login')),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX idx_webauthn_sessions_id_purpose ON webauthn_sessions(id, purpose);
