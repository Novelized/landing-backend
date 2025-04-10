-- Create extension for encryption if not exists
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Create the email_signups table
CREATE TABLE IF NOT EXISTS email_signups (
    id SERIAL PRIMARY KEY,
    name BYTEA NOT NULL, -- Encrypted name
    email BYTEA NOT NULL, -- Encrypted email
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create a unique index on the encrypted email
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_signups_email ON email_signups (email);

-- Create function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger to automatically update the updated_at column
CREATE TRIGGER update_email_signups_updated_at
    BEFORE UPDATE ON email_signups
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create function to encrypt data
CREATE OR REPLACE FUNCTION encrypt_data(data TEXT, encryption_key TEXT)
RETURNS BYTEA AS $$
BEGIN
    RETURN pgp_sym_encrypt(data, encryption_key);
END;
$$ LANGUAGE plpgsql;

-- Create function to decrypt data
CREATE OR REPLACE FUNCTION decrypt_data(encrypted_data BYTEA, encryption_key TEXT)
RETURNS TEXT AS $$
BEGIN
    RETURN pgp_sym_decrypt(encrypted_data, encryption_key);
END;
$$ LANGUAGE plpgsql;

-- Create view for decrypted data (only accessible with proper permissions)
CREATE OR REPLACE VIEW email_signups_decrypted AS
SELECT 
    id,
    decrypt_data(name, current_setting('app.encryption_key')) as name,
    decrypt_data(email, current_setting('app.encryption_key')) as email,
    is_active,
    created_at,
    updated_at
FROM email_signups;

-- Set up row level security
ALTER TABLE email_signups ENABLE ROW LEVEL SECURITY;

-- Create policy to only allow access to active records
CREATE POLICY active_records_policy ON email_signups
    FOR ALL
    USING (is_active = true);

-- Create policy to allow access to all records for administrators
CREATE POLICY admin_access_policy ON email_signups
    FOR ALL
    USING (current_setting('app.is_admin') = 'true');

-- Comments for documentation
COMMENT ON TABLE email_signups IS 'Stores encrypted user signup information for Novelized platform';
COMMENT ON COLUMN email_signups.id IS 'Unique identifier for each signup';
COMMENT ON COLUMN email_signups.name IS 'Encrypted user name';
COMMENT ON COLUMN email_signups.email IS 'Encrypted user email';
COMMENT ON COLUMN email_signups.is_active IS 'Flag indicating if the signup is active';
COMMENT ON COLUMN email_signups.created_at IS 'Timestamp when the record was created';
COMMENT ON COLUMN email_signups.updated_at IS 'Timestamp when the record was last updated'; 