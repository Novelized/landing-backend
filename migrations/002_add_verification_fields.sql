-- Add verification fields to email_signups table
ALTER TABLE email_signups
ADD COLUMN verification_token BYTEA,
ADD COLUMN is_verified BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN verification_sent_at TIMESTAMP WITH TIME ZONE,
ADD COLUMN verified_at TIMESTAMP WITH TIME ZONE;

-- Create index on verification token for faster lookups
CREATE INDEX IF NOT EXISTS idx_email_signups_verification_token ON email_signups (verification_token);

-- Drop the existing view
DROP VIEW IF EXISTS email_signups_decrypted;

-- Recreate the view with all fields
CREATE VIEW email_signups_decrypted AS
SELECT 
    id,
    decrypt_data(name, current_setting('app.encryption_key')) as name,
    decrypt_data(email, current_setting('app.encryption_key')) as email,
    is_active,
    is_verified,
    decrypt_data(verification_token, current_setting('app.encryption_key')) as verification_token,
    verification_sent_at,
    verified_at,
    created_at,
    updated_at
FROM email_signups;

-- Add comments for the new columns
COMMENT ON COLUMN email_signups.verification_token IS 'Encrypted token used for email verification';
COMMENT ON COLUMN email_signups.is_verified IS 'Flag indicating if the email has been verified';
COMMENT ON COLUMN email_signups.verification_sent_at IS 'Timestamp when the verification email was sent';
COMMENT ON COLUMN email_signups.verified_at IS 'Timestamp when the email was verified'; 