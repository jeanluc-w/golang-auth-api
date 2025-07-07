CREATE OR REPLACE FUNCTION prevent_multiple_totp_mfa()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.type = 'totp' THEN
    IF EXISTS (
      SELECT 1 FROM mfa_factors
      WHERE user_id = NEW.user_id AND type = 'totp' AND id != NEW.id
    ) THEN
      RAISE EXCEPTION 'Only one TOTP MFA factor is allowed per user';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_prevent_multiple_totp
BEFORE INSERT OR UPDATE ON mfa_factors
FOR EACH ROW
EXECUTE FUNCTION prevent_multiple_totp_mfa();
