CREATE OR REPLACE FUNCTION prevent_admin_deletion()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.role = 'admin' THEN
    RAISE EXCEPTION 'Cannot delete an admin user.';
  END IF;
  RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_prevent_admin_deletion
BEFORE DELETE ON users
FOR EACH ROW
EXECUTE FUNCTION prevent_admin_deletion();



CREATE OR REPLACE FUNCTION prevent_admin_demotion()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.role = 'admin' AND NEW.role != 'admin' THEN
    RAISE EXCEPTION 'Cannot change role from admin to %', NEW.role;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_prevent_admin_demotion
BEFORE UPDATE ON users
FOR EACH ROW
WHEN (OLD.role = 'admin' AND NEW.role IS DISTINCT FROM OLD.role)
EXECUTE FUNCTION prevent_admin_demotion();



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
