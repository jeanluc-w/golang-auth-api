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
