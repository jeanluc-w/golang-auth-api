CREATE OR REPLACE FUNCTION log_user_update()
RETURNS TRIGGER AS $$
DECLARE
  changed JSONB := '{}';
BEGIN
  IF NEW.email IS DISTINCT FROM OLD.email THEN
    changed := jsonb_set(changed, '{email}', to_jsonb(ARRAY[OLD.email, NEW.email]));
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    changed := jsonb_set(changed, '{status}', to_jsonb(ARRAY[OLD.status::TEXT, NEW.status::TEXT]));
  END IF;

  IF NEW.role IS DISTINCT FROM OLD.role THEN
    changed := jsonb_set(changed, '{role}', to_jsonb(ARRAY[OLD.role::TEXT, NEW.role::TEXT]));
  END IF;

  IF changed != '{}' THEN
    INSERT INTO audit_logs (
      actor_id,
      target_user_id,
      target_username,
      target_email,
      action,
      changes,
      created_at
    ) VALUES (
      current_setting('app.actor_id', true)::UUID,
      NEW.id,
      NEW.username,
      NEW.email,
      'update_user',
      changed,
      now()
    );
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_user_update_audit
AFTER UPDATE ON users
FOR EACH ROW
WHEN (OLD.* IS DISTINCT FROM NEW.*)
EXECUTE FUNCTION log_user_update();
