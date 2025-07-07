CREATE OR REPLACE FUNCTION log_auth_identity_update()
RETURNS TRIGGER AS $$
DECLARE
  changed JSONB := '{}';
BEGIN
  IF NEW.failed_attempts IS DISTINCT FROM OLD.failed_attempts THEN
    changed := jsonb_set(changed, '{failed_attempts}', to_jsonb(ARRAY[OLD.failed_attempts, NEW.failed_attempts]));
  END IF;

  IF NEW.lockout_until IS DISTINCT FROM OLD.lockout_until THEN
    changed := jsonb_set(changed, '{lockout_until}', to_jsonb(ARRAY[OLD.lockout_until, NEW.lockout_until]));
  END IF;

  IF NEW.password_hash IS DISTINCT FROM OLD.password_hash THEN
    changed := jsonb_set(changed, '{password_hash}', to_jsonb(ARRAY['[REDACTED]', '[REDACTED]']));
  END IF;

  IF changed != '{}' THEN
    INSERT INTO audit_logs (
      actor_id,
      target_user_id,
      action,
      changes,
      created_at
    ) VALUES (
      current_setting('app.actor_id', true)::UUID,
      NEW.user_id,
      'password_reset',
      changed,
      now()
    );
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_auth_identity_update_audit
AFTER UPDATE ON auth_identities
FOR EACH ROW
WHEN (OLD.* IS DISTINCT FROM NEW.*)
EXECUTE FUNCTION log_auth_identity_update();
