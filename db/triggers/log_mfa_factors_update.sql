CREATE OR REPLACE FUNCTION log_mfa_factor_update()
RETURNS TRIGGER AS $$
DECLARE
  changed JSONB := '{}';
BEGIN
  IF NEW.verified IS DISTINCT FROM OLD.verified THEN
    changed := jsonb_set(changed, '{verified}', to_jsonb(ARRAY[OLD.verified, NEW.verified]));
  END IF;

  IF NEW.enabled IS DISTINCT FROM OLD.enabled THEN
    changed := jsonb_set(changed, '{enabled}', to_jsonb(ARRAY[OLD.enabled, NEW.enabled]));
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
      'mfa_change',
      changed,
      now()
    );
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_mfa_factor_update_audit
AFTER UPDATE ON mfa_factors
FOR EACH ROW
WHEN (OLD.* IS DISTINCT FROM NEW.*)
EXECUTE FUNCTION log_mfa_factor_update();
