CREATE OR REPLACE FUNCTION log_password_reset_used()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.used_at IS NOT NULL AND OLD.used_at IS NULL THEN
    INSERT INTO audit_logs (
      actor_id,
      target_user_id,
      action,
      reason,
      created_at
    ) VALUES (
      current_setting('app.actor_id', true)::UUID,
      NEW.user_id,
      'password_reset',
      'Password reset completed',
      now()
    );
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_password_reset_used
AFTER UPDATE ON password_resets
FOR EACH ROW
WHEN (OLD.used_at IS DISTINCT FROM NEW.used_at)
EXECUTE FUNCTION log_password_reset_used();
