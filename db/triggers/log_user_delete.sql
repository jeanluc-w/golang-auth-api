CREATE OR REPLACE FUNCTION log_user_delete()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO audit_logs (
    actor_id,
    target_user_id,
    target_username,
    target_email,
    action,
    reason,
    created_at
  ) VALUES (
    current_setting('app.actor_id', true)::UUID,
    OLD.id,
    OLD.username,
    OLD.email,
    'user_deleted',
    'User account deleted',
    now()
  );

  RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_user_delete_audit
BEFORE DELETE ON users
FOR EACH ROW
EXECUTE FUNCTION log_user_delete();
