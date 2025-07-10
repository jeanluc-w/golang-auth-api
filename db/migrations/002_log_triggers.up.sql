-- This trigger logs changes to the `auth_identities`table.
-- It captures changes to the `failed_attempts`, `lockout_until`, and `password_hash` fields.
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


-- This trigger logs changes to MFA factors.
-- It captures changes to the `verified` and `enabled` fields.
-- It logs the user ID, action, and changes made.
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


-- This trigger logs password reset usage.
-- It captures when a password reset is marked as used.
-- It logs the user ID, action, and reason for the reset.
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



-- This trigger logs user deletions.
-- It captures the user ID, username, email, and action performed.
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

-- This trigger logs user updates.
-- It captures changes to the user's email, status, and role. 
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
