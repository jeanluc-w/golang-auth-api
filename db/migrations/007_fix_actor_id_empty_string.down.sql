-- Restores the pre-fix function bodies (bare ::UUID cast, no NULLIF) —
-- see 007_fix_actor_id_empty_string.up.sql for why that's buggy. This
-- exists only for migrate-down symmetry; there's no reason to actually run
-- it outside of reverting the whole migration.

CREATE OR REPLACE FUNCTION log_auth_identity_update()
RETURNS TRIGGER AS $$
DECLARE
  changed JSONB := '{}';
  user_rec RECORD;
BEGIN
  IF NEW.failed_attempts IS DISTINCT FROM OLD.failed_attempts THEN
    changed := jsonb_set(changed, '{failed_attempts}', to_jsonb(ARRAY[OLD.failed_attempts, NEW.failed_attempts]));
  END IF;

  IF NEW.locked_at IS DISTINCT FROM OLD.locked_at THEN
    changed := jsonb_set(changed, '{locked_at}', to_jsonb(ARRAY[OLD.locked_at, NEW.locked_at]));
  END IF;

  IF NEW.password_hash IS DISTINCT FROM OLD.password_hash THEN
    changed := jsonb_set(changed, '{password_hash}', to_jsonb(ARRAY['[REDACTED]', '[REDACTED]']));
  END IF;

  IF changed != '{}' THEN
    SELECT username, email INTO user_rec FROM users WHERE id = NEW.user_id;

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
      NEW.user_id,
      user_rec.username,
      user_rec.email,
      'password_reset',
      changed,
      now()
    );
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION log_mfa_factor_update()
RETURNS TRIGGER AS $$
DECLARE
  changed JSONB := '{}';
  user_rec RECORD;
BEGIN
  IF NEW.verified IS DISTINCT FROM OLD.verified THEN
    changed := jsonb_set(changed, '{verified}', to_jsonb(ARRAY[OLD.verified, NEW.verified]));
  END IF;

  IF NEW.enabled IS DISTINCT FROM OLD.enabled THEN
    changed := jsonb_set(changed, '{enabled}', to_jsonb(ARRAY[OLD.enabled, NEW.enabled]));
  END IF;

  IF changed != '{}' THEN
    SELECT username, email INTO user_rec FROM users WHERE id = NEW.user_id;

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
      NEW.user_id,
      user_rec.username,
      user_rec.email,
      'mfa_change',
      changed,
      now()
    );
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION log_password_reset_used()
RETURNS TRIGGER AS $$
DECLARE
  user_rec RECORD;
BEGIN
  IF NEW.used_at IS NOT NULL AND OLD.used_at IS NULL THEN
    SELECT username, email INTO user_rec FROM users WHERE id = NEW.user_id;

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
      NEW.user_id,
      user_rec.username,
      user_rec.email,
      'password_reset',
      'Password reset completed',
      now()
    );
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;


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
