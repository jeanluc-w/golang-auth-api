CREATE OR REPLACE FUNCTION remove_expired_password_resets()
RETURNS VOID AS $$
BEGIN
  DELETE FROM password_resets
  WHERE used_at IS NULL AND expires_at < now();
END;
$$ LANGUAGE plpgsql;



CREATE OR REPLACE FUNCTION remove_old_login_logs()
RETURNS VOID AS $$
BEGIN
  DELETE FROM logins
  WHERE created_at < now() - INTERVAL '90 days';
END;
$$ LANGUAGE plpgsql;



CREATE OR REPLACE FUNCTION remove_old_password_resets()
RETURNS VOID AS $$
BEGIN
  DELETE FROM password_resets
  WHERE id IN (
    SELECT id FROM (
      SELECT id,
             ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY created_at DESC) as rn
      FROM password_resets
    ) sub
    WHERE sub.rn > 5
  );
END;
$$ LANGUAGE plpgsql;



CREATE OR REPLACE FUNCTION remove_unverified_mfa_factors()
RETURNS VOID AS $$
BEGIN
  DELETE FROM mfa_factors
  WHERE verified = FALSE
    AND created_at < now() - INTERVAL '2 hours';
END;
$$ LANGUAGE plpgsql;



CREATE OR REPLACE FUNCTION revoke_expired_sessions()
RETURNS VOID AS $$
BEGIN
  UPDATE sessions
  SET revoked = TRUE
  WHERE revoked = FALSE AND expires_at < now();
END;
$$ LANGUAGE plpgsql;



CREATE OR REPLACE FUNCTION revoke_old_sessions()
RETURNS VOID AS $$
BEGIN
  UPDATE sessions
  SET revoked = TRUE
  WHERE revoked = FALSE
    AND created_at < now() - INTERVAL '30 days';
END;
$$ LANGUAGE plpgsql;



CREATE OR REPLACE FUNCTION revoke_all_other_sessions(_user_id UUID, _current_session_id UUID)
RETURNS VOID AS $$
BEGIN
  UPDATE sessions
  SET revoked = TRUE
  WHERE user_id = _user_id AND id != _current_session_id;
END;
$$ LANGUAGE plpgsql;
