CREATE OR REPLACE FUNCTION revoke_expired_sessions()
RETURNS VOID AS $$
BEGIN
  UPDATE sessions
  SET revoked = TRUE
  WHERE revoked = FALSE AND expires_at < now();
END;
$$ LANGUAGE plpgsql;
