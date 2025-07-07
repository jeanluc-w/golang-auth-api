CREATE OR REPLACE FUNCTION revoke_old_sessions()
RETURNS VOID AS $$
BEGIN
  UPDATE sessions
  SET revoked = TRUE
  WHERE revoked = FALSE
    AND created_at < now() - INTERVAL '30 days';
END;
$$ LANGUAGE plpgsql;
