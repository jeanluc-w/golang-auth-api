CREATE OR REPLACE FUNCTION remove_expired_password_resets()
RETURNS VOID AS $$
BEGIN
  DELETE FROM password_resets
  WHERE used_at IS NULL AND expires_at < now();
END;
$$ LANGUAGE plpgsql;
