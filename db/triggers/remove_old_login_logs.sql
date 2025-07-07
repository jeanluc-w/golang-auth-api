CREATE OR REPLACE FUNCTION remove_old_login_logs()
RETURNS VOID AS $$
BEGIN
  DELETE FROM logins
  WHERE created_at < now() - INTERVAL '90 days';
END;
$$ LANGUAGE plpgsql;
