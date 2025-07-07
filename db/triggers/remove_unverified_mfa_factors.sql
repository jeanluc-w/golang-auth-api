CREATE OR REPLACE FUNCTION remove_unverified_mfa_factors()
RETURNS VOID AS $$
BEGIN
  DELETE FROM mfa_factors
  WHERE verified = FALSE
    AND created_at < now() - INTERVAL '2 hours';
END;
$$ LANGUAGE plpgsql;
