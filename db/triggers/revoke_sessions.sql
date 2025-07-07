CREATE OR REPLACE FUNCTION revoke_all_other_sessions(_user_id UUID, _current_session_id UUID)
RETURNS VOID AS $$
BEGIN
  UPDATE sessions
  SET revoked = TRUE
  WHERE user_id = _user_id AND id != _current_session_id;
END;
$$ LANGUAGE plpgsql;
