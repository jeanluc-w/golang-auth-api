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
