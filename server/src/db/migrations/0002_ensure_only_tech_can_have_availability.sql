CREATE OR REPLACE FUNCTION ensure_tech_user()
RETURNS trigger AS $$
BEGIN
  PERFORM 1 FROM users WHERE id = NEW.user_id AND role = 'tech';
  
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Only users with role=tech can have availability records';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;