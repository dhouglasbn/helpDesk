CREATE OR REPLACE FUNCTION ensure_ticket_roles()
RETURNS trigger AS $$
BEGIN
  PERFORM 1 FROM users WHERE id = NEW.client_id AND role = 'client';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'client_id must be a user with role=client';
  END IF;

  PERFORM 1 FROM users WHERE id = NEW.tech_id AND role = 'tech';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tech_id must be a user with role=tech';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER ensure_ticket_roles_trigger
BEFORE INSERT OR UPDATE ON tickets
FOR EACH ROW
EXECUTE FUNCTION ensure_ticket_roles();