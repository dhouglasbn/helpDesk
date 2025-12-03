CREATE TRIGGER ensure_tech_user_trigger
BEFORE INSERT OR UPDATE ON technician_availability
FOR EACH ROW
EXECUTE FUNCTION ensure_tech_user();