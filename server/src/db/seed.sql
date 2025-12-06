INSERT INTO users (id, name, email, password_hash, role)
VALUES (
  '8dfceb80-199c-488f-8918-a0609175399c',
  'Administrador',
  'administrador@admin.com',
  '$2b$10$049vvxbTsOW3IiqoEVUKM.4.au3WCHO5I24MxCZw3GzBwadPHf8WO',
  'admin'
) ON CONFLICT (id) DO NOTHING;

INSERT INTO services (id, title, price, active) VALUES
  ('4878508a-2fd4-4005-8418-83fce08c0e50', 'Instalação e atualização de softwares', 100.0, true),
  ('2f72feca-f0c9-4b09-ab63-f2b3af3d8950', 'Instalação e atualização de hardwares', 150.0, true),
  ('08bc85dc-e13f-472d-a156-4d6cc026934e', 'Diagnóstico e remoção de vírus', 120.0, true),
  ('099cb99d-7a79-44cd-832f-9d8e4729a06b', 'Suporte a impressoras', 80.0, true),
  ('33807cc5-731e-4bf4-888c-d56a27745ef5', 'Suporte a periféricos', 60.0, true)
  ON CONFLICT (id) DO NOTHING;

INSERT INTO users (id, name, email, password_hash, role, picture) VALUES
  ('b9f0f153-4bc2-4576-9a8f-7b78762b2b37', 'Técnico 1', 'tecnico1@tech.com', '$2b$10$m.C.STCN2JBQIFJH/XOxaetUw.2.cAGnB9rnS6PHsTdBUpWtty9Ke', 'tech', 'foto1.jpg'),
  ('8717d531-97de-43f5-a1dd-e1bdcc20140d', 'Técnico 2', 'tecnico2@tech.com', '$2b$10$Ae8yqNB7DDJUpoeyNdK67ekBFtdsDUF7PBWVJEvv/fiRrpwm5tU7m', 'tech', 'foto2.jpg'),
  ('a290e17b-d0a3-4b36-b3dd-75a3e810be7b', 'Técnico 3', 'tecnico3@tech.com', '$2b$10$NsnNWhGVUzApTi/vGEwTWOLaT0phxHmh.WUbkYXnVn.MZL9dF4YOm', 'tech', 'foto3.jpg')
  ON CONFLICT (id) DO NOTHING;

INSERT INTO technician_availability (id, user_id, time) VALUES
  ('ade4320d-2ac9-48ff-8ff5-b0490d31227f', 'b9f0f153-4bc2-4576-9a8f-7b78762b2b37', '08:00'),
  ('22bd31c3-7c19-41b0-95a6-569e993a01b5', 'b9f0f153-4bc2-4576-9a8f-7b78762b2b37', '09:00'),
  ('0607fc71-298e-4ca9-8747-36bbeb3dfb72', 'b9f0f153-4bc2-4576-9a8f-7b78762b2b37', '10:00'),
  ('3071910f-b184-4c01-95f8-a0b4c8007b9a', 'b9f0f153-4bc2-4576-9a8f-7b78762b2b37', '11:00'),
  ('299bd763-84d4-4322-a77e-7781c690c7a4', 'b9f0f153-4bc2-4576-9a8f-7b78762b2b37', '14:00'),
  ('efdf84da-6ca9-457d-94b8-4ca2348d7620', 'b9f0f153-4bc2-4576-9a8f-7b78762b2b37', '15:00'),
  ('847f356c-56ac-48ca-89ec-8b13b6a5d472', 'b9f0f153-4bc2-4576-9a8f-7b78762b2b37', '16:00'),
  ('eeced3f7-8819-4d18-94ed-dc195ba7a564', 'b9f0f153-4bc2-4576-9a8f-7b78762b2b37', '17:00'),

  ('22b18079-e352-4edb-a77d-5e35c0887168', '8717d531-97de-43f5-a1dd-e1bdcc20140d', '10:00'),
  ('85c37037-b943-4741-b68f-4a1d17809f42', '8717d531-97de-43f5-a1dd-e1bdcc20140d', '11:00'),
  ('84bc6d05-3c0a-4641-8dda-86269a6e6b5b', '8717d531-97de-43f5-a1dd-e1bdcc20140d', '12:00'),
  ('101b4fea-96c3-4314-934b-67b70fc68417', '8717d531-97de-43f5-a1dd-e1bdcc20140d', '13:00'),
  ('788715d4-2af4-4422-8d1a-cc46a6e5f969', '8717d531-97de-43f5-a1dd-e1bdcc20140d', '16:00'),
  ('0742801c-2c2b-4f00-826f-14b1e3a65e09', '8717d531-97de-43f5-a1dd-e1bdcc20140d', '17:00'),
  ('7277dcb0-9c20-4c8b-9e90-d43b288f5e46', '8717d531-97de-43f5-a1dd-e1bdcc20140d', '18:00'),
  ('1e88f508-7736-4b51-b22c-5d29e0aad7dd', '8717d531-97de-43f5-a1dd-e1bdcc20140d', '19:00'),

  ('9612912e-b0d9-4d6d-a807-afadd6e12158', 'a290e17b-d0a3-4b36-b3dd-75a3e810be7b', '12:00'),
  ('03b56041-3946-4470-a15a-81064e4ce210', 'a290e17b-d0a3-4b36-b3dd-75a3e810be7b', '13:00'),
  ('7655a098-edb6-46c6-8172-7423eca19aa9', 'a290e17b-d0a3-4b36-b3dd-75a3e810be7b', '14:00'),
  ('f4a3111c-5844-4f1b-93ab-54c327626b6d', 'a290e17b-d0a3-4b36-b3dd-75a3e810be7b', '15:00'),
  ('3fac8f4d-0393-4fc4-bc99-9d0468475df6', 'a290e17b-d0a3-4b36-b3dd-75a3e810be7b', '18:00'),
  ('75975360-3126-4eaa-9de7-03d9c1dc83cf', 'a290e17b-d0a3-4b36-b3dd-75a3e810be7b', '19:00'),
  ('44f452a7-8772-4010-a44f-26bc95d1c057', 'a290e17b-d0a3-4b36-b3dd-75a3e810be7b', '20:00'),
  ('4ac530f0-5076-450e-9dcc-3b0f49f54ff1', 'a290e17b-d0a3-4b36-b3dd-75a3e810be7b', '21:00')
  ON CONFLICT (id) DO NOTHING;