/**
 * @openapi
 * /users/login:
 *   post:
 *     tags:
 *       - Users
 *     summary: Realiza login e retorna o token JWT
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login realizado
 *       400:
 *         description: Credenciais inválidas
 */

/**
 * @openapi
 * /users/tech:
 *   post:
 *     tags:
 *       - Users
 *     summary: Cria conta de técnico (ADMIN)
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - email
 *               - password
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *     responses:
 *       201:
 *         description: Técnico criado
 *       403:
 *         description: Não autorizado
 */

/**
 * @openapi
 * /users/techList:
 *   get:
 *     tags:
 *       - Users
 *     summary: Lista contas de técnicos (ADMIN)
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Lista de técnicos
 */

/**
 * @openapi
 * /users/tech/{id}:
 *   put:
 *     tags:
 *       - Users
 *     summary: Atualiza conta de técnico
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: string
 *           format: uuid
 *         required: true
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - newName
 *               - newEmail
 *               - newPassword
 *             properties:
 *               newName:
 *                 type: string
 *               newEmail:
 *                 type: string
 *                 format: email
 *               newPassword:
 *                 type: string
 *     responses:
 *       200:
 *         description: Técnico atualizado
 *       403:
 *         description: Não autorizado
 */

/**
 * @openapi
 * /users/techAvailabilities/{id}:
 *   put:
 *     tags:
 *       - Users
 *     summary: Atualiza horários disponíveis do técnico
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: string
 *           format: uuid
 *         required: true
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - newAvailabilities
 *             properties:
 *               newAvailabilities:
 *                 type: array
 *                 items:
 *                   type: string
 *                   example: "14:00"
 *     responses:
 *       200:
 *         description: Horários atualizados
 */

/**
 * @openapi
 * /users/admin/{id}:
 *   put:
 *     tags:
 *       - Users
 *     summary: Atualiza um administrador
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         schema:
 *           type: string
 *           format: uuid
 *         required: true
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - newName
 *               - newEmail
 *               - newPassword
 *     responses:
 *       200:
 *         description: Admin atualizado
 */

/**
 * @openapi
 * /users/client:
 *   post:
 *     tags:
 *       - Users
 *     summary: Cria conta de cliente
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - email
 *               - password
 *     responses:
 *       201:
 *         description: Cliente criado
 */

/**
 * @openapi
 * /users/client/{id}:
 *   put:
 *     tags:
 *       - Users
 *     summary: Atualiza conta de cliente
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         schema:
 *           type: string
 *           format: uuid
 *         required: true
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - newName
 *               - newEmail
 *               - newPassword
 *     responses:
 *       200:
 *         description: Cliente atualizado
 */

/**
 * @openapi
 * /users/client/{id}:
 *   delete:
 *     tags:
 *       - Users
 *     summary: Deleta conta de cliente
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         schema:
 *           type: string
 *           format: uuid
 *         required: true
 *     responses:
 *       204:
 *         description: Conta removida
 */

/**
 * @openapi
 * /users/picture/{id}:
 *   put:
 *     tags:
 *       - Users
 *     summary: Atualiza a foto de um usuário
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             required:
 *               - profilePic
 *             properties:
 *               profilePic:
 *                 type: string
 *                 format: binary
 *     responses:
 *       200:
 *         description: Foto atualizada
 */

/**
 * @openapi
 * /users/picture/{id}:
 *   get:
 *     tags:
 *       - Users
 *     summary: Retorna a foto do usuário
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     responses:
 *       200:
 *         description: Foto retornada
 */
