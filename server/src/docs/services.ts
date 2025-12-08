/**
 * @openapi
 * /services:
 *   post:
 *     tags:
 *       - Services
 *     summary: Cria um novo serviço
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - title
 *               - price
 *             properties:
 *               title:
 *                 type: string
 *                 minLength: 3
 *               price:
 *                 type: number
 *                 minimum: 0
 *     responses:
 *       201:
 *         description: Serviço criado com sucesso
 *       400:
 *         description: Erro de validação
 *       403:
 *         description: Apenas administradores podem criar serviços
 */

/**
 * @openapi
 * /services/list:
 *   get:
 *     tags:
 *       - Services
 *     summary: Lista todos os serviços ativos
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Lista de serviços
 */

/**
 * @openapi
 * /services/{id}:
 *   put:
 *     tags:
 *       - Services
 *     summary: Atualiza um serviço existente
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
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - title
 *               - price
 *             properties:
 *               title:
 *                 type: string
 *               price:
 *                 type: number
 *     responses:
 *       200:
 *         description: Serviço atualizado
 *       403:
 *         description: Apenas admins podem atualizar serviços
 *       400:
 *         description: Erro de validação
 */

/**
 * @openapi
 * /services/{id}:
 *   delete:
 *     tags:
 *       - Services
 *     summary: Desativa um serviço
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     responses:
 *       204:
 *         description: Serviço desativado
 *       403:
 *         description: Apenas admins podem desativar serviços
 */
