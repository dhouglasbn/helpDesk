/**
 * @openapi
 * /tickets:
 *   post:
 *     tags:
 *       - Tickets
 *     summary: Cria um novo ticket
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - techId
 *               - servicesIds
 *             properties:
 *               techId:
 *                 type: string
 *                 format: uuid
 *               servicesIds:
 *                 type: array
 *                 items:
 *                   type: string
 *                   format: uuid
 *     responses:
 *       201:
 *         description: Ticket criado
 *       403:
 *         description: Somente clientes podem criar tickets
 */

/**
 * @openapi
 * /tickets/clientHistory:
 *   get:
 *     tags:
 *       - Tickets
 *     summary: Lista o histórico de tickets do cliente autenticado
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Histórico retornado
 */

/**
 * @openapi
 * /tickets/tech:
 *   get:
 *     tags:
 *       - Tickets
 *     summary: Lista os tickets do técnico autenticado
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Lista de tickets
 */

/**
 * @openapi
 * /tickets/list:
 *   get:
 *     tags:
 *       - Tickets
 *     summary: Lista todos os tickets (somente admin)
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Lista de tickets
 *       403:
 *         description: Apenas admins podem listar todos os tickets
 */

/**
 * @openapi
 * /tickets/addServices/{ticketId}:
 *   put:
 *     tags:
 *       - Tickets
 *     summary: Adiciona serviços a um ticket
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: ticketId
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
 *               - servicesIds
 *             properties:
 *               servicesIds:
 *                 type: array
 *                 items:
 *                   type: string
 *     responses:
 *       200:
 *         description: Serviços adicionados
 *       403:
 *         description: Apenas técnicos/admin podem adicionar serviços
 */

/**
 * @openapi
 * /tickets/status/{ticketId}:
 *   put:
 *     tags:
 *       - Tickets
 *     summary: Atualiza o status de um ticket
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: ticketId
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
 *               - status
 *             properties:
 *               status:
 *                 type: string
 *                 enum: [aberto, em_atendimento, encerrado]
 *     responses:
 *       200:
 *         description: Status atualizado
 *       403:
 *         description: Apenas técnicos/admin podem atualizar status
 */
