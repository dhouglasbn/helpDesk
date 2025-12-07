import { Router } from "express"
import { authMiddleware } from "../middlewares/authMiddleware.ts"
import { validateZodSchema } from "../middlewares/validateDataMiddleware.ts"
import { z } from "zod"
import TicketController from "../controllers/ticketController.ts"

const router = Router()
const ticketController = new TicketController()

router.post(
	"/",
	authMiddleware,
	validateZodSchema(
		z.object({
			techId: z.uuid("Informe um identificador válido para o técnico"),
			servicesIds: z.uuid().array().min(1, "Informe pelo menos 1 serviço"),
		}),
	),
	ticketController.createTicket,
)

export { router as ticketRoutes }
