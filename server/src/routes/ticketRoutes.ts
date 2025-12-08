import { Router } from "express";
import { authMiddleware } from "../middlewares/authMiddleware.ts";
import { validateZodSchema } from "../middlewares/validateDataMiddleware.ts";
import { z } from "zod";
import TicketController from "../controllers/ticketController.ts";

const router = Router();
const ticketController = new TicketController();

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
);
router.get(
	"/clientHistory",
	authMiddleware,
	ticketController.showClientHistory,
);
router.get("/tech", authMiddleware, ticketController.listTechTickets);
router.get("/list", authMiddleware, ticketController.listAllTickets);
router.put(
	"/addServices/:ticketId",
	authMiddleware,
	validateZodSchema(
		z.object({
			servicesIds: z.uuid().array().min(1, "Informe pelo menos 1 serviço"),
		}),
		z.object({
			ticketId: z.uuid(),
		}),
	),
	ticketController.addServicesToATicket,
);
router.put(
	"/status/:ticketId",
	authMiddleware,
	validateZodSchema(
		z.object({
			status: z.enum(["aberto", "em_atendimento", "encerrado"]),
		}),
		z.object({
			ticketId: z.uuid(),
		}),
	),
	ticketController.updateTicketStatus,
);

export { router as ticketRoutes };
