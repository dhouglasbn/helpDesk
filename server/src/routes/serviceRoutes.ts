import { Router } from "express";
import { authMiddleware } from "../middlewares/authMiddleware.ts";
import { validateZodSchema } from "../middlewares/validateDataMiddleware.ts";
import { z } from "zod";
import ServiceController from "../controllers/serviceController.ts";

const router = Router();
const serviceController = new ServiceController();

router.post(
	"/",
	authMiddleware,
	validateZodSchema(
		z.object({
			title: z.string().min(3, "O título deve ter no mínimo 3 caracteres"),
			price: z.number().min(0, "O preço deve ser um número positivo"),
		}),
	),
	serviceController.createService,
);
router.get("/list", authMiddleware, serviceController.listServices);
router.put(
	"/:id",
	authMiddleware,
	validateZodSchema(
		z.object({
			title: z.string().min(3, "O título deve ter no mínimo 3 caracteres"),
			price: z.number().min(0, "O preço deve ser um número positivo"),
		}),
		z.object({
			id: z.uuid(),
		}),
	),
	serviceController.updateService,
);
router.delete(
	"/:id",
	authMiddleware,
	validateZodSchema(
		z.undefined(),
		z.object({
			id: z.uuid(),
		}),
	),
	serviceController.deactivateService,
);

export { router as serviceRoutes };
