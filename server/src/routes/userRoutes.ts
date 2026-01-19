import { Router } from "express";
import UserController from "../controllers/userController.ts";
import { authMiddleware } from "../middlewares/authMiddleware.ts";
import { validateZodSchema } from "../middlewares/validateDataMiddleware.ts";
import { z } from "zod";
import multer from "multer";

const router = Router();
const userController = new UserController();
const upload = multer({ storage: multer.memoryStorage() });

// login
router.post("/login", userController.login);

// CRUD tech accounts
router.post(
	"/tech",
	authMiddleware,
	validateZodSchema(
		z.object({
			name: z.string().min(3),
			email: z.email(),
			password: z.string().min(6),
		}),
	),
	userController.createTechAccount,
);
router.get("/techList", authMiddleware, userController.listTechAccounts);
router.put(
	"/tech/:id",
	authMiddleware,
	validateZodSchema(
		z.object({
			newName: z.string().min(3),
			newEmail: z.email(),
			newPassword: z.string().min(6),
		}),
		z.object({
			id: z.uuid(),
		}),
	),
	userController.updateTechAccount,
);
router.put(
	"/techAvailabilities/:id",
	authMiddleware,
	validateZodSchema(
		z.object({
			newAvailabilities: z
				.string()
				.regex(/^([01]\d|2[0-3]):00$/, {
					message: "Horário inválido. Use o formato HH:00 (00–23 / 00).",
				})
				.array()
				.min(1),
		}),
		z.object({
			id: z.uuid(),
		}),
	),
	userController.updateTechAvailabilities,
);

router.put(
	"/admin/:id",
	authMiddleware,
	validateZodSchema(
		z.object({
			newName: z.string().min(3),
			newEmail: z.email(),
			newPassword: z.string().min(6),
		}),
		z.object({
			id: z.uuid(),
		}),
	),
	userController.updateAdminAccount,
);

// CRUD de clients
router.post(
	"/client",
	validateZodSchema(
		z.object({
			name: z.string().min(3),
			email: z.email(),
			password: z.string().min(6),
		}),
	),
	userController.createClientAccount,
);
router.put(
	"/client/:id",
	authMiddleware,
	validateZodSchema(
		z.object({
			newName: z.string().min(3),
			newEmail: z.email(),
			newPassword: z.string().min(6),
		}),
		z.object({
			id: z.uuid(),
		}),
	),
	userController.updateClientAccount,
);
router.get("/clientList", authMiddleware, userController.listClientAccounts);
router.delete(
	"/client/:id",
	authMiddleware,
	validateZodSchema(
		undefined,
		z.object({
			id: z.uuid(),
		}),
	),
	userController.deleteClientAccount,
);

// GET e UPLOAD da foto de usuário
router.put(
	"/picture/:id",
	upload.single("profilePic"),
	authMiddleware,
	validateZodSchema(
		undefined,
		z.object({
			id: z.uuid(),
		}),
	),
	userController.updateUserPicture,
);
router.get(
	"/picture/:id",
	validateZodSchema(
		undefined,
		z.object({
			id: z.uuid(),
		}),
	),
	userController.getUserPicture,
);

export { router as userRoutes };
