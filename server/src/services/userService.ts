// biome-ignore assist/source/organizeImports: <idontcare>
import { db } from "../db/connection.ts";
import { schema } from "../db/schema/index.ts";
import bcrypt from "bcrypt";
import { eq } from "drizzle-orm";
import { sql } from "drizzle-orm";
import type { UpdateUserObject } from "../types/updateUserObject.ts";

export default class UserService {
	// Métodos do serviço de autenticação podem ser adicionados aqui
	createTechAccount = async (name: string, email: string, password: string) => {
		const emailAleradyInUse = await db.query.users.findFirst({
			where: eq(schema.users.email, email),
		});
		if (emailAleradyInUse) {
			throw new Error("Email already in use");
		}

		const passwordHash = await bcrypt.hash(password, 10);

		const defaultAvailabilities = [
			"08:00",
			"09:00",
			"10:00",
			"11:00",
			"14:00",
			"15:00",
			"16:00",
			"17:00",
		];

		const [newUser] = await db
			.insert(schema.users)
			.values({
				name,
				email,
				passwordHash,
				role: "tech",
			})
			.returning();

		const availabilityRows = defaultAvailabilities.map((time) => ({
			userId: newUser.id,
			time,
		}));

		await db.insert(schema.techniciansAvailabilities).values(availabilityRows);
		return newUser;
	};

	createClientAccount = async (
		name: string,
		email: string,
		password: string,
	) => {
		const emailAleradyInUse = await db.query.users.findFirst({
			where: eq(schema.users.email, email),
		});
		if (emailAleradyInUse) {
			throw new Error("Email already in use");
		}

		const passwordHash = await bcrypt.hash(password, 10);

		return await db
			.insert(schema.users)
			.values({
				name,
				email,
				passwordHash,
				role: "client",
			})
			.returning();
	};

	listTechAccounts = async () =>
		await db
			.select({
				id: schema.users.id,
				name: schema.users.name,
				email: schema.users.email,
				passwordHash: schema.users.passwordHash,
				role: schema.users.role,
				availabilities: sql`array_agg(${schema.techniciansAvailabilities.time} ORDER BY ${schema.techniciansAvailabilities.time})`,
			})
			.from(schema.users)
			.leftJoin(
				schema.techniciansAvailabilities,
				eq(schema.techniciansAvailabilities.userId, schema.users.id),
			)
			.where(eq(schema.users.role, "tech"))
			.groupBy(schema.users.id);

	listClientAccounts = async () =>
		await db.query.users.findMany({
			where: eq(schema.users.role, "client"),
		});

	updateAdminAccount = async (
		updatingUserId: string,
		{ newName, newEmail, newPassword }: UpdateUserObject,
	) => {
		const userWithNewEmail = await db.query.users.findFirst({
			where: eq(schema.users.email, newEmail),
		});

		const userExists = await db.query.users.findFirst({
			where: eq(schema.users.id, updatingUserId),
		});
		if (!userExists || userExists.role !== "admin") {
			throw new Error("Admin not found");
		}

		if (userWithNewEmail && userWithNewEmail.id !== updatingUserId) {
			throw new Error("Email already in use by another account");
		}

		const passwordHash = await bcrypt.hash(newPassword, 10);

		return await db
			.update(schema.users)
			.set({
				name: newName,
				email: newEmail,
				passwordHash,
			})
			.where(eq(schema.users.id, updatingUserId))
			.returning();
	};

	updateTechAccount = async (
		updatingUserId: string,
		{ newName, newEmail, newPassword }: UpdateUserObject,
	) => {
		const userWithNewEmail = await db.query.users.findFirst({
			where: eq(schema.users.email, newEmail),
		});

		const userExists = await db.query.users.findFirst({
			where: eq(schema.users.id, updatingUserId),
		});
		if (!userExists || userExists.role !== "tech") {
			throw new Error("Tech not found");
		}

		if (userWithNewEmail && userWithNewEmail.id !== updatingUserId) {
			throw new Error("Email already in use by another account");
		}

		const passwordHash = await bcrypt.hash(newPassword, 10);

		return await db
			.update(schema.users)
			.set({
				name: newName,
				email: newEmail,
				passwordHash,
			})
			.where(eq(schema.users.id, updatingUserId))
			.returning();
	};

	updateClientAccount = async (
		updatingUserId: string,
		{ newName, newEmail, newPassword }: UpdateUserObject,
	) => {
		const userWithNewEmail = await db.query.users.findFirst({
			where: eq(schema.users.email, newEmail),
		});

		const userExists = await db.query.users.findFirst({
			where: eq(schema.users.id, updatingUserId),
		});
		if (!userExists || userExists.role !== "client") {
			throw new Error("Client not found");
		}

		if (userWithNewEmail && userWithNewEmail.id !== updatingUserId) {
			throw new Error("Email already in use by another account");
		}

		const passwordHash = await bcrypt.hash(newPassword, 10);

		return await db
			.update(schema.users)
			.set({
				name: newName,
				email: newEmail,
				passwordHash,
			})
			.where(eq(schema.users.id, updatingUserId))
			.returning();
	};

	updateTechAvailabilities = async (
		userId: string,
		newAvailabilities: string[],
	) => {
		const userExists = await db.query.users.findFirst({
			where: eq(schema.users.id, userId),
		});
		if (!userExists || userExists.role !== "tech") {
			throw new Error("Technician not found");
		}

		await db
			.delete(schema.techniciansAvailabilities)
			.where(eq(schema.techniciansAvailabilities.userId, userId));

		const availabilityRows = newAvailabilities.map((time) => ({
			userId,
			time,
		}));

		return await db
			.insert(schema.techniciansAvailabilities)
			.values(availabilityRows)
			.returning();
	};

	updateUserPicture = async (userId: string, pictureUrl: string) => {
		const userExists = await db.query.users.findFirst({
			where: eq(schema.users.id, userId),
		});
		if (!userExists) {
			throw new Error("User not found");
		}

		await db
			.update(schema.users)
			.set({
				picture: pictureUrl,
			})
			.where(eq(schema.users.id, userId));

		return `http://localhost:3333/users/picture/${userId}`;
	};

	getUserPicture = async (userId: string) => {
		const user = await db.query.users.findFirst({
			where: eq(schema.users.id, userId),
		});

		if (!user) {
			throw new Error("User not found");
		}

		return user.picture;
	};

	deleteClienteAccount = async (clientId: string) => {
		const clientExists = await db.query.users.findFirst({
			where: eq(schema.users.id, clientId),
		});
		if (!clientExists || clientExists.role !== "client") {
			throw new Error("Client not found");
		}

		await db.delete(schema.users).where(eq(schema.users.id, clientId));
	};
}
