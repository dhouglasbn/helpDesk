// biome-ignore assist/source/organizeImports: <i dont care>
import { db } from "../db/connection.ts";
import { schema } from "../db/schema/index.ts";
import { eq, and, inArray, sql, desc } from "drizzle-orm";
import type { UserInToken } from "../types/ourRequest.ts";
import type { TicketStatus } from "../types/ticketData.ts";

export default class TicketService {
	createTicket = async (
		clientId: string,
		techId: string,
		servicesIds: string[],
	) => {
		const currentHour = `${new Date().toTimeString().slice(0, 2)}:00`; // "HH:MM"
		const availableTech = await db
			.select({
				id: schema.users.id,
				name: schema.users.name,
				email: schema.users.email,
			})
			.from(schema.users)
			.leftJoin(
				schema.techniciansAvailabilities,
				eq(schema.techniciansAvailabilities.userId, schema.users.id),
			)
			.where(
				and(
					eq(schema.users.id, techId),
					eq(schema.users.role, "tech"),
					eq(schema.techniciansAvailabilities.time, currentHour),
				),
			);

		console.log(currentHour);

		console.log(availableTech);

		if (!availableTech[0])
			throw new Error(
				"Esse técnico não existe ou não está disponível no momento.",
			);

		const existingServices = await db
			.select({
				id: schema.services.id,
				title: schema.services.title,
				price: schema.services.price,
			})
			.from(schema.services)
			.where(
				and(
					inArray(schema.services.id, servicesIds),
					eq(schema.services.active, true),
				),
			);

		if (existingServices.length !== servicesIds.length) {
			throw new Error("Algum serviço informado não existe");
		}

		const ticket = await db.transaction(async (tx) => {
			const [newTicket] = await tx
				.insert(schema.tickets)
				.values({
					clientId,
					techId,
				})
				.returning();

			await tx.insert(schema.ticketServices).values(
				servicesIds.map((serviceId) => ({
					ticketId: newTicket.id,
					serviceId,
				})),
			);

			return newTicket;
		});

		return {
			id: ticket.id,
			clientId: ticket.clientId,
			techId: ticket.techId,
			status: ticket.status,
			createdAt: ticket.createdAt,
			services: existingServices,
			totalPrice: `${existingServices.reduce((acc, service) => acc + Number(service.price), 0)}.0`,
		};
	};

	showClientHistory = async (clientId: string) =>
		await db
			.select({
				id: schema.tickets.id,
				clientId: schema.tickets.clientId,
				techId: schema.tickets.techId,
				status: schema.tickets.status,
				createdAt: schema.tickets.createdAt,
				updatedAt: schema.tickets.updatedAt,
				services: sql`json_agg(json_build_object(
        'id', ${schema.services.id},
        'title', ${schema.services.title},
        'price', ${schema.services.price}::text
      ))`,
				totalPrice: sql`SUM(${schema.services.price}::numeric)`,
			})
			.from(schema.tickets)
			.leftJoin(
				schema.ticketServices,
				eq(schema.ticketServices.ticketId, schema.tickets.id),
			)
			.leftJoin(
				schema.services,
				eq(schema.services.id, schema.ticketServices.serviceId),
			)
			.where(eq(schema.tickets.clientId, clientId))
			.groupBy(schema.tickets.id)
			.orderBy(desc(schema.tickets.createdAt));

	listTechTickets = async (techId: string) =>
		await db
			.select({
				id: schema.tickets.id,
				clientId: schema.tickets.clientId,
				techId: schema.tickets.techId,
				status: schema.tickets.status,
				createdAt: schema.tickets.createdAt,
				updatedAt: schema.tickets.updatedAt,
				services: sql`json_agg(json_build_object(
        'id', ${schema.services.id},
        'title', ${schema.services.title},
        'price', ${schema.services.price}::text
      ))`,
				totalPrice: sql`SUM(${schema.services.price}::numeric)`,
			})
			.from(schema.tickets)
			.leftJoin(
				schema.ticketServices,
				eq(schema.ticketServices.ticketId, schema.tickets.id),
			)
			.leftJoin(
				schema.services,
				eq(schema.services.id, schema.ticketServices.serviceId),
			)
			.where(eq(schema.tickets.techId, techId))
			.groupBy(schema.tickets.id)
			.orderBy(schema.tickets.createdAt);

	listAllTickets = async () =>
		await db
			.select({
				id: schema.tickets.id,
				clientId: schema.tickets.clientId,
				techId: schema.tickets.techId,
				status: schema.tickets.status,
				createdAt: schema.tickets.createdAt,
				updatedAt: schema.tickets.updatedAt,
				services: sql`json_agg(json_build_object(
        'id', ${schema.services.id},
        'title', ${schema.services.title},
        'price', ${schema.services.price}::text
      ))`,
				totalPrice: sql`SUM(${schema.services.price}::numeric)`,
			})
			.from(schema.tickets)
			.leftJoin(
				schema.ticketServices,
				eq(schema.ticketServices.ticketId, schema.tickets.id),
			)
			.leftJoin(
				schema.services,
				eq(schema.services.id, schema.ticketServices.serviceId),
			)
			.groupBy(schema.tickets.id)
			.orderBy(schema.tickets.createdAt);

	addServicesToTicket = async (
		ticketId: string,
		user: UserInToken,
		servicesIds: string[],
	) => {
		const ticket = await db.query.tickets.findFirst({
			where: eq(schema.tickets.id, ticketId),
		});
		if (!ticket) throw new Error("Esse chamado não existe");
		if (ticket.techId !== user.id && user.role !== "admin") {
			throw new Error(
				"Acesso negado: você só pode adicionar serviços aos seus chamados",
			);
		}

		const existingServices = await db
			.select({
				id: schema.services.id,
				title: schema.services.title,
				price: schema.services.price,
			})
			.from(schema.services)
			.where(
				and(
					inArray(schema.services.id, servicesIds),
					eq(schema.services.active, true),
				),
			);

		if (existingServices.length !== servicesIds.length) {
			throw new Error("Algum serviço informado não existe");
		}

		return await db.transaction(async (tx) => {
			await db
				.insert(schema.ticketServices)
				.values(servicesIds.map((serviceId) => ({ ticketId, serviceId })))
				.onConflictDoNothing();

			return await tx
				.select({
					serviceId: schema.ticketServices.serviceId,
				})
				.from(schema.ticketServices)
				.where(eq(schema.ticketServices.ticketId, ticketId));
		});
	};

	updateStatus = async (
		ticketId: string,
		user: UserInToken,
		status: TicketStatus,
	) => {
		const ticket = await db.query.tickets.findFirst({
			where: eq(schema.tickets.id, ticketId),
		});
		if (!ticket) throw new Error("Esse chamado não existe");
		if (ticket.techId !== user.id && user.role !== "admin") {
			throw new Error(
				"Acesso negado: você só pode atualizar o status dos seus chamados",
			);
		}

		return await db
			.update(schema.tickets)
			.set({
				status,
			})
			.where(eq(schema.tickets.id, ticketId))
			.returning();
	};
}
