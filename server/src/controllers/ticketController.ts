// biome-ignore assist/source/organizeImports: <i dont care>
import ServiceService from "../services/serviceService.ts";
import TicketService from "../services/ticketService.ts";
import type { OurRequest } from "../types/ourRequest.ts";
import type { Response } from "express";

export default class TicketController {
	private ticketService: TicketService;

	constructor() {
		this.ticketService = new TicketService();
	}

	createTicket = async (request: OurRequest, reply: Response) => {
		if (!request.user?.role || request.user.role !== "client") {
			return reply
				.status(403)
				.json({
					message:
						"Acesso negado: Somente o cliente pode criar serviços para os técnicos.",
				});
		}

		const { techId, servicesIds } = request.body;

		try {
			const newTicket = await this.ticketService.createTicket(
				request.user.id,
				techId,
				servicesIds,
			);
			return reply.status(201).json(newTicket).send();
		} catch (error) {
			return reply.status(400).json({ error: (error as Error).message });
		}
	};

	showClientHistory = async (request: OurRequest, reply: Response) => {
		if (!request.user?.role || request.user.role !== "client") {
			return reply
				.status(403)
				.json({
					message:
						"Acesso negado: Somente o cliente pode ver seu histórico de tickets.",
				});
		}

		try {
			const history = await this.ticketService.showClientHistory(
				request.user.id,
			);
			return reply.status(200).json(history).send();
		} catch (error) {
			return reply.status(400).json({ error: (error as Error).message });
		}
	};

	listTechTickets = async (request: OurRequest, reply: Response) => {
		if (!request.user?.role || request.user.role !== "tech") {
			return reply
				.status(403)
				.json({
					message: "Acesso negado: Somente o técnico pode listar seus tickets.",
				});
		}

		try {
			const tickets = await this.ticketService.listTechTickets(request.user.id);
			return reply.status(200).json(tickets).send();
		} catch (error) {
			return reply.status(400).json({ error: (error as Error).message });
		}
	};

	listAllTickets = async (request: OurRequest, reply: Response) => {
		if (!request.user?.role || request.user.role !== "admin") {
			return reply
				.status(403)
				.json({
					message:
						"Acesso negado: Somente um admin pode listar todos os tickets.",
				});
		}

		try {
			const tickets = await this.ticketService.listAllTickets();
			return reply.status(200).json(tickets).send();
		} catch (error) {
			return reply.status(400).json({ error: (error as Error).message });
		}
	};

	addServicesToATicket = async (request: OurRequest, reply: Response) => {
		if (
			!request.user?.role ||
			(request.user.role !== "tech" && request.user.role !== "admin")
		) {
			return reply
				.status(403)
				.json({
					message:
						"Acesso negado: Somente técnicos e admins podem adicionar serviços a um chamado.",
				});
		}

		try {
			const { ticketId } = request.params;
			const { servicesIds } = request.body;
			const services = await this.ticketService.addServicesToTicket(
				ticketId,
				request.user,
				servicesIds,
			);
			return reply.status(200).json(services).send();
		} catch (error) {
			return reply.status(400).json({ error: (error as Error).message });
		}
	};

	updateTicketStatus = async (request: OurRequest, reply: Response) => {
		if (
			!request.user?.role ||
			(request.user.role !== "tech" && request.user.role !== "admin")
		) {
			return reply
				.status(403)
				.json({
					message:
						"Acesso negado: Somente técnicos e admins podem atualizar o status de um chamado.",
				});
		}

		try {
			const { ticketId } = request.params;
			const { status } = request.body;
			const ticket = await this.ticketService.updateStatus(
				ticketId,
				request.user,
				status,
			);
			return reply.status(200).json(ticket).send();
		} catch (error) {
			return reply.status(400).json({ error: (error as Error).message });
		}
	};
}
