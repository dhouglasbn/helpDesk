// biome-ignore assist/source/organizeImports: <i dont care>
import ServiceService from "../services/serviceService.ts"
import TicketService from "../services/ticketService.ts"
import type { OurRequest } from "../types/ourRequest.ts"
import type { Response } from "express"

export default class TicketController {
	private ticketService: TicketService

	constructor() {
		this.ticketService = new TicketService()
	}

	createTicket = async (request: OurRequest, reply: Response) => {
		if (!request.user?.role || request.user.role !== "client") {
			return reply.status(403).json({ message: "Acesso negado: Somente o cliente pode criar serviços para os técnicos." })
		}

		const { techId, servicesIds } = request.body

		try {
			const newTicket = await this.ticketService.createTicket(request.user.id, techId, servicesIds)
			return reply.status(201).json(newTicket).send()
		} catch (error) {
			return reply.status(400).json({ error: (error as Error).message })
		}
	}

}
