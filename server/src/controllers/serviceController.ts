// biome-ignore assist/source/organizeImports: <i dont care>
import ServiceService from "../services/serviceService.ts"
import type { OurRequest } from "../types/ourRequest.ts"
import type { Response } from "express"

export default class ServiceController {
	private serviceService: ServiceService

	constructor() {
		this.serviceService = new ServiceService()
	}

	createService = async (request: OurRequest, reply: Response) => {
		if (!request.user?.role || request.user.role !== "admin") {
			return reply.status(403).json({ message: "Acesso negado: Somente o admin pode criar serviços para os técnicos." })
		}

		const { title, price } = request.body

		try {
			const newService = await this.serviceService.createService(title, price)
			return reply.status(201).json(newService).send()
		} catch (error) {
			return reply.status(400).json({ error: (error as Error).message })
		}
	}

	updateService = async (request: OurRequest, reply: Response) => {
		if (!request.user?.role || request.user.role !== "admin") {
			return reply.status(403).json({ message: "Acesso negado: Somente o admin pode atualizar serviços para os técnicos." })
		}

		const { title, price } = request.body

		try {
			const serviceId = request.params.id
			const newService = await this.serviceService.updateService(serviceId, title, price)
			return reply.status(200).json(newService).send()
		} catch (error) {
			return reply.status(400).json({ error: (error as Error).message })
		}
	}

	deactivateService = async (request: OurRequest, reply: Response) => {
		if (!request.user?.role || request.user.role !== "admin") {
			return reply.status(403).json({ message: "Acesso negado: Somente o admin pode desativar serviços dos técnicos." })
		}

		try {
			const serviceId = request.params.id
			await this.serviceService.deactivateService(serviceId)
			return reply.status(204).json().send()
		} catch (error) {
			return reply.status(400).json({ error: (error as Error).message })
		}
	}

	listServices = async (request: OurRequest, reply: Response) => {
		if (!request.user?.role || request.user.role !== "admin") {
			return reply.status(403).json({ message: "Acesso negado: Somente o admin pode listar serviços dos técnicos." })
		}

		try {
			const list = await this.serviceService.listServices()
			return reply.status(200).json(list).send()
		} catch (error) {
			return reply.status(400).json({ error: (error as Error).message })
		}
	}
}
