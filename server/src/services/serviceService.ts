import { db } from "../db/connection.ts"
import { schema } from "../db/schema/index.ts"
import { eq } from "drizzle-orm"

export default class ServiceService {
	// Métodos do serviço de autenticação podem ser adicionados aqui
	createService = async (title: string, price: number) => {
		return await db
			.insert(schema.services)
			.values({
				title,
				price: String(price),
			})
			.returning()
	}

	updateService = async (serviceId: string, title: string, price: number) => {
		const serviceExists = await db.query.services.findFirst({ where: eq(schema.services.id, serviceId) })
		if (!serviceExists) {
			throw new Error("Este serviço não existe.")
		}

		return await db.update(schema.services)
			.set({
				title,
				price: String(price)
			})
			.where(eq(schema.services.id, serviceId))
			.returning()
	}

	deactivateService = async (serviceId: string) => {
		const serviceExists = await db.query.services.findFirst({ where: eq(schema.services.id, serviceId) })
		if (!serviceExists) {
			throw new Error("Este serviço não existe.")
		}

		return await db.update(schema.services)
			.set({
				active: false
			})
			.where(eq(schema.services.id, serviceId))
			.returning()
	}
}
