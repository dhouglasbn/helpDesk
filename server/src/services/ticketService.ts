// biome-ignore assist/source/organizeImports: <i dont care>
import { db } from "../db/connection.ts"
import { schema } from "../db/schema/index.ts"
import { eq, and, inArray } from "drizzle-orm"

export default class TicketService {

  createTicket = async (clientId: string, techId: string, servicesIds: string[]) => {
    const techExists = await db.query.users.findFirst({ where: and(eq(schema.users.id, techId), eq(schema.users.role, 'tech'))})
    if (!techExists) throw new Error("Esse técnico não existe")
    
    const existingServices = await db
      .select({ id: schema.services.id })
      .from(schema.services)
      .where(inArray(schema.services.id, servicesIds))

    if (existingServices.length !== servicesIds.length) {
      throw new Error("Algum serviço informado não existe")
    }

    const ticket = await db.transaction(async tx => {
      const [newTicket] = await tx
      .insert(schema.tickets)
      .values({
        clientId,
        techId
      })
      .returning()

      await tx.insert(schema.ticketServices)
      .values(
        servicesIds.map(serviceId => ({
          ticketId: newTicket.id,
          serviceId,
        }))
      )

      return newTicket
    })

    return {
      id: ticket.id,
      clientId: ticket.clientId,
      techId: ticket.techId,
      status: ticket.status,
      createdAt: ticket.createdAt,
      servicesIds: servicesIds
    }
  }
}