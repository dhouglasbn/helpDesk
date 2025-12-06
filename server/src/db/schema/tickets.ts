import { pgEnum, pgTable, timestamp, uuid } from "drizzle-orm/pg-core"
import { users } from "./users.ts"

export const ticketStatusEnum = pgEnum("ticket_status", ["aberto", "em_atendimento", "encerrado"])

export const tickets = pgTable("tickets", {
	id: uuid().primaryKey().defaultRandom(),
	clientId: uuid("client_id")
		.references(() => users.id, { onDelete: "cascade" })
		.notNull(),
	techId: uuid("tech_id")
		.references(() => users.id, { onDelete: "cascade" })
		.notNull(),
	status: ticketStatusEnum("status").notNull().default("aberto"),
	createdAt: timestamp("created_at").defaultNow().notNull(),
	updatedAt: timestamp("updated_at").defaultNow().notNull(),
})
