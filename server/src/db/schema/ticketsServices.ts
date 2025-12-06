import { pgTable, primaryKey, uuid } from "drizzle-orm/pg-core"
import { tickets } from "./tickets.ts"
import { services } from "./services.ts"

export const ticketServices = pgTable(
	"ticket_services",
	{
		ticketId: uuid("ticket_id")
			.references(() => tickets.id, { onDelete: "cascade" })
			.notNull(),
		serviceId: uuid("service_id")
			.references(() => services.id, { onDelete: "cascade" })
			.notNull(),
	},
	(t) => [primaryKey({ columns: [t.ticketId, t.serviceId] })],
)
