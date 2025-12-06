import { pgTable, uuid, varchar } from "drizzle-orm/pg-core"
import { users } from "./users.ts"

export const techniciansAvailabilities = pgTable("technician_availability", {
	id: uuid().primaryKey().defaultRandom(),
	userId: uuid("user_id")
		.references(() => users.id, { onDelete: "cascade" })
		.notNull(),
	time: varchar("time").notNull(),
})
