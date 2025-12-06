import { boolean, numeric, pgTable, uuid, varchar } from "drizzle-orm/pg-core"

export const services = pgTable("services", {
	id: uuid().primaryKey().defaultRandom(),
	title: varchar("title").notNull(),
	price: numeric("price").notNull(),
	active: boolean("active").notNull().default(true)
})
