import { pgEnum, pgTable, uuid, varchar } from "drizzle-orm/pg-core"
import { techniciansAvailabilities } from "./techAvailabilities.ts"
import { relations } from "drizzle-orm"

export const userRoleEnum = pgEnum("user_role", ["admin", "tech", "client"])

export const users = pgTable("users", {
	id: uuid().primaryKey().defaultRandom(),
	name: varchar("name").notNull(),
	email: varchar("email").notNull().unique(),
	passwordHash: varchar("password_hash").notNull(),
	role: userRoleEnum("role").notNull(),
	picture: varchar("picture"),
})

export const userRelations = relations(users, ({ many }) => ({
	availabilities: many(techniciansAvailabilities)
}))

