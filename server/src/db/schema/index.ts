import { services } from "./services.ts"
import { techniciansAvailabilities } from "./techAvailabilities.ts"
import { tickets } from "./tickets.ts"
import { ticketServices } from "./ticketsServices.ts"
import { users } from "./users.ts"

export const schema = {
	users,
	techniciansAvailabilities,
	services,
	tickets,
	ticketServices,
}
