import express from "express"
import cors from "cors"
import { env } from "./env.ts"
import { userRoutes } from "./routes/userRoutes.ts"
import { serviceRoutes } from "./routes/serviceRoutes.ts"

const app = express()
const PORT = env.PORT || 3333

app.use(cors())
app.use(express.json())

app.use("/users", userRoutes)
app.use("/services", serviceRoutes)
app.get("/health", (req, res) => res.send("OK"))

app.listen(
	{
		hots: "0.0.0.0",
		port: PORT,
	},
	() => {
		console.log(`Server is running on http://localhost:${PORT}`)
	},
)
