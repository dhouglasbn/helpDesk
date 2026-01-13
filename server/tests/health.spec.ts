import request from "supertest"
import express from "express"
import cors from "cors"

const app = express()

app.use(cors())
app.use(express.json())
app.get("/health", (_req, res) => res.send("OK"))

describe("Health Check", () => {
	it("GET /health returns OK", async () => {
		const response = await request(app).get("/health")
		expect(response.status).toBe(200)
		expect(response.text).toBe("OK")
	})
})
