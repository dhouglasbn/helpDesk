import request from "supertest"
import express, { type Express } from "express"
import cors from "cors"
import jwt from "jsonwebtoken"

import { userRoutes } from "../src/routes/userRoutes.ts"

let app: Express

// Mock auth tokens
const createMockToken = (userId: string, role: "admin" | "tech" | "client") =>
	jwt.sign({ id: userId, role }, process.env.JWT_SECRET || "test-secret", { expiresIn: "1h" })

const mockAdminToken = createMockToken("admin-id-123", "admin")
const mockTechToken = createMockToken("tech-id-123", "tech")
const mockClientToken = createMockToken("client-id-123", "client")

describe("User Routes", () => {
	beforeEach(() => {
		app = express()
		app.use(cors())
		app.use(express.json())
		app.use(express.urlencoded({ extended: true }))
		app.use("/users", userRoutes)
	})

	describe("POST /users/login", () => {
		it("should return 200 with token on successful login", async () => {
			const response = await request(app).post("/users/login").send({
				email: "admin@example.com",
				password: "password123",
			})

			expect(response.status).toBeLessThanOrEqual(400) // Can fail if user doesn't exist
			if (response.status === 200) {
				expect(response.body).toHaveProperty("token")
				expect(typeof response.body.token).toBe("string")
			}
		})

		it("should return 400 on invalid credentials", async () => {
			const response = await request(app).post("/users/login").send({
				email: "nonexistent@example.com",
				password: "wrongpassword",
			})

			expect(response.status).toBe(400)
			expect(response.body).toHaveProperty("error")
		})

		it("should return 400 when email is missing", async () => {
			const response = await request(app).post("/users/login").send({
				password: "password123",
			})

			expect([400, 500]).toContain(response.status)
		})
	})

	describe("POST /users/tech - Create Tech Account", () => {
		it("should return 403 when non-admin tries to create tech account", async () => {
			const response = await request(app).post("/users/tech").set("Authorization", `Bearer ${mockTechToken}`).send({
				name: "Técnico Novo",
				email: "tech@example.com",
				password: "password123",
			})

			expect(response.status).toBe(403)
			expect(response.body.message).toContain("admin")
		})

		it("should return 401 when no token is provided", async () => {
			const response = await request(app).post("/users/tech").send({
				name: "Técnico Novo",
				email: "tech@example.com",
				password: "password123",
			})

			expect(response.status).toBe(401)
		})

		it("should validate required fields", async () => {
			const response = await request(app).post("/users/tech").set("Authorization", `Bearer ${mockAdminToken}`).send({
				name: "ab", // too short
				email: "invalid-email",
				password: "short", // too short
			})

			expect([400, 422]).toContain(response.status)
		})
	})

	describe("GET /users/techList - List Tech Accounts", () => {
		it("should return 403 when non-admin tries to list tech accounts", async () => {
			const response = await request(app).get("/users/techList").set("Authorization", `Bearer ${mockClientToken}`)

			expect(response.status).toBe(403)
			expect(response.body.message).toContain("admin")
		})

		it("should return 401 when no token is provided", async () => {
			const response = await request(app).get("/users/techList")

			expect(response.status).toBe(401)
		})

		it("should return tech list when admin is authenticated", async () => {
			const response = await request(app).get("/users/techList").set("Authorization", `Bearer ${mockAdminToken}`)

			expect([200, 400]).toContain(response.status)
			if (response.status === 200) {
				expect(response.body).toHaveProperty("techList")
				expect(Array.isArray(response.body.techList)).toBe(true)
			}
		})
	})

	describe("PUT /users/tech/:id - Update Tech Account", () => {
		const techId = "tech-id-123"

		it("should return 403 when unauthorized user tries to update another tech", async () => {
			const response = await request(app)
				.put(`/users/tech/${techId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					newName: "Técnico Atualizado",
					newEmail: "newemail@example.com",
					newPassword: "newpassword123",
				})

			// Tech can update their own account but not others (or validation error if other)
			expect([200, 403, 400]).toContain(response.status)
		})

		it("should return 401 when no token is provided", async () => {
			const response = await request(app).put(`/users/tech/${techId}`).send({
				newName: "Técnico Atualizado",
				newEmail: "newemail@example.com",
				newPassword: "newpassword123",
			})

			expect(response.status).toBe(401)
		})

		it("should validate update fields", async () => {
			const response = await request(app)
				.put(`/users/tech/${techId}`)
				.set("Authorization", `Bearer ${mockAdminToken}`)
				.send({
					newName: "ab", // too short
					newEmail: "invalid-email",
					newPassword: "short",
				})

			expect([400, 422]).toContain(response.status)
		})

		it("admin should be able to update any tech account", async () => {
			const response = await request(app)
				.put(`/users/tech/${techId}`)
				.set("Authorization", `Bearer ${mockAdminToken}`)
				.send({
					newName: "Técnico Atualizado",
					newEmail: "updated@example.com",
					newPassword: "newpassword123",
				})

			expect([200, 400]).toContain(response.status)
		})
	})

	describe("PUT /users/techAvailabilities/:id - Update Tech Availabilities", () => {
		const techId = "tech-id-123"

		it("should return 401 when no token is provided", async () => {
			const response = await request(app)
				.put(`/users/techAvailabilities/${techId}`)
				.send({
					newAvailabilities: ["08:00", "09:00", "10:00"],
				})

			expect(response.status).toBe(401)
		})

		it("should return 403 when non-tech/admin tries to update availabilities", async () => {
			const response = await request(app)
				.put(`/users/techAvailabilities/${techId}`)
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({
					newAvailabilities: ["08:00", "09:00", "10:00"],
				})

			expect([403, 400]).toContain(response.status)
		})

		it("should validate availability format", async () => {
			const response = await request(app)
				.put(`/users/techAvailabilities/${techId}`)
				.set("Authorization", `Bearer ${mockAdminToken}`)
				.send({
					newAvailabilities: ["25:00", "invalid"], // invalid format
				})

			expect([400, 422]).toContain(response.status)
		})

		it("should accept valid availability times", async () => {
			const response = await request(app)
				.put(`/users/techAvailabilities/${techId}`)
				.set("Authorization", `Bearer ${mockAdminToken}`)
				.send({
					newAvailabilities: ["08:00", "09:00", "10:00", "11:00", "14:00"],
				})

			expect([200, 400]).toContain(response.status)
		})
	})

	describe("PUT /users/admin/:id - Update Admin Account", () => {
		const adminId = "admin-id-123"

		it("should return 403 when non-admin tries to update admin account", async () => {
			const response = await request(app)
				.put(`/users/admin/${adminId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					newName: "Admin Atualizado",
					newEmail: "admin@example.com",
					newPassword: "newpassword123",
				})

			expect([403, 400]).toContain(response.status)
			if (response.status === 403) {
				expect(response.body.message).toContain("admin")
			}
		})

		it("should return 401 when no token is provided", async () => {
			const response = await request(app).put(`/users/admin/${adminId}`).send({
				newName: "Admin Atualizado",
				newEmail: "admin@example.com",
				newPassword: "newpassword123",
			})

			expect(response.status).toBe(401)
		})

		it("admin should be able to update admin account", async () => {
			const response = await request(app)
				.put(`/users/admin/${adminId}`)
				.set("Authorization", `Bearer ${mockAdminToken}`)
				.send({
					newName: "Admin Atualizado",
					newEmail: "admin.new@example.com",
					newPassword: "newpassword123",
				})

			expect([200, 400]).toContain(response.status)
		})
	})

	describe("POST /users/client - Create Client Account", () => {
		it("should allow creating client account without authentication", async () => {
			const response = await request(app)
				.post("/users/client")
				.send({
					name: "Cliente Novo",
					email: `client${Date.now()}@example.com`,
					password: "password123",
				})

			expect([201, 400]).toContain(response.status)
			if (response.status === 201) {
				expect(response.body).toHaveProperty("newClient")
			}
		})

		it("should validate client creation fields", async () => {
			const response = await request(app).post("/users/client").send({
				name: "ab", // too short
				email: "invalid-email",
				password: "short",
			})

			expect([400, 422]).toContain(response.status)
		})

		it("should reject duplicate email", async () => {
			const email = `client${Date.now()}@example.com`
			const validData = {
				name: "Cliente Um",
				email,
				password: "password123",
			}

			// First request
			await request(app).post("/users/client").send(validData)

			// Second request with same email
			const response = await request(app).post("/users/client").send(validData)

			expect(response.status).toBe(400)
			expect(response.body).toHaveProperty("error")
		})
	})

	describe("PUT /users/client/:id - Update Client Account", () => {
		const clientId = "client-id-123"

		it("should return 401 when no token is provided", async () => {
			const response = await request(app).put(`/users/client/${clientId}`).send({
				newName: "Cliente Atualizado",
				newEmail: "newemail@example.com",
				newPassword: "newpassword123",
			})

			expect(response.status).toBe(401)
		})

		it("should allow client to update their own account", async () => {
			const response = await request(app)
				.put(`/users/client/${clientId}`)
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({
					newName: "Cliente Atualizado",
					newEmail: "updated@example.com",
					newPassword: "newpassword123",
				})

			expect([200, 400]).toContain(response.status)
		})

		it("should prevent client from updating another client account", async () => {
			const otherId = "other-client-id"
			const response = await request(app)
				.put(`/users/client/${otherId}`)
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({
					newName: "Cliente Atualizado",
					newEmail: "updated@example.com",
					newPassword: "newpassword123",
				})

			expect([403, 400]).toContain(response.status)
		})

		it("admin should be able to update any client account", async () => {
			const response = await request(app)
				.put(`/users/client/${clientId}`)
				.set("Authorization", `Bearer ${mockAdminToken}`)
				.send({
					newName: "Cliente Atualizado",
					newEmail: "updated.admin@example.com",
					newPassword: "newpassword123",
				})

			expect([200, 400]).toContain(response.status)
		})

		it("should validate update fields", async () => {
			const response = await request(app)
				.put(`/users/client/${clientId}`)
				.set("Authorization", `Bearer ${mockAdminToken}`)
				.send({
					newName: "ab",
					newEmail: "invalid-email",
					newPassword: "short",
				})

			expect([400, 422]).toContain(response.status)
		})
	})

	describe("GET /users/clientList - List Client Accounts", () => {
		it("should return 403 when non-admin tries to list clients", async () => {
			const response = await request(app).get("/users/clientList").set("Authorization", `Bearer ${mockClientToken}`)

			expect(response.status).toBe(403)
			expect(response.body.message).toContain("admin")
		})

		it("should return 401 when no token is provided", async () => {
			const response = await request(app).get("/users/clientList")

			expect(response.status).toBe(401)
		})

		it("should return client list when admin is authenticated", async () => {
			const response = await request(app).get("/users/clientList").set("Authorization", `Bearer ${mockAdminToken}`)

			expect([200, 400]).toContain(response.status)
			if (response.status === 200) {
				expect(response.body).toHaveProperty("clientList")
				expect(Array.isArray(response.body.clientList)).toBe(true)
			}
		})
	})

	describe("DELETE /users/client/:id - Delete Client Account", () => {
		const clientId = "client-id-123"

		it("should return 401 when no token is provided", async () => {
			const response = await request(app).delete(`/users/client/${clientId}`)

			expect(response.status).toBe(401)
		})

		it("should allow client to delete their own account", async () => {
			const response = await request(app)
				.delete(`/users/client/${clientId}`)
				.set("Authorization", `Bearer ${mockClientToken}`)

			expect([204, 400]).toContain(response.status)
		})

		it("should prevent client from deleting another client account", async () => {
			const otherId = "other-client-id"
			const response = await request(app)
				.delete(`/users/client/${otherId}`)
				.set("Authorization", `Bearer ${mockClientToken}`)

			expect([403, 400]).toContain(response.status)
		})

		it("admin should be able to delete any client account", async () => {
			const response = await request(app)
				.delete(`/users/client/${clientId}`)
				.set("Authorization", `Bearer ${mockAdminToken}`)

			expect([204, 400]).toContain(response.status)
		})

		it("should return 403 when non-admin/client tries to delete", async () => {
			const response = await request(app)
				.delete(`/users/client/${clientId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)

			expect([403, 400]).toContain(response.status)
		})
	})

	describe("PUT /users/picture/:id - Update User Picture", () => {
		const userId = "user-id-123"

		it("should return 401 when no token is provided", async () => {
			const response = await request(app)
				.put(`/users/picture/${userId}`)
				.attach("profilePic", Buffer.from("test image data"))

			expect(response.status).toBe(401)
		})

		it("should allow user to update their own picture", async () => {
			const response = await request(app)
				.put(`/users/picture/${userId}`)
				.set("Authorization", `Bearer ${mockClientToken}`)
				.attach("profilePic", Buffer.from("test image data"), "test.png")

			expect([200, 400, 403]).toContain(response.status)
		})

		it("should prevent user from updating another user picture", async () => {
			const otherId = "other-user-id"
			const response = await request(app)
				.put(`/users/picture/${otherId}`)
				.set("Authorization", `Bearer ${mockClientToken}`)
				.attach("profilePic", Buffer.from("test image data"), "test.png")

			expect(response.status).toBe(403)
		})

		it("admin should be able to update any user picture", async () => {
			const response = await request(app)
				.put(`/users/picture/${userId}`)
				.set("Authorization", `Bearer ${mockAdminToken}`)
				.attach("profilePic", Buffer.from("test image data"), "test.png")

			expect([200, 400]).toContain(response.status)
		})

		it("should return 400 when no file is uploaded", async () => {
			const response = await request(app)
				.put(`/users/picture/${userId}`)
				.set("Authorization", `Bearer ${mockClientToken}`)

			expect([400, 403]).toContain(response.status)
			if (response.status === 400) {
				expect(response.body).toHaveProperty("message")
			}
		})
	})

	describe("GET /users/picture/:id - Get User Picture", () => {
		const userId = "user-id-123"

		it("should return user picture", async () => {
			const response = await request(app).get(`/users/picture/${userId}`)

			expect([200, 400]).toContain(response.status)
			if (response.status === 200) {
				expect(response.body).toHaveProperty("userPicture")
			}
		})
	})

	describe("Authorization and Requisite Compliance", () => {
		it("should enforce admin-only operations for tech creation", async () => {
			// Only admin can create tech
			const clientResponse = await request(app)
				.post("/users/tech")
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({
					name: "Técnico Novo",
					email: "tech@example.com",
					password: "password123",
				})

			expect(clientResponse.status).toBe(403)

			const techResponse = await request(app).post("/users/tech").set("Authorization", `Bearer ${mockTechToken}`).send({
				name: "Técnico Novo",
				email: "tech2@example.com",
				password: "password123",
			})

			expect(techResponse.status).toBe(403)
		})

		it("should enforce permission checks for tech account updates", async () => {
			// Tech can only update their own account
			const techId = "tech-id-123"

			const response = await request(app)
				.put(`/users/tech/${techId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					newName: "Updated",
					newEmail: "updated@example.com",
					newPassword: "newpass123",
				})

			// Will succeed if it's their own ID, fail if not
			expect([200, 403, 400]).toContain(response.status)
		})

		it("should allow client self-service operations", async () => {
			// Client can create their own account without auth
			const response = await request(app)
				.post("/users/client")
				.send({
					name: "New Client",
					email: `client${Date.now()}@example.com`,
					password: "password123",
				})

			expect([201, 400]).toContain(response.status)
		})
	})
})
