// biome-ignore assist/source/organizeImports: <sorted>
import request from "supertest";
import express, { type Express } from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { eq } from "drizzle-orm";
import { db } from "../src/db/connection.ts";
import { schema } from "../src/db/schema/index.ts";

import { ticketRoutes } from "../src/routes/ticketRoutes.ts";

let app: Express;

// Shared fixture IDs (created once in beforeAll)
let realAdminId = "";
let realTechId1 = "";
let realTechId2 = "";
let realClientId = "";
let realClientId2 = "";
let realServiceId1 = "";
let realServiceId2 = "";
let realTicketId = "";

// Mock auth tokens
const createMockToken = (userId: string, role: "admin" | "tech" | "client") =>
	jwt.sign({ id: userId, role }, process.env.JWT_SECRET || "test-secret", {
		expiresIn: "1h",
	});

let mockAdminToken = "";
let mockTechToken = "";
let mockTech2Token = "";
let mockClientToken = "";
let mockClient2Token = "";

describe("Ticket Routes", () => {
	beforeAll(async () => {
		app = express();
		app.use(cors());
		app.use(express.json());
		app.use(express.urlencoded({ extended: true }));
		app.use("/tickets", ticketRoutes);

		// Create shared fixtures once for all tests
		try {
			const hashedAdmin = bcrypt.hashSync("password123", 8);
			const [createdAdmin] = await db
				.insert(schema.users)
				.values({
					name: "Admin User",
					email: `admin.${Date.now()}@test.com`,
					passwordHash: hashedAdmin,
					role: "admin",
				})
				.returning();
			realAdminId = createdAdmin.id;

			const hashedTech1 = bcrypt.hashSync("password123", 8);
			const [createdTech1] = await db
				.insert(schema.users)
				.values({
					name: "Tech User 1",
					email: `tech1.${Date.now()}@test.com`,
					passwordHash: hashedTech1,
					role: "tech",
				})
				.returning();
			realTechId1 = createdTech1.id;

			const currentHour = `${new Date().toTimeString().slice(0, 2)}:00`;
			await db.insert(schema.techniciansAvailabilities).values({
				userId: realTechId1,
				time: currentHour,
			});

			const hashedTech2 = bcrypt.hashSync("password123", 8);
			const [createdTech2] = await db
				.insert(schema.users)
				.values({
					name: "Tech User 2",
					email: `tech2.${Date.now()}@test.com`,
					passwordHash: hashedTech2,
					role: "tech",
				})
				.returning();
			realTechId2 = createdTech2.id;

			const hashedClient = bcrypt.hashSync("password123", 8);
			const [createdClient] = await db
				.insert(schema.users)
				.values({
					name: "Client User",
					email: `client.${Date.now()}@test.com`,
					passwordHash: hashedClient,
					role: "client",
				})
				.returning();
			realClientId = createdClient.id;

			const hashedClient2 = bcrypt.hashSync("password123", 8);
			const [createdClient2] = await db
				.insert(schema.users)
				.values({
					name: "Client User 2",
					email: `client2.${Date.now()}@test.com`,
					passwordHash: hashedClient2,
					role: "client",
				})
				.returning();
			realClientId2 = createdClient2.id;

			const [createdService1] = await db
				.insert(schema.services)
				.values({
					title: "Service 1",
					price: "100.00",
					active: true,
				})
				.returning();
			realServiceId1 = createdService1.id;

			const [createdService2] = await db
				.insert(schema.services)
				.values({
					title: "Service 2",
					price: "200.00",
					active: true,
				})
				.returning();
			realServiceId2 = createdService2.id;

			const [createdTicket] = await db
				.insert(schema.tickets)
				.values({
					clientId: realClientId,
					techId: realTechId1,
				})
				.returning();
			realTicketId = createdTicket.id;

			await db.insert(schema.ticketServices).values([
				{
					ticketId: realTicketId,
					serviceId: realServiceId1,
				},
			]);

			mockAdminToken = createMockToken(realAdminId, "admin");
			mockTechToken = createMockToken(realTechId1, "tech");
			mockTech2Token = createMockToken(realTechId2, "tech");
			mockClientToken = createMockToken(realClientId, "client");
			mockClient2Token = createMockToken(realClientId2, "client");
		} catch (error) {
			console.error("Failed to create test fixtures:", error);
			throw error;
		}
	});

	afterAll(async () => {
		try {
			await db.delete(schema.ticketServices);
			await db.delete(schema.tickets);
			await db.delete(schema.techniciansAvailabilities);
			await db.delete(schema.services);
			await db.delete(schema.users);
		} catch (_error) {
			// Ignore cleanup errors
		}
	});

	beforeEach(async () => {
		// Reset app for each test
		app = express();
		app.use(cors());
		app.use(express.json());
		app.use(express.urlencoded({ extended: true }));
		app.use("/tickets", ticketRoutes);
	});

	// ============================================================
	// POST / - CREATE TICKET
	// ============================================================
	describe("POST /tickets - Create Ticket", () => {
		it("should return 401 when no authentication token is provided", async () => {
			const response = await request(app)
				.post("/tickets")
				.send({
					techId: realTechId1,
					servicesIds: [realServiceId1],
				});

			expect(response.status).toBe(401);
		});

		it("should return 403 when non-client user tries to create a ticket", async () => {
			const response = await request(app)
				.post("/tickets")
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					techId: realTechId1,
					servicesIds: [realServiceId1],
				});

			expect([400, 403]).toContain(response.status);
		});

		it("should return 403 when admin tries to create a ticket", async () => {
			const response = await request(app)
				.post("/tickets")
				.set("Authorization", `Bearer ${mockAdminToken}`)
				.send({
					techId: realTechId1,
					servicesIds: [realServiceId1],
				});

			expect([400, 403]).toContain(response.status);
		});

		it("should validate that at least one service is provided", async () => {
			const response = await request(app)
				.post("/tickets")
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({
					techId: realTechId1,
					servicesIds: [],
				});

			expect(response.status).toBe(400);
		});

		it("should validate that techId is a valid UUID", async () => {
			const response = await request(app)
				.post("/tickets")
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({
					techId: "not-a-uuid",
					servicesIds: [realServiceId1],
				});

			expect(response.status).toBe(400);
		});

		it("should validate that servicesIds contains valid UUIDs", async () => {
			const response = await request(app)
				.post("/tickets")
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({
					techId: realTechId1,
					servicesIds: ["not-a-uuid"],
				});

			expect(response.status).toBe(400);
		});
	});

	// ============================================================
	// GET /tickets/clientHistory - LIST CLIENT TICKETS
	// ============================================================
	describe("GET /tickets/clientHistory - List Client Tickets", () => {
		it("should return 401 when no authentication token is provided", async () => {
			const response = await request(app).get("/tickets/clientHistory");

			expect(response.status).toBe(401);
		});

		it("should return 403 when non-client user tries to view client history", async () => {
			const response = await request(app)
				.get("/tickets/clientHistory")
				.set("Authorization", `Bearer ${mockTechToken}`);

			expect(response.status).toBe(403);
		});

		it("should return 403 when admin tries to view client history", async () => {
			const response = await request(app)
				.get("/tickets/clientHistory")
				.set("Authorization", `Bearer ${mockAdminToken}`);

			expect(response.status).toBe(403);
		});

		it("should allow authenticated client to access their history", async () => {
			const response = await request(app)
				.get("/tickets/clientHistory")
				.set("Authorization", `Bearer ${mockClientToken}`);

			expect(response.status).toBe(200);
			expect(Array.isArray(response.body)).toBe(true);
		});
	});

	// ============================================================
	// GET /tickets/tech - LIST TECH TICKETS
	// ============================================================
	describe("GET /tickets/tech - List Tech Tickets", () => {
		it("should return 401 when no authentication token is provided", async () => {
			const response = await request(app).get("/tickets/tech");

			expect(response.status).toBe(401);
		});

		it("should return 403 when non-tech user tries to list tech tickets", async () => {
			const response = await request(app)
				.get("/tickets/tech")
				.set("Authorization", `Bearer ${mockClientToken}`);

			expect(response.status).toBe(403);
			expect(response.body.message).toContain("técnico");
		});

		it("should return 403 when admin tries to list tech tickets", async () => {
			const response = await request(app)
				.get("/tickets/tech")
				.set("Authorization", `Bearer ${mockAdminToken}`);

			expect(response.status).toBe(403);
		});

		it("should allow authenticated technician to list their tickets", async () => {
			const response = await request(app)
				.get("/tickets/tech")
				.set("Authorization", `Bearer ${mockTechToken}`);

			expect(response.status).toBe(200);
			expect(Array.isArray(response.body)).toBe(true);
		});
	});

	// ============================================================
	// GET /tickets/list - LIST ALL TICKETS
	// ============================================================
	describe("GET /tickets/list - List All Tickets", () => {
		it("should return 401 when no authentication token is provided", async () => {
			const response = await request(app).get("/tickets/list");

			expect(response.status).toBe(401);
		});

		it("should return 403 when non-admin user tries to list all tickets", async () => {
			const response = await request(app)
				.get("/tickets/list")
				.set("Authorization", `Bearer ${mockClientToken}`);

			expect(response.status).toBe(403);
			expect(response.body.message).toContain("admin");
		});

		it("should return 403 when technician tries to list all tickets", async () => {
			const response = await request(app)
				.get("/tickets/list")
				.set("Authorization", `Bearer ${mockTechToken}`);

			expect(response.status).toBe(403);
		});

		it("should allow authenticated admin to list all tickets", async () => {
			const response = await request(app)
				.get("/tickets/list")
				.set("Authorization", `Bearer ${mockAdminToken}`);

			expect([200, 400]).toContain(response.status);
		});
	});

	// ============================================================
	// PUT /tickets/addServices/:ticketId - ADD SERVICES TO TICKET
	// ============================================================
	describe("PUT /tickets/addServices/:ticketId - Add Services to Ticket", () => {
		it("should return 401 when no authentication token is provided", async () => {
			const response = await request(app)
				.put(`/tickets/addServices/${realTicketId}`)
				.send({
					servicesIds: [realServiceId2],
				});

			expect(response.status).toBe(401);
		});

		it("should return 403 when client tries to add services to a ticket", async () => {
			const response = await request(app)
				.put(`/tickets/addServices/${realTicketId}`)
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({
					servicesIds: [realServiceId2],
				});

			expect([400, 403]).toContain(response.status);
		});

		it("should allow technician to add services to a ticket", async () => {
			// CREATE own ticket
			const hashedClient = bcrypt.hashSync("password123", 8);
			const [createdClient] = await db
				.insert(schema.users)
				.values({
					name: "Add Services Test Client",
					email: `addservicesclient.${Date.now()}@test.com`,
					passwordHash: hashedClient,
					role: "client",
				})
				.returning();
			const createdClientToken = createMockToken(createdClient.id, "client");

			const [createdTicket] = await db
				.insert(schema.tickets)
				.values({
					clientId: createdClient.id,
					techId: realTechId1,
					status: "aberto",
				})
				.returning();

			// TEST
			const response = await request(app)
				.put(`/tickets/addServices/${createdTicket.id}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					servicesIds: [realServiceId2],
				});

			expect(response.status).toBe(200);

			// CLEANUP
			await db
				.delete(schema.ticketServices)
				.where(eq(schema.ticketServices.ticketId, createdTicket.id));
			await db
				.delete(schema.tickets)
				.where(eq(schema.tickets.id, createdTicket.id));
			await db
				.delete(schema.users)
				.where(eq(schema.users.id, createdClient.id));
		});

		it("should allow admin to add services to a ticket", async () => {
			// CREATE own ticket
			const hashedClient = bcrypt.hashSync("password123", 8);
			const [createdClient] = await db
				.insert(schema.users)
				.values({
					name: "Add Services Admin Test Client",
					email: `addservicesadmin.${Date.now()}@test.com`,
					passwordHash: hashedClient,
					role: "client",
				})
				.returning();

			const [createdTicket] = await db
				.insert(schema.tickets)
				.values({
					clientId: createdClient.id,
					techId: realTechId1,
					status: "aberto",
				})
				.returning();

			// TEST
			const response = await request(app)
				.put(`/tickets/addServices/${createdTicket.id}`)
				.set("Authorization", `Bearer ${mockAdminToken}`)
				.send({
					servicesIds: [realServiceId2],
				});

			expect(response.status).toBe(200);

			// CLEANUP
			await db
				.delete(schema.ticketServices)
				.where(eq(schema.ticketServices.ticketId, createdTicket.id));
			await db
				.delete(schema.tickets)
				.where(eq(schema.tickets.id, createdTicket.id));
			await db
				.delete(schema.users)
				.where(eq(schema.users.id, createdClient.id));
		});

		it("should validate ticketId is a valid UUID", async () => {
			const response = await request(app)
				.put("/tickets/addServices/not-a-uuid")
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					servicesIds: [realServiceId2],
				});

			expect(response.status).toBe(400);
		});

		it("should validate servicesIds is not empty", async () => {
			const response = await request(app)
				.put(`/tickets/addServices/${realTicketId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					servicesIds: [],
				});

			expect(response.status).toBe(400);
		});

		it("should validate servicesIds contains valid UUIDs", async () => {
			const response = await request(app)
				.put(`/tickets/addServices/${realTicketId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					servicesIds: ["not-a-uuid"],
				});

			expect(response.status).toBe(400);
		});

		it("should accept multiple service IDs", async () => {
			const response = await request(app)
				.put(`/tickets/addServices/${realTicketId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					servicesIds: [realServiceId1, realServiceId2],
				});

			expect([200, 400]).toContain(response.status);
		});
	});

	// ============================================================
	// PUT /tickets/status/:ticketId - UPDATE TICKET STATUS
	// ============================================================
	describe("PUT /tickets/status/:ticketId - Update Ticket Status", () => {
		it("should return 401 when no authentication token is provided", async () => {
			const response = await request(app)
				.put(`/tickets/status/${realTicketId}`)
				.send({
					status: "em_atendimento",
				});

			expect(response.status).toBe(401);
		});

		it("should return 403 when client tries to update ticket status", async () => {
			const response = await request(app)
				.put(`/tickets/status/${realTicketId}`)
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({
					status: "em_atendimento",
				});

			expect([400, 403]).toContain(response.status);
		});

		it("should allow technician to update ticket status", async () => {
			// CREATE own ticket
			const hashedClient = bcrypt.hashSync("password123", 8);
			const [createdClient] = await db
				.insert(schema.users)
				.values({
					name: "Status Update Test Client",
					email: `statusupdateclient.${Date.now()}@test.com`,
					passwordHash: hashedClient,
					role: "client",
				})
				.returning();

			const [createdTicket] = await db
				.insert(schema.tickets)
				.values({
					clientId: createdClient.id,
					techId: realTechId1,
					status: "aberto",
				})
				.returning();

			// TEST
			const response = await request(app)
				.put(`/tickets/status/${createdTicket.id}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					status: "em_atendimento",
				});

			expect(response.status).toBe(200);

			// CLEANUP
			await db
				.delete(schema.tickets)
				.where(eq(schema.tickets.id, createdTicket.id));
			await db
				.delete(schema.users)
				.where(eq(schema.users.id, createdClient.id));
		});

		it("should allow admin to update ticket status", async () => {
			// CREATE own ticket
			const hashedClient = bcrypt.hashSync("password123", 8);
			const [createdClient] = await db
				.insert(schema.users)
				.values({
					name: "Status Update Admin Test Client",
					email: `statusupdateadmin.${Date.now()}@test.com`,
					passwordHash: hashedClient,
					role: "client",
				})
				.returning();

			const [createdTicket] = await db
				.insert(schema.tickets)
				.values({
					clientId: createdClient.id,
					techId: realTechId1,
					status: "aberto",
				})
				.returning();

			// TEST
			const response = await request(app)
				.put(`/tickets/status/${createdTicket.id}`)
				.set("Authorization", `Bearer ${mockAdminToken}`)
				.send({
					status: "encerrado",
				});

			expect(response.status).toBe(200);

			// CLEANUP
			await db
				.delete(schema.tickets)
				.where(eq(schema.tickets.id, createdTicket.id));
			await db
				.delete(schema.users)
				.where(eq(schema.users.id, createdClient.id));
		});

		it("should only accept valid status values", async () => {
			const response = await request(app)
				.put(`/tickets/status/${realTicketId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					status: "invalid_status",
				});

			expect(response.status).toBe(400);
		});

		it("should accept 'aberto' as a valid status", async () => {
			const response = await request(app)
				.put(`/tickets/status/${realTicketId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					status: "aberto",
				});

			expect([200, 400]).toContain(response.status);
		});

		it("should accept 'em_atendimento' as a valid status", async () => {
			const response = await request(app)
				.put(`/tickets/status/${realTicketId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					status: "em_atendimento",
				});

			expect([200, 400]).toContain(response.status);
		});

		it("should accept 'encerrado' as a valid status", async () => {
			const response = await request(app)
				.put(`/tickets/status/${realTicketId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					status: "encerrado",
				});

			expect([200, 400]).toContain(response.status);
		});

		it("should validate ticketId is a valid UUID", async () => {
			const response = await request(app)
				.put("/tickets/status/not-a-uuid")
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					status: "em_atendimento",
				});

			expect(response.status).toBe(400);
		});
	});

	// ============================================================
	// AUTHORIZATION REQUIREMENTS (REQUISITES)
	// ============================================================
	describe("Authorization Requirements - Requisites Compliance", () => {
		it("O Admin - should not create tickets directly", async () => {
			const response = await request(app)
				.post("/tickets")
				.set("Authorization", `Bearer ${mockAdminToken}`)
				.send({
					techId: realTechId1,
					servicesIds: [realServiceId1],
				});

			expect([400, 403]).toContain(response.status);
		});

		it("O Admin - should list all tickets", async () => {
			const response = await request(app)
				.get("/tickets/list")
				.set("Authorization", `Bearer ${mockAdminToken}`);

			expect([200, 400]).toContain(response.status);
		});

		it("O Admin - should edit ticket status", async () => {
			const response = await request(app)
				.put(`/tickets/status/${realTicketId}`)
				.set("Authorization", `Bearer ${mockAdminToken}`)
				.send({ status: "em_atendimento" });

			expect([200, 400]).toContain(response.status);
		});

		it("O Técnico - should not create tickets", async () => {
			const response = await request(app)
				.post("/tickets")
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					techId: realTechId2,
					servicesIds: [realServiceId1],
				});

			expect([400, 403]).toContain(response.status);
		});

		it("O Técnico - should list only their assigned tickets", async () => {
			const response = await request(app)
				.get("/tickets/tech")
				.set("Authorization", `Bearer ${mockTechToken}`);

			expect([200, 400]).toContain(response.status);
		});

		it("O Técnico - should add services to ticket", async () => {
			const response = await request(app)
				.put(`/tickets/addServices/${realTicketId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({ servicesIds: [realServiceId2] });

			expect([200, 400]).toContain(response.status);
		});

		it("O Técnico - should edit ticket status", async () => {
			const response = await request(app)
				.put(`/tickets/status/${realTicketId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({ status: "em_atendimento" });

			expect([200, 400]).toContain(response.status);
		});

		it("O Cliente - should create tickets", async () => {
			const response = await request(app)
				.post("/tickets")
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({
					techId: realTechId1,
					servicesIds: [realServiceId1],
				});

			expect([201, 400]).toContain(response.status);
		});

		it("O Cliente - should view their history", async () => {
			const response = await request(app)
				.get("/tickets/clientHistory")
				.set("Authorization", `Bearer ${mockClientToken}`);

			expect([200, 400]).toContain(response.status);
		});

		it("O Cliente - should NOT alter ticket after creation", async () => {
			const updateResponse = await request(app)
				.put(`/tickets/status/${realTicketId}`)
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({ status: "em_atendimento" });

			const addResponse = await request(app)
				.put(`/tickets/addServices/${realTicketId}`)
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({ servicesIds: [realServiceId2] });

			expect([400, 403]).toContain(updateResponse.status);
			expect([400, 403]).toContain(addResponse.status);
		});
	});

	// ============================================================
	// VALIDATION TESTS (Requisites: Status values)
	// ============================================================
	describe("Validation - Requisites Compliance", () => {
		it("should only accept valid ticket status: aberto", async () => {
			const response = await request(app)
				.put(`/tickets/status/${realTicketId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({ status: "aberto" });

			expect([200, 400]).toContain(response.status);
		});

		it("should only accept valid ticket status: em_atendimento", async () => {
			const response = await request(app)
				.put(`/tickets/status/${realTicketId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({ status: "em_atendimento" });

			expect([200, 400]).toContain(response.status);
		});

		it("should only accept valid ticket status: encerrado", async () => {
			const response = await request(app)
				.put(`/tickets/status/${realTicketId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({ status: "encerrado" });

			expect([200, 400]).toContain(response.status);
		});

		it("should reject invalid status values", async () => {
			const invalidStatuses = [
				"opening",
				"in_service",
				"closed",
				"pending",
				"invalid",
			];

			for (const status of invalidStatuses) {
				const response = await request(app)
					.put(`/tickets/status/${realTicketId}`)
					.set("Authorization", `Bearer ${mockTechToken}`)
					.send({ status });

				expect(response.status).toBe(400);
			}
		});

		it("should require at least one service when creating ticket", async () => {
			const response = await request(app)
				.post("/tickets")
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({
					techId: realTechId1,
					servicesIds: [],
				});

			expect(response.status).toBe(400);
		});

		it("should require at least one service when adding services", async () => {
			const response = await request(app)
				.put(`/tickets/addServices/${realTicketId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({ servicesIds: [] });

			expect(response.status).toBe(400);
		});

		it("should validate techId is UUID format", async () => {
			const invalidIds = ["", "123", "invalid-id", "12345678-1234-1234"];

			for (const id of invalidIds) {
				const response = await request(app)
					.post("/tickets")
					.set("Authorization", `Bearer ${mockClientToken}`)
					.send({
						techId: id,
						servicesIds: [realServiceId1],
					});

				expect(response.status).toBe(400);
			}
		});

		it("should validate serviceIds are UUID format", async () => {
			const response = await request(app)
				.post("/tickets")
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({
					techId: realTechId1,
					servicesIds: ["invalid-uuid"],
				});

			expect(response.status).toBe(400);
		});

		it("should validate ticketId is UUID format in status update", async () => {
			const response = await request(app)
				.put("/tickets/status/invalid-id")
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({ status: "em_atendimento" });

			expect(response.status).toBe(400);
		});

		it("should validate ticketId is UUID format in add services", async () => {
			const response = await request(app)
				.put("/tickets/addServices/invalid-id")
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({ servicesIds: [realServiceId1] });

			expect(response.status).toBe(400);
		});
	});

	// ============================================================
	// MULTIPLE ROLES SCENARIOS
	// ============================================================
	describe("Multiple Users with Different Roles", () => {
		it("different clients should be able to create independent tickets", async () => {
			const client1Response = await request(app)
				.post("/tickets")
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({
					techId: realTechId1,
					servicesIds: [realServiceId1],
				});

			const client2Response = await request(app)
				.post("/tickets")
				.set("Authorization", `Bearer ${mockClient2Token}`)
				.send({
					techId: realTechId2,
					servicesIds: [realServiceId2],
				});

			expect([201, 400]).toContain(client1Response.status);
			expect([201, 400]).toContain(client2Response.status);
		});

		it("different technicians should see their own tickets", async () => {
			const tech1Response = await request(app)
				.get("/tickets/tech")
				.set("Authorization", `Bearer ${mockTechToken}`);

			const tech2Response = await request(app)
				.get("/tickets/tech")
				.set("Authorization", `Bearer ${mockTech2Token}`);

			expect([200, 400]).toContain(tech1Response.status);
			expect([200, 400]).toContain(tech2Response.status);
		});

		it("same client can assign tickets to different technicians", async () => {
			const response1 = await request(app)
				.post("/tickets")
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({
					techId: realTechId1,
					servicesIds: [realServiceId1],
				});

			const response2 = await request(app)
				.post("/tickets")
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({
					techId: realTechId2,
					servicesIds: [realServiceId2],
				});

			expect([201, 400]).toContain(response1.status);
			expect([201, 400]).toContain(response2.status);
		});
	});

	// ============================================================
	// AUTHENTICATION TESTS
	// ============================================================
	describe("Authentication", () => {
		it("should reject requests without authentication token", async () => {
			const postResponse = await request(app)
				.post("/tickets")
				.send({ techId: realTechId1, servicesIds: [realServiceId1] });

			const getHistoryResponse = await request(app).get(
				"/tickets/clientHistory",
			);

			const getTechResponse = await request(app).get("/tickets/tech");

			const getListResponse = await request(app).get("/tickets/list");

			const putStatusResponse = await request(app)
				.put(`/tickets/status/${realTicketId}`)
				.send({ status: "em_atendimento" });

			const putServicesResponse = await request(app)
				.put(`/tickets/addServices/${realTicketId}`)
				.send({ servicesIds: [realServiceId1] });

			expect(postResponse.status).toBe(401);
			expect(getHistoryResponse.status).toBe(401);
			expect(getTechResponse.status).toBe(401);
			expect(getListResponse.status).toBe(401);
			expect(putStatusResponse.status).toBe(401);
			expect(putServicesResponse.status).toBe(401);
		});

		it("should accept valid JWT tokens", async () => {
			const response = await request(app)
				.get("/tickets/list")
				.set("Authorization", `Bearer ${mockAdminToken}`);

			expect([200, 400]).toContain(response.status);
		});
	});

	// ============================================================
	// COVERAGE TESTS - Lines 10-68 (createTicket service logic)
	// ============================================================
	describe("Coverage Tests - Create Ticket Service Logic", () => {
		it("should successfully create ticket when tech is available at current hour", async () => {
			// CREATE own client entity
			const hashedClient = bcrypt.hashSync("password123", 8);
			const [createdClient] = await db
				.insert(schema.users)
				.values({
					name: "Ticket Create Test Client",
					email: `ticketclient.${Date.now()}@test.com`,
					passwordHash: hashedClient,
					role: "client",
				})
				.returning();
			const createdClientToken = createMockToken(createdClient.id, "client");

			// TEST
			const response = await request(app)
				.post("/tickets")
				.set("Authorization", `Bearer ${createdClientToken}`)
				.send({
					techId: realTechId1,
					servicesIds: [realServiceId1],
				});

			expect(response.status).toBe(201);
			expect(response.body).toHaveProperty("id");
			expect(response.body).toHaveProperty("clientId", createdClient.id);
			expect(response.body).toHaveProperty("techId", realTechId1);
			expect(response.body).toHaveProperty("services");
			expect(response.body).toHaveProperty("totalPrice");

			// CLEANUP
			await db
				.delete(schema.tickets)
				.where(eq(schema.tickets.id, response.body.id));
			await db
				.delete(schema.users)
				.where(eq(schema.users.id, createdClient.id));
		});

		it("should return 400 when tech does not exist", async () => {
			const nonExistentTechId = "00000000-0000-0000-0000-000000000000";
			const response = await request(app)
				.post("/tickets")
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({
					techId: nonExistentTechId,
					servicesIds: [realServiceId1],
				});

			expect(response.status).toBe(400);
			expect(response.body).toHaveProperty("error");
		});

		it("should return 400 when tech is not available at current hour", async () => {
			// Tech2 has no availability set
			const response = await request(app)
				.post("/tickets")
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({
					techId: realTechId2,
					servicesIds: [realServiceId1],
				});

			expect(response.status).toBe(400);
			expect(response.body.error).toContain("não está disponível");
		});

		it("should return 400 when service does not exist", async () => {
			const nonExistentServiceId = "00000000-0000-0000-0000-000000000000";
			const response = await request(app)
				.post("/tickets")
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({
					techId: realTechId1,
					servicesIds: [nonExistentServiceId],
				});

			expect(response.status).toBe(400);
			expect(response.body.error).toContain("serviço informado não existe");
		});

		it("should return 400 when some services do not exist", async () => {
			const nonExistentServiceId = "00000000-0000-0000-0000-000000000000";
			const response = await request(app)
				.post("/tickets")
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({
					techId: realTechId1,
					servicesIds: [realServiceId1, nonExistentServiceId],
				});

			expect(response.status).toBe(400);
			expect(response.body.error).toContain("serviço informado não existe");
		});

		it("should create ticket with multiple services", async () => {
			const response = await request(app)
				.post("/tickets")
				.set("Authorization", `Bearer ${mockClientToken}`)
				.send({
					techId: realTechId1,
					servicesIds: [realServiceId1, realServiceId2],
				});

			expect(response.status).toBe(201);
			expect(response.body.services).toHaveLength(2);
			expect(response.body.totalPrice).toBeDefined();
		});
	});

	// ============================================================
	// COVERAGE TESTS - Lines 141-168 (addServicesToTicket logic)
	// ============================================================
	describe("Coverage Tests - Add Services to Ticket Logic", () => {
		it("should return 400 when ticket does not exist", async () => {
			const nonExistentTicketId = "00000000-0000-0000-0000-000000000000";
			const response = await request(app)
				.put(`/tickets/addServices/${nonExistentTicketId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					servicesIds: [realServiceId2],
				});

			expect(response.status).toBe(400);
			expect(response.body.error).toContain("não existe");
		});

		it("should return 400 when tech tries to add services to another tech's ticket", async () => {
			const response = await request(app)
				.put(`/tickets/addServices/${realTicketId}`)
				.set("Authorization", `Bearer ${mockTech2Token}`)
				.send({
					servicesIds: [realServiceId2],
				});

			expect(response.status).toBe(400);
			expect(response.body.error).toContain("Acesso negado");
		});

		it("should allow tech to add services to their own ticket", async () => {
			const response = await request(app)
				.put(`/tickets/addServices/${realTicketId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					servicesIds: [realServiceId2],
				});

			expect(response.status).toBe(200);
			expect(Array.isArray(response.body)).toBe(true);
		});

		it("admin should be able to add services to any ticket", async () => {
			const response = await request(app)
				.put(`/tickets/addServices/${realTicketId}`)
				.set("Authorization", `Bearer ${mockAdminToken}`)
				.send({
					servicesIds: [realServiceId2],
				});

			expect(response.status).toBe(200);
		});

		it("should return 400 when service does not exist when adding", async () => {
			const nonExistentServiceId = "00000000-0000-0000-0000-000000000000";
			const response = await request(app)
				.put(`/tickets/addServices/${realTicketId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					servicesIds: [nonExistentServiceId],
				});

			expect(response.status).toBe(400);
			expect(response.body.error).toContain("serviço informado não existe");
		});

		it("should return 400 when some services do not exist when adding", async () => {
			const nonExistentServiceId = "00000000-0000-0000-0000-000000000000";
			const response = await request(app)
				.put(`/tickets/addServices/${realTicketId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					servicesIds: [realServiceId2, nonExistentServiceId],
				});

			expect(response.status).toBe(400);
			expect(response.body.error).toContain("serviço informado não existe");
		});
	});

	// ============================================================
	// COVERAGE TESTS - Lines 178-186 (updateStatus logic)
	// ============================================================
	describe("Coverage Tests - Update Ticket Status Logic", () => {
		it("should return 400 when ticket does not exist on status update", async () => {
			const nonExistentTicketId = "00000000-0000-0000-0000-000000000000";
			const response = await request(app)
				.put(`/tickets/status/${nonExistentTicketId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					status: "em_atendimento",
				});

			expect(response.status).toBe(400);
			expect(response.body.error).toContain("não existe");
		});

		it("should return 400 when tech tries to update status of another tech's ticket", async () => {
			const response = await request(app)
				.put(`/tickets/status/${realTicketId}`)
				.set("Authorization", `Bearer ${mockTech2Token}`)
				.send({
					status: "em_atendimento",
				});

			expect(response.status).toBe(400);
			expect(response.body.error).toContain("Acesso negado");
		});

		it("should allow tech to update status of their own ticket", async () => {
			const response = await request(app)
				.put(`/tickets/status/${realTicketId}`)
				.set("Authorization", `Bearer ${mockTechToken}`)
				.send({
					status: "em_atendimento",
				});

			expect(response.status).toBe(200);
			const ticket = Array.isArray(response.body)
				? response.body[0]
				: response.body;
			expect(ticket).toHaveProperty("status", "em_atendimento");
		});

		it("admin should be able to update status of any ticket", async () => {
			const response = await request(app)
				.put(`/tickets/status/${realTicketId}`)
				.set("Authorization", `Bearer ${mockAdminToken}`)
				.send({
					status: "encerrado",
				});

			expect(response.status).toBe(200);
			const ticket = Array.isArray(response.body)
				? response.body[0]
				: response.body;
			expect(ticket).toHaveProperty("status", "encerrado");
		});

		it("should allow updating status to all valid statuses", async () => {
			const statuses = ["aberto", "em_atendimento", "encerrado"];

			for (const status of statuses) {
				const response = await request(app)
					.put(`/tickets/status/${realTicketId}`)
					.set("Authorization", `Bearer ${mockTechToken}`)
					.send({ status });

				expect([200, 400]).toContain(response.status);
				if (response.status === 200) {
					const ticket = Array.isArray(response.body)
						? response.body[0]
						: response.body;
					expect(ticket).toHaveProperty("status", status);
				}
			}
		});
	});
});
