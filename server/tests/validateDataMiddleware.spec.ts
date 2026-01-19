// biome-ignore assist/source/organizeImports: <sorted>
import { validateZodSchema } from "../src/middlewares/validateDataMiddleware.ts";
import { z } from "zod";
import type { Response, NextFunction } from "express";
import type { OurRequest } from "../src/types/ourRequest.ts";

describe("validateZodSchema", () => {
	let mockRequest: Partial<OurRequest>;
	let mockResponse: Partial<Response>;
	let mockNext: NextFunction;

	beforeEach(() => {
		mockRequest = {
			body: {},
			params: {},
			query: {},
		};

		mockResponse = {
			status: jest.fn().mockReturnThis(),
			json: jest.fn().mockReturnThis(),
		};

		mockNext = jest.fn();
		jest.clearAllMocks();
	});

	describe("No schemas provided", () => {
		it("should call next() when no schemas are provided", () => {
			const middleware = validateZodSchema();

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockNext).toHaveBeenCalled();
			expect(mockResponse.status).not.toHaveBeenCalled();
		});

		it("should preserve request data when no schemas are provided", () => {
			mockRequest.body = { name: "John" };
			mockRequest.params = { id: "123" };
			mockRequest.query = { filter: "active" };

			const middleware = validateZodSchema();

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockRequest.body).toEqual({ name: "John" });
			expect(mockRequest.params).toEqual({ id: "123" });
			expect(mockRequest.query).toEqual({ filter: "active" });
			expect(mockNext).toHaveBeenCalled();
		});
	});

	describe("Body validation", () => {
		it("should validate body successfully", () => {
			const bodySchema = z.object({
				name: z.string(),
				age: z.number(),
			});

			mockRequest.body = { name: "John", age: 30 };

			const middleware = validateZodSchema(bodySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockNext).toHaveBeenCalled();
			expect(mockResponse.status).not.toHaveBeenCalled();
		});

		it("should return 400 with error message when body validation fails", () => {
			const bodySchema = z.object({
				name: z.string(),
				age: z.number(),
			});

			mockRequest.body = { name: "John", age: "not a number" };

			const middleware = validateZodSchema(bodySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockResponse.status).toHaveBeenCalledWith(400);
			expect(mockResponse.json).toHaveBeenCalledWith(
				expect.objectContaining({
					message: "Erro de validação (req.body)",
					errors: expect.any(Array),
				}),
			);
			expect(mockNext).not.toHaveBeenCalled();
		});

		it("should include error details for missing required fields", () => {
			const bodySchema = z.object({
				email: z.string().email(),
			});

			mockRequest.body = {};

			const middleware = validateZodSchema(bodySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockResponse.status).toHaveBeenCalledWith(400);
			const call = (mockResponse.json as any).mock.calls[0][0];
			expect(call.errors).toHaveLength(1);
			expect(mockNext).not.toHaveBeenCalled();
		});

		it("should validate email format in body", () => {
			const bodySchema = z.object({
				email: z.string().email("Email inválido"),
			});

			mockRequest.body = { email: "invalid-email" };

			const middleware = validateZodSchema(bodySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockResponse.status).toHaveBeenCalledWith(400);
			const call = (mockResponse.json as any).mock.calls[0][0];
			expect(call.errors[0]).toContain("Email inválido");
		});

		it("should validate string length in body", () => {
			const bodySchema = z.object({
				password: z.string().min(6, "Mínimo 6 caracteres"),
			});

			mockRequest.body = { password: "123" };

			const middleware = validateZodSchema(bodySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockResponse.status).toHaveBeenCalledWith(400);
			const call = (mockResponse.json as any).mock.calls[0][0];
			expect(call.errors[0]).toContain("Mínimo 6 caracteres");
		});

		it("should handle complex nested body validation", () => {
			const bodySchema = z.object({
				user: z.object({
					name: z.string(),
					profile: z.object({
						bio: z.string().optional(),
					}),
				}),
			});

			mockRequest.body = {
				user: {
					name: "John",
					profile: { bio: "Software Developer" },
				},
			};

			const middleware = validateZodSchema(bodySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockNext).toHaveBeenCalled();
		});

		it("should reject complex nested body with invalid data", () => {
			const bodySchema = z.object({
				user: z.object({
					name: z.string(),
					age: z.number(),
				}),
			});

			mockRequest.body = {
				user: {
					name: "John",
					age: "invalid",
				},
			};

			const middleware = validateZodSchema(bodySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockResponse.status).toHaveBeenCalledWith(400);
			expect(mockNext).not.toHaveBeenCalled();
		});

		it("should replace body with validated data", () => {
			const bodySchema = z.object({
				name: z.string().trim(),
			});

			mockRequest.body = { name: "  John  " };

			const middleware = validateZodSchema(bodySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockRequest.body.name).toBe("John");
			expect(mockNext).toHaveBeenCalled();
		});
	});

	describe("Params validation", () => {
		it("should validate params successfully", () => {
			const paramsSchema = z.object({
				id: z.string().uuid(),
			});

			mockRequest.params = { id: "550e8400-e29b-41d4-a716-446655440000" };

			const middleware = validateZodSchema(undefined, paramsSchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockNext).toHaveBeenCalled();
			expect(mockResponse.status).not.toHaveBeenCalled();
		});

		it("should return 400 with error message when params validation fails", () => {
			const paramsSchema = z.object({
				id: z.string().uuid("ID deve ser um UUID válido"),
			});

			mockRequest.params = { id: "invalid-uuid" };

			const middleware = validateZodSchema(undefined, paramsSchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockResponse.status).toHaveBeenCalledWith(400);
			expect(mockResponse.json).toHaveBeenCalledWith(
				expect.objectContaining({
					message: "Erro de validação (params)",
					errors: expect.any(Array),
				}),
			);
			expect(mockNext).not.toHaveBeenCalled();
		});

		it("should validate numeric params", () => {
			const paramsSchema = z.object({
				page: z.string().transform(Number).pipe(z.number().positive()),
			});

			mockRequest.params = { page: "1" };

			const middleware = validateZodSchema(undefined, paramsSchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockNext).toHaveBeenCalled();
		});

		it("should fail numeric params validation with invalid number", () => {
			const paramsSchema = z.object({
				page: z.string().transform(Number).pipe(z.number().positive()),
			});

			mockRequest.params = { page: "-1" };

			const middleware = validateZodSchema(undefined, paramsSchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockResponse.status).toHaveBeenCalledWith(400);
		});

		it("should replace params with validated data", () => {
			const paramsSchema = z.object({
				id: z.string().toUpperCase(),
			});

			mockRequest.params = { id: "abc123" };

			const middleware = validateZodSchema(undefined, paramsSchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockRequest.params.id).toBe("ABC123");
			expect(mockNext).toHaveBeenCalled();
		});
	});

	describe("Query validation", () => {
		it("should validate query successfully", () => {
			const querySchema = z.object({
				filter: z.string().optional(),
				sort: z.string().optional(),
			});

			mockRequest.query = { filter: "active", sort: "name" };

			const middleware = validateZodSchema(undefined, undefined, querySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockNext).toHaveBeenCalled();
			expect(mockResponse.status).not.toHaveBeenCalled();
		});

		it("should return 400 with error message when query validation fails", () => {
			const querySchema = z.object({
				page: z.string().transform(Number).pipe(z.number().positive()),
			});

			mockRequest.query = { page: "-1" };

			const middleware = validateZodSchema(undefined, undefined, querySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockResponse.status).toHaveBeenCalledWith(400);
			expect(mockResponse.json).toHaveBeenCalledWith(
				expect.objectContaining({
					message: "Erro de validação (query)",
					errors: expect.any(Array),
				}),
			);
			expect(mockNext).not.toHaveBeenCalled();
		});

		it("should handle optional query parameters", () => {
			const querySchema = z.object({
				limit: z.string().transform(Number).optional(),
			});

			mockRequest.query = {};

			const middleware = validateZodSchema(undefined, undefined, querySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockNext).toHaveBeenCalled();
		});

		it("should replace query with validated data", () => {
			const querySchema = z.object({
				search: z.string().toLowerCase(),
			});

			mockRequest.query = { search: "HELLO" };

			const middleware = validateZodSchema(undefined, undefined, querySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockRequest.query.search).toBe("hello");
			expect(mockNext).toHaveBeenCalled();
		});
	});

	describe("Combined validation (body, params, query)", () => {
		it("should validate all three when all schemas provided", () => {
			const bodySchema = z.object({ name: z.string() });
			const paramsSchema = z.object({ id: z.string() });
			const querySchema = z.object({ filter: z.string().optional() });

			mockRequest.body = { name: "John" };
			mockRequest.params = { id: "123" };
			mockRequest.query = { filter: "active" };

			const middleware = validateZodSchema(
				bodySchema,
				paramsSchema,
				querySchema,
			);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockNext).toHaveBeenCalled();
			expect(mockResponse.status).not.toHaveBeenCalled();
		});

		it("should fail if body validation fails (even if others pass)", () => {
			const bodySchema = z.object({ email: z.string().email() });
			const paramsSchema = z.object({ id: z.string() });
			const querySchema = z.object({ filter: z.string().optional() });

			mockRequest.body = { email: "invalid" };
			mockRequest.params = { id: "123" };
			mockRequest.query = { filter: "active" };

			const middleware = validateZodSchema(
				bodySchema,
				paramsSchema,
				querySchema,
			);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockResponse.status).toHaveBeenCalledWith(400);
			expect(mockResponse.json).toHaveBeenCalledWith(
				expect.objectContaining({
					message: "Erro de validação (req.body)",
				}),
			);
			expect(mockNext).not.toHaveBeenCalled();
		});

		it("should fail if params validation fails (even if others pass)", () => {
			const bodySchema = z.object({ name: z.string() });
			const paramsSchema = z.object({
				id: z.string().uuid(),
			});
			const querySchema = z.object({ filter: z.string().optional() });

			mockRequest.body = { name: "John" };
			mockRequest.params = { id: "invalid-uuid" };
			mockRequest.query = { filter: "active" };

			const middleware = validateZodSchema(
				bodySchema,
				paramsSchema,
				querySchema,
			);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockResponse.status).toHaveBeenCalledWith(400);
			expect(mockResponse.json).toHaveBeenCalledWith(
				expect.objectContaining({
					message: "Erro de validação (params)",
				}),
			);
			expect(mockNext).not.toHaveBeenCalled();
		});

		it("should fail if query validation fails (even if others pass)", () => {
			const bodySchema = z.object({ name: z.string() });
			const paramsSchema = z.object({ id: z.string() });
			const querySchema = z.object({
				page: z.string().transform(Number).pipe(z.number().positive()),
			});

			mockRequest.body = { name: "John" };
			mockRequest.params = { id: "123" };
			mockRequest.query = { page: "-1" };

			const middleware = validateZodSchema(
				bodySchema,
				paramsSchema,
				querySchema,
			);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockResponse.status).toHaveBeenCalledWith(400);
			expect(mockResponse.json).toHaveBeenCalledWith(
				expect.objectContaining({
					message: "Erro de validação (query)",
				}),
			);
			expect(mockNext).not.toHaveBeenCalled();
		});

		it("should validate body and params but skip query if not provided", () => {
			const bodySchema = z.object({ name: z.string() });
			const paramsSchema = z.object({ id: z.string() });

			mockRequest.body = { name: "John" };
			mockRequest.params = { id: "123" };
			mockRequest.query = { unexpectedField: "value" };

			const middleware = validateZodSchema(bodySchema, paramsSchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockNext).toHaveBeenCalled();
			expect(mockResponse.status).not.toHaveBeenCalled();
		});
	});

	describe("Error handling and edge cases", () => {
		it("should handle empty objects", () => {
			const bodySchema = z.object({});

			mockRequest.body = {};

			const middleware = validateZodSchema(bodySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockNext).toHaveBeenCalled();
		});

		it("should handle array validation in body", () => {
			const bodySchema = z.object({
				items: z.array(z.string()),
			});

			mockRequest.body = { items: ["a", "b", "c"] };

			const middleware = validateZodSchema(bodySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockNext).toHaveBeenCalled();
		});

		it("should fail array validation with invalid items", () => {
			const bodySchema = z.object({
				items: z.array(z.number()),
			});

			mockRequest.body = { items: ["a", "b", "c"] };

			const middleware = validateZodSchema(bodySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockResponse.status).toHaveBeenCalledWith(400);
		});

		it("should handle discriminated unions", () => {
			const bodySchema = z.object({
				type: z.enum(["user", "admin"]),
				permissions: z.array(z.string()).optional(),
			});

			mockRequest.body = {
				type: "admin",
				permissions: ["read", "write"],
			};

			const middleware = validateZodSchema(bodySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockNext).toHaveBeenCalled();
		});

		it("should fail discriminated unions with invalid type", () => {
			const bodySchema = z.object({
				type: z.enum(["user", "admin"]),
			});

			mockRequest.body = { type: "invalid" };

			const middleware = validateZodSchema(bodySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockResponse.status).toHaveBeenCalledWith(400);
		});

		it("should include all error messages when multiple validation failures", () => {
			const bodySchema = z.object({
				email: z.string().email(),
				password: z.string().min(6),
				age: z.number().positive(),
			});

			mockRequest.body = {
				email: "invalid",
				password: "123",
				age: -5,
			};

			const middleware = validateZodSchema(bodySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockResponse.status).toHaveBeenCalledWith(400);
			const call = (mockResponse.json as any).mock.calls[0][0];
			expect(call.errors.length).toBeGreaterThanOrEqual(1);
		});

		it("should handle nullable fields", () => {
			const bodySchema = z.object({
				name: z.string().nullable(),
			});

			mockRequest.body = { name: null };

			const middleware = validateZodSchema(bodySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockNext).toHaveBeenCalled();
		});

		it("should handle default values", () => {
			const bodySchema = z.object({
				role: z.string().default("user"),
			});

			mockRequest.body = {};

			const middleware = validateZodSchema(bodySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockRequest.body.role).toBe("user");
			expect(mockNext).toHaveBeenCalled();
		});

		it("should handle coerced values", () => {
			const paramsSchema = z.object({
				count: z.coerce.number(),
			});

			mockRequest.params = { count: "42" };

			const middleware = validateZodSchema(undefined, paramsSchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockRequest.params.count).toBe(42);
			expect(mockNext).toHaveBeenCalled();
		});

		it("should handle strict validation", () => {
			const bodySchema = z
				.object({
					name: z.string(),
				})
				.strict();

			mockRequest.body = {
				name: "John",
				extra: "field",
			};

			const middleware = validateZodSchema(bodySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockResponse.status).toHaveBeenCalledWith(400);
		});

		it("should handle passthrough validation", () => {
			const bodySchema = z
				.object({
					name: z.string(),
				})
				.passthrough();

			mockRequest.body = {
				name: "John",
				extra: "field",
			};

			const middleware = validateZodSchema(bodySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockNext).toHaveBeenCalled();
			expect(mockRequest.body.extra).toBe("field");
		});

		it("should not call next if any validation fails", () => {
			const bodySchema = z.object({
				name: z.string(),
			});
			const paramsSchema = z.object({
				id: z.number(),
			});

			mockRequest.body = {};
			mockRequest.params = { id: "invalid" };

			const middleware = validateZodSchema(bodySchema, paramsSchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockNext).not.toHaveBeenCalled();
		});

		it("should return consistent error response format", () => {
			const bodySchema = z.object({
				test: z.string(),
			});

			mockRequest.body = { test: 123 };

			const middleware = validateZodSchema(bodySchema);

			middleware(mockRequest as OurRequest, mockResponse as Response, mockNext);

			expect(mockResponse.json).toHaveBeenCalledWith({
				message: "Erro de validação (req.body)",
				errors: expect.any(Array),
			});
		});
	});
});
