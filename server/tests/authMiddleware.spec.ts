// biome-ignore assist/source/organizeImports: <sorted>
import jwt from "jsonwebtoken";
import { authMiddleware } from "../src/middlewares/authMiddleware.ts";
import type { Response, NextFunction } from "express";
import type { OurRequest } from "../src/types/ourRequest.ts";

jest.mock("jsonwebtoken");
jest.mock("../src/env.ts", () => ({
	env: {
		JWT_SECRET: "test-secret",
	},
}));

describe("authMiddleware", () => {
	let mockRequest: Partial<OurRequest>;
	let mockResponse: Partial<Response>;
	let mockNext: NextFunction;

	beforeEach(() => {
		mockRequest = {
			headers: {},
			user: undefined,
		};

		mockResponse = {
			status: jest.fn().mockReturnThis(),
			json: jest.fn().mockReturnThis(),
		};

		mockNext = jest.fn();
		jest.clearAllMocks();
	});

	describe("Missing or invalid authorization header", () => {
		it("should return 401 when authorization header is missing", () => {
			mockRequest.headers = {};

			const result = authMiddleware(
				mockRequest as OurRequest,
				mockResponse as Response,
				mockNext,
			);

			expect(mockResponse.status).toHaveBeenCalledWith(401);
			expect(mockResponse.json).toHaveBeenCalledWith({
				message: "Token não enviado",
			});
			expect(mockNext).not.toHaveBeenCalled();
			expect(result).toBeDefined();
		});

		it("should return 401 when authorization header is undefined", () => {
			mockRequest.headers = {
				authorization: undefined,
			};

			authMiddleware(
				mockRequest as OurRequest,
				mockResponse as Response,
				mockNext,
			);

			expect(mockResponse.status).toHaveBeenCalledWith(401);
			expect(mockResponse.json).toHaveBeenCalledWith({
				message: "Token não enviado",
			});
			expect(mockNext).not.toHaveBeenCalled();
		});

		it("should return 401 when authorization header is empty", () => {
			mockRequest.headers = {
				authorization: "",
			};

			authMiddleware(
				mockRequest as OurRequest,
				mockResponse as Response,
				mockNext,
			);

			expect(mockResponse.status).toHaveBeenCalledWith(401);
			expect(mockResponse.json).toHaveBeenCalledWith({
				message: "Token não enviado",
			});
			expect(mockNext).not.toHaveBeenCalled();
		});

		it("should return 401 when token is missing after Bearer", () => {
			mockRequest.headers = {
				authorization: "Bearer ",
			};

			authMiddleware(
				mockRequest as OurRequest,
				mockResponse as Response,
				mockNext,
			);

			expect(mockResponse.status).toHaveBeenCalledWith(401);
			expect(mockResponse.json).toHaveBeenCalledWith({
				message: "Token inválido",
			});
			expect(mockNext).not.toHaveBeenCalled();
		});

		it("should return 401 when authorization header has no Bearer prefix", () => {
			mockRequest.headers = {
				authorization: "token-without-bearer",
			};

			authMiddleware(
				mockRequest as OurRequest,
				mockResponse as Response,
				mockNext,
			);

			expect(mockResponse.status).toHaveBeenCalledWith(401);
			expect(mockResponse.json).toHaveBeenCalledWith({
				message: "Token inválido",
			});
			expect(mockNext).not.toHaveBeenCalled();
		});

		it("should return 401 when authorization uses different scheme", () => {
			mockRequest.headers = {
				authorization: "Basic dXNlcm5hbWU6cGFzc3dvcmQ=",
			};

			(jwt.verify as jest.Mock).mockImplementation(() => {
				throw new Error("Invalid token");
			});

			authMiddleware(
				mockRequest as OurRequest,
				mockResponse as Response,
				mockNext,
			);

			expect(mockResponse.status).toHaveBeenCalledWith(401);
			expect(mockResponse.json).toHaveBeenCalledWith({
				error: "Token expirado ou inválido",
			});
			expect(mockNext).not.toHaveBeenCalled();
		});
	});

	describe("Valid token", () => {
		it("should call next() when token is valid", () => {
			const decodedToken = {
				id: "user-123",
				role: "admin",
			};

			mockRequest.headers = {
				authorization: "Bearer valid-token",
			};

			(jwt.verify as jest.Mock).mockReturnValue(decodedToken as any);

			authMiddleware(
				mockRequest as OurRequest,
				mockResponse as Response,
				mockNext,
			);

			expect(jwt.verify).toHaveBeenCalledWith("valid-token", "test-secret");
			expect(mockRequest.user).toEqual(decodedToken);
			expect(mockNext).toHaveBeenCalled();
			expect(mockResponse.status).not.toHaveBeenCalled();
		});

		it("should set user data from decoded token", () => {
			const decodedToken = {
				id: "user-456",
				role: "client",
				iat: 1234567890,
				exp: 1234567890,
			};

			mockRequest.headers = {
				authorization: "Bearer another-token",
			};

			(jwt.verify as jest.Mock).mockReturnValue(decodedToken as any);

			authMiddleware(
				mockRequest as OurRequest,
				mockResponse as Response,
				mockNext,
			);

			expect(mockRequest.user).toEqual(decodedToken);
			expect(mockNext).toHaveBeenCalled();
		});

		it("should handle tokens with extra spaces in Bearer", () => {
			mockRequest.headers = {
				authorization: "Bearer  token-with-extra-space",
			};

			authMiddleware(
				mockRequest as OurRequest,
				mockResponse as Response,
				mockNext,
			);

			expect(mockResponse.status).toHaveBeenCalledWith(401);
			expect(mockResponse.json).toHaveBeenCalledWith({
				message: "Token inválido",
			});
			expect(mockNext).not.toHaveBeenCalled();
		});
	});

	describe("Invalid or expired token", () => {
		it("should return 401 when token verification fails", () => {
			mockRequest.headers = {
				authorization: "Bearer invalid-token",
			};

			(jwt.verify as jest.Mock).mockImplementation(() => {
				throw new Error("Token verification failed");
			});

			authMiddleware(
				mockRequest as OurRequest,
				mockResponse as Response,
				mockNext,
			);

			expect(mockResponse.status).toHaveBeenCalledWith(401);
			expect(mockResponse.json).toHaveBeenCalledWith({
				error: "Token expirado ou inválido",
			});
			expect(mockNext).not.toHaveBeenCalled();
		});

		it("should return 401 when token is expired", () => {
			mockRequest.headers = {
				authorization: "Bearer expired-token",
			};

			const expiredError = new Error("jwt expired");
			(jwt.verify as jest.Mock).mockImplementation(() => {
				throw expiredError;
			});

			authMiddleware(
				mockRequest as OurRequest,
				mockResponse as Response,
				mockNext,
			);

			expect(mockResponse.status).toHaveBeenCalledWith(401);
			expect(mockResponse.json).toHaveBeenCalledWith({
				error: "Token expirado ou inválido",
			});
			expect(mockNext).not.toHaveBeenCalled();
		});

		it("should return 401 when token signature is invalid", () => {
			mockRequest.headers = {
				authorization: "Bearer invalid-signature-token",
			};

			const signatureError = new Error("invalid signature");
			(jwt.verify as jest.Mock).mockImplementation(() => {
				throw signatureError;
			});

			authMiddleware(
				mockRequest as OurRequest,
				mockResponse as Response,
				mockNext,
			);

			expect(mockResponse.status).toHaveBeenCalledWith(401);
			expect(mockResponse.json).toHaveBeenCalledWith({
				error: "Token expirado ou inválido",
			});
			expect(mockNext).not.toHaveBeenCalled();
		});

		it("should return 401 when token format is invalid", () => {
			mockRequest.headers = {
				authorization: "Bearer malformed.token",
			};

			const formatError = new Error("invalid token format");
			(jwt.verify as jest.Mock).mockImplementation(() => {
				throw formatError;
			});

			authMiddleware(
				mockRequest as OurRequest,
				mockResponse as Response,
				mockNext,
			);

			expect(mockResponse.status).toHaveBeenCalledWith(401);
			expect(mockResponse.json).toHaveBeenCalledWith({
				error: "Token expirado ou inválido",
			});
			expect(mockNext).not.toHaveBeenCalled();
		});
	});

	describe("Edge cases", () => {
		it("should handle authorization header with multiple Bearer words", () => {
			mockRequest.headers = {
				authorization: "Bearer Bearer token",
			};

			(jwt.verify as jest.Mock).mockImplementation(() => {
				throw new Error("Invalid token");
			});

			authMiddleware(
				mockRequest as OurRequest,
				mockResponse as Response,
				mockNext,
			);

			expect(jwt.verify).toHaveBeenCalledWith("Bearer", "test-secret");
		});

		it("should handle case-sensitive Bearer prefix", () => {
			mockRequest.headers = {
				authorization: "bearer valid-token",
			};

			(jwt.verify as jest.Mock).mockImplementation(() => {
				throw new Error("Invalid token");
			});

			authMiddleware(
				mockRequest as OurRequest,
				mockResponse as Response,
				mockNext,
			);

			expect(jwt.verify).toHaveBeenCalledWith("valid-token", "test-secret");
			expect(mockNext).not.toHaveBeenCalled();
		});

		it("should not modify request if authorization fails", () => {
			mockRequest.headers = {
				authorization: "Bearer invalid",
			};

			const originalUser = mockRequest.user;

			(jwt.verify as jest.Mock).mockImplementation(() => {
				throw new Error("Invalid");
			});

			authMiddleware(
				mockRequest as OurRequest,
				mockResponse as Response,
				mockNext,
			);

			expect(mockRequest.user).toBe(originalUser);
		});

		it("should handle special characters in token", () => {
			mockRequest.headers = {
				authorization: "Bearer token!@#$%^&*()",
			};

			const decodedToken = {
				id: "user-special",
				role: "admin",
			};

			(jwt.verify as jest.Mock).mockReturnValue(decodedToken as any);

			authMiddleware(
				mockRequest as OurRequest,
				mockResponse as Response,
				mockNext,
			);

			expect(jwt.verify).toHaveBeenCalledWith("token!@#$%^&*()", "test-secret");
			expect(mockNext).toHaveBeenCalled();
		});

		it("should handle very long token", () => {
			const longToken = "Bearer " + "a".repeat(10000);

			mockRequest.headers = {
				authorization: longToken,
			};

			const decodedToken = { id: "user-long", role: "admin" };

			(jwt.verify as jest.Mock).mockReturnValue(decodedToken as any);

			authMiddleware(
				mockRequest as OurRequest,
				mockResponse as Response,
				mockNext,
			);

			expect(mockNext).toHaveBeenCalled();
		});
	});
});
