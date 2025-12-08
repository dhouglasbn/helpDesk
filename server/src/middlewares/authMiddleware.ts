import { env } from "../env.ts";
import type { Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import type { OurRequest, UserInToken } from "../types/ourRequest.ts";

export function authMiddleware(
	request: OurRequest,
	reply: Response,
	next: NextFunction,
) {
	const JWT_SECRET = env.JWT_SECRET;
	const authHeader = request.headers.authorization;

	if (!authHeader) {
		return reply.status(401).json({ message: "Token não enviado" });
	}

	const [, token] = authHeader.split(" ");

	if (!token) {
		return reply.status(401).json({ message: "Token inválido" });
	}
	try {
		const decoded = jwt.verify(token, JWT_SECRET) as UserInToken;
		request.user = decoded; // salva info do usuário no request
		return next();
	} catch (err) {
		return reply.status(401).json({ error: "Token expirado ou inválido" });
	}
}
