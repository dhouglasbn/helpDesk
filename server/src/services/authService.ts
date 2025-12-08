import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { env } from "../env.ts";
import { db } from "../db/connection.ts";
import { schema } from "../db/schema/index.ts";
import { eq } from "drizzle-orm";

export default class AuthService {
	// Métodos do serviço de autenticação podem ser adicionados aqui
	authenticate = async (email: string, password: string) => {
		const user = await db.query.users.findFirst({
			where: eq(schema.users.email, email),
		});
		if (!user) {
			throw new Error("Credenciais inválidas");
		}

		const ok = await bcrypt.compare(password, user.passwordHash);
		if (!ok) {
			throw new Error("Credenciais inválidas");
		}

		// Gera o token
		return jwt.sign(
			{ id: user.id, email: user.email, role: user.role },
			env.JWT_SECRET,
			{
				expiresIn: "1h",
			},
		);
	};
}
