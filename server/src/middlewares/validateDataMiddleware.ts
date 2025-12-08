import type { Response, NextFunction } from "express";
import type { OurRequest } from "../types/ourRequest.ts";
import type { ZodType } from "zod/v4";

export function validateZodSchema<
	BodySchema extends ZodType<any> = ZodType<any>,
	ParamsSchema extends ZodType<any> = ZodType<any>,
	QuerySchema extends ZodType<any> = ZodType<any>,
>(
	bodySchema?: BodySchema,
	paramsSchema?: ParamsSchema,
	querySchema?: QuerySchema,
) {
	return (req: OurRequest, res: Response, next: NextFunction) => {
		if (bodySchema) {
			const bodyResult = bodySchema.safeParse(req.body);

			if (!bodyResult.success) {
				return res.status(400).json({
					message: "Erro de validação (req.body)",
					errors: bodyResult.error.issues.map((error) => error.message),
				});
			}

			req.body = bodyResult.data;
		}

		if (paramsSchema) {
			const paramsResult = paramsSchema.safeParse(req.params);
			if (!paramsResult.success) {
				return res.status(400).json({
					message: "Erro de validação (params)",
					errors: paramsResult.error.issues.map((error) => error.message),
				});
			}
			req.params = paramsResult.data;
		}

		if (querySchema) {
			const queryResult = querySchema.safeParse(req.query);
			if (!queryResult.success) {
				return res.status(400).json({
					message: "Erro de validação (query)",
					errors: queryResult.error.issues.map((error) => error.message),
				});
			}
			req.query = queryResult.data;
		}
		next();
	};
}
