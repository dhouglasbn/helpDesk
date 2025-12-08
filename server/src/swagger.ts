import swaggerJsdoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";

const options = {
	definition: {
		openapi: "3.0.0",
		info: {
			title: "HelpDesk API",
			version: "1.0.0",
			description: "Documentação da API do HelpDesk.",
		},
		components: {
			securitySchemes: {
				bearerAuth: {
					type: "http",
					scheme: "bearer",
					bearerFormat: "JWT",
				},
			},
		},
	},

	// Caminhos dos arquivos onde estão suas rotas com comentários JSDoc
	apis: ["./src/docs/*.ts"], // ajuste se seus arquivos estiverem em outro lugar
};

export const swaggerSpec = swaggerJsdoc(options);
export const swaggerUiMiddleware = swaggerUi;
