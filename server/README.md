<h1 align="center">
  <br>
  HelpDesk API
</h1>

<p align="center">
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License MIT">
  </a>
</p>
</h1>

<p>
  Uma API REST construída em Node.js, utilizando TypeScript, Drizzle ORM, validação com Zod, autenticação via JWT, documentação com Swagger, e banco de dados PostgreSQL.
  O objetivo do projeto é fornecer um backend organizado e escalável para um sistema de gerenciamento para técnicos prestarem serviços para seus clientes.
</p>

# 📌 Tecnologias Utilizadas
## Backend

- Node.js
- TypeScript
- Express
- Zod (validação de entrada)
- bcryptjs (hash de senha)
- jsonwebtoken (autenticação JWT)
- SwaggerJSdoc + SwaggerUI (documentação)
- PostgreSQL (banco de dados)
- Drizzle ORM
- Migrations
  - Seed
  - Transações
  - Schemas tipados

## Ferramentas de Desenvolvimento

- ts-node / tsx
- tsconfig paths
- ESLint
- BiomeJs

# 🎯 Objetivo da Aplicação

A API fornece recursos essenciais para um sistema de helpdesk interno:

- Criação e autenticação de usuários
- Registro e listagem de serviços
- Abertura e gerenciamento de tickets
- Associação de múltiplos serviços a um ticket
- Consultas agregadas e relações entre tabelas
- Documentação clara via Swagger
- Padronização robusta de erros e validações

Tudo isso seguindo boas práticas como:

- Camada de serviço
- Padronização de respostas HTTP
- Repositórios isolados
- Schemas validados
- Transações com Drizzle

# 🔐 Autenticação

A autenticação é baseada em JWT Bearer Token.

Fluxo:

- Usuário se registra ou faz login
- Recebe token JWT
- Envia Authorization: Bearer <token>
- Middleware valida e autoriza acesso

# 📚 Documentação Swagger

A documentação está disponível em:

```
GET /docs
```

---

# 🚀 Como Executar o Projeto
1. Clonar o repositório
``` bash
git clone https://github.com/dhouglasbn/helpDesk.git
cd helpDesk
```

2. Instalar dependências
``` bash
npm install
```

3. Configurar variáveis de ambiente

Crie um arquivo .env:

```bash
  DATABASE_URL=postgres://docker:docker@localhost:5432/helpdesk
  JWT_SECRET=batata
  PORT=3333
```

4. Rodar os containers docker
``` bash
docker compose up -d
```

5. Rodar o generate do drizzle
``` bash
npm run db:generate
```

6. Rodar migrations
``` bash
npm run db:migrate
```

7. Rodar seeds
``` bash
npm run db:seed
```

8. Iniciar servidor
``` bash
npm run dev
```

---

# Contribuições

Contribuições são bem vindas! Abra uma issue e submeta um pull request.

# 📄 Licença

[MIT License](https://opensource.org/licenses/MIT)
