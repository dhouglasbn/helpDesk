# Test Database Setup and Isolation

## Overview

Your tests now use an isolated PostgreSQL test database separate from your development database. This ensures that:

- ✅ Tests don't modify your development data
- ✅ Tests can run in parallel safely
- ✅ Database state is independent and clean
- ✅ Tests are deterministic and repeatable

## Database Configuration

### Docker Compose Services

Two PostgreSQL databases are configured in `docker-compose.yml`:

1. **Development Database (`pg`)**
   - Port: `5432`
   - Database: `helpdesk`
   - User: `docker`
   - Password: `docker`

2. **Test Database (`pg_test`)**
   - Port: `5433`
   - Database: `helpdesk_test`
   - User: `docker`
   - Password: `docker`

### Environment Variables

Two `.env` files configure the application:

1. **`.env`** - Development environment
   ```
   DATABASE_URL=postgres://docker:docker@localhost:5432/helpdesk
   PORT=3333
   JWT_SECRET=sensacaoSensacional
   ```

2. **`.env.test`** - Test environment
   ```
   DATABASE_URL=postgres://docker:docker@localhost:5433/helpdesk_test
   PORT=3333
   JWT_SECRET=test-secret-key-for-testing
   ```

## Starting the Test Database

```bash
# Start both development and test databases
docker compose up -d

# Stop containers
docker compose down

# Remove all volumes and restart fresh
docker compose down -v
docker compose up -d
```

## Running Tests

```bash
# Run all tests with isolated database
npm test

# Run tests with coverage
npm run test:cov

# Run specific test file
npm test -- tests/userRoutes.spec.ts
```

## How Test Isolation Works

### 1. Environment Loading (`tests/setup.ts`)
- Automatically loads `.env.test` before tests run
- Sets `NODE_ENV=test`
- Provides fallback values if env file is missing

### 2. Test Database Connection
- All tests connect to `postgres://docker:docker@localhost:5433/helpdesk_test`
- The connection is separate from development database
- Database schema is automatically initialized via Docker entrypoint scripts

### 3. Data Isolation
- Each test can create/modify data without affecting other tests
- The database persists between test runs (for debugging)
- To reset database to fresh state: `docker compose down -v && docker compose up -d`

## Jest Configuration

In `jest.config.ts`:
```typescript
{
  setupFiles: ["<rootDir>/tests/setup.ts"],
  testTimeout: 10000,  // Sufficient time for DB operations
  // ... other config
}
```

The `setupFiles` option ensures environment variables are loaded before any tests run.

## Key Files

- **`docker-compose.yml`** - Defines pg and pg_test services
- **`.env.test`** - Test database connection string
- **`tests/setup.ts`** - Loads test environment and configures DB
- **`tests/setup/database.ts`** - Database utility functions for cleanup
- **`jest.config.ts`** - Jest configuration with setup files

## Debugging

### Check if test database is running
```bash
docker compose ps
```

### View test database logs
```bash
docker compose logs pg_test
```

### Connect to test database directly
```bash
# From your machine
psql postgresql://docker:docker@localhost:5433/helpdesk_test

# Or via docker
docker compose exec pg_test psql -U docker helpdesk_test
```

### Reset test database to fresh state
```bash
docker compose down -v  # Remove volumes
docker compose up -d    # Recreate with seed data
npm test                # Run tests
```

## Notes

- Tests use real database operations through actual service layer (not mocked)
- This provides comprehensive integration testing
- The test database is automatically seeded with migrations from `docker/` directory
- Database connection is managed by the actual application code
- Tests are isolated by separate database, not transaction rollbacks

## Next Steps

To further improve test isolation, consider:

1. **Add per-test cleanup** - Use `beforeEach()` to clear specific tables
2. **Database snapshots** - Save database state for faster resets
3. **Parallel test execution** - With separate schemas per worker
4. **CI/CD integration** - GitHub Actions workflows with test database
