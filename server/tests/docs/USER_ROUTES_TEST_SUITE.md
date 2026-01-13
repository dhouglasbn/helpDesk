# User Routes Test Suite

## Overview

A comprehensive Jest test suite for all user routes in the helpdesk API, ensuring compliance with the system's requisites and proper authorization checks.

## Test Coverage

### 45 Total Tests covering:

#### 1. **POST /users/login** (3 tests)

- Successful login returns token
- Invalid credentials handling
- Missing email validation

#### 2. **POST /users/tech** - Create Tech Account (3 tests)

- Only admin can create tech accounts (role enforcement)
- Token validation (401 when missing)
- Field validation (name length, email format, password length)

#### 3. **GET /users/techList** - List Tech Accounts (3 tests)

- Only admin can list technicians
- Proper authentication required
- Returns array of technicians when authorized

#### 4. **PUT /users/tech/:id** - Update Tech Account (4 tests)

- Tech/Admin authorization
- Tech can only update their own account (non-admin restriction)
- Admin can update any tech account
- Field validation for updates

#### 5. **PUT /users/techAvailabilities/:id** - Update Tech Availabilities (4 tests)

- Tech/Admin authorization
- Time format validation (HH:00 format, 00-23 range)
- At least one availability time required
- Proper error handling for invalid formats

#### 6. **PUT /users/admin/:id** - Update Admin Account (3 tests)

- Only admin can update admin accounts
- Proper authentication required
- Field validation for admin updates

#### 7. **POST /users/client** - Create Client Account (3 tests)

- Client accounts can be created without authentication
- Field validation enforcement
- Duplicate email rejection

#### 8. **PUT /users/client/:id** - Update Client Account (5 tests)

- Client/Admin authorization
- Client can only update their own account
- Admin can update any client account
- Proper field validation
- Authentication requirement

#### 9. **GET /users/clientList** - List Client Accounts (3 tests)

- Only admin can list clients
- Proper authentication required
- Returns array of clients when authorized

#### 10. **DELETE /users/client/:id** - Delete Client Account (5 tests)

- Client/Admin authorization
- Client can only delete their own account
- Admin can delete any client account
- Proper authentication requirement
- Tech cannot delete client accounts

#### 11. **PUT /users/picture/:id** - Update User Picture (5 tests)

- Authentication required
- User can update their own picture
- User cannot update another user's picture (non-admin)
- Admin can update any user's picture
- File upload validation (must have file)

#### 12. **GET /users/picture/:id** - Get User Picture (1 test)

- Retrieves user picture

#### 13. **Authorization and Requisite Compliance** (3 tests)

- Admin-only operations enforcement
- Permission checks for tech updates
- Client self-service operations

## Requisite Compliance

✅ **Admin Operations**

- Can create, list, and edit tech accounts
- Can create, list, edit, and delete client accounts
- Can manage system services
- Can list all tickets and edit their status
- Can update any user's profile picture
- Can manage tech availabilities

✅ **Tech Operations**

- Can edit their own profile
- Can upload profile picture
- Can list their assigned tickets
- Can update tech availabilities (their own or admin can update)
- Cannot create or delete client accounts
- Cannot create tickets

✅ **Client Operations**

- Can create client account without authentication
- Can edit their own profile
- Can upload profile picture
- Can create tickets
- Can view ticket history
- Cannot update other client accounts
- Cannot alter tickets after creation

## Running Tests

```bash
# Run all tests
npm test

# Run user routes tests only
npm test -- tests/userRoutes.spec.ts

# Run with coverage
npm test -- --coverage
```

## Test Configuration

- **Framework**: Jest with TypeScript support (ts-jest)
- **HTTP Testing**: Supertest for Express testing
- **Environment**: Node.js
- **Test Timeout**: 5 seconds per test
- **Environment Variables**: Pre-set for testing (JWT_SECRET, DATABASE_URL)

## Mock Tokens

The test suite uses JWT tokens with mock data for different user roles:

- Admin token: `{ id: 'admin-id-123', role: 'admin' }`
- Tech token: `{ id: 'tech-id-123', role: 'tech' }`
- Client token: `{ id: 'client-id-123', role: 'client' }`

These allow testing authorization logic without hitting the database.

## Notes

- Tests use `supertest` to make HTTP requests to Express app
- Validation errors may return 400 before reaching authorization checks
- Tests account for both authorization errors (403) and validation errors (400)
- All tests respect the requisites defined in `requisites.md`
