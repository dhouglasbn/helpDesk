import { cleanupTestDatabase, closeTestDatabase } from "./setup/database.ts"

/**
 * Global setup - runs once before all tests
 */
export async function globalSetup() {
	console.log("\n=== Starting Test Suite ===\n")
	await cleanupTestDatabase()
}

/**
 * Global teardown - runs once after all tests
 */
export async function globalTeardown() {
	console.log("\n=== Ending Test Suite ===\n")
	await closeTestDatabase()
}
