import { sql } from "../../src/db/connection.ts"

/**
 * Clear all data from test database
 */
export async function cleanupTestDatabase() {
	try {
		// Get all tables except migration table
		// biome-ignore lint/suspicious/noExplicitAny: <any is ok>
		const result: any[] = await sql`
      SELECT tablename FROM pg_tables 
      WHERE schemaname = 'public'
    `

		const tables = result.map((row) => row.tablename)

		if (tables.length > 0) {
			// Disable foreign keys temporarily
			await sql`SET session_replication_role = REPLICA`

			// Truncate all tables
			for (const table of tables) {
				await sql.unsafe(`TRUNCATE TABLE "${table}" CASCADE`)
			}

			// Re-enable foreign keys
			await sql`SET session_replication_role = DEFAULT`
		}
	} catch (error) {
		console.error("Failed to cleanup test database:", error)
		throw error
	}
}

/**
 * Close database connection
 */
export async function closeTestDatabase() {
	try {
		await sql.end()
	} catch (error) {
		console.error("Failed to close test database:", error)
		throw error
	}
}
