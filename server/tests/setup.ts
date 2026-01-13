import fs from "node:fs"
import path from "node:path"

// Load .env.test file
const envTestPath = path.resolve(process.cwd(), ".env.test")
if (fs.existsSync(envTestPath)) {
	const envContent = fs.readFileSync(envTestPath, "utf-8")
	// biome-ignore lint/complexity/noForEach: <forEach is ok>
	envContent.split("\n").forEach((line) => {
		const [key, value] = line.split("=")
		if (key && value) {
			process.env[key.trim()] = value.trim()
		}
	})
}

// Set test mode
process.env.NODE_ENV = "test"

// Fallback values if not in .env.test
if (!process.env.DATABASE_URL) {
	process.env.DATABASE_URL = "postgres://docker:docker@localhost:5433/helpdesk_test"
}
if (!process.env.JWT_SECRET) {
	process.env.JWT_SECRET = "test-secret-key-for-testing"
}
