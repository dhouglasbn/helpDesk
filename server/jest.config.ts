export default {
	preset: "ts-jest",
	testEnvironment: "node",
	testMatch: ["**/tests/**/*.spec.ts"],
	moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json", "node"],
	collectCoverageFrom: ["src/**/*.ts", "!src/**/*.d.ts"],
	testTimeout: 10_000,
	setupFiles: ["<rootDir>/tests/setup.ts"],
}
