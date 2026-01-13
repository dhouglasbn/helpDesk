import { cleanupTestDatabase } from './setup/database.ts';

/**
 * Setup before each test suite
 */
export async function setupSuite() {
  // Clean database before each suite
  await cleanupTestDatabase();
}

export default setupSuite;
