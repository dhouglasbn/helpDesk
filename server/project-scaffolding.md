What to include

- Install only Playwright test runner (no extra frameworks)
- Configure baseURL and a reasonable timout (at most 5 seconds)
- Create a tests/ directory
- CI: Github Actions workflow

Local setup

1. Install dev dependency

- npm i -D jest

2. Github Actions

- Create .github/workflows/playwright.yml with a job that:
  - Checks out the repo
  - Sets up Node.js
  - Runs npm ci
  - Runs npm test
