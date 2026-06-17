# Repository Guidelines

## Project Structure & Module Organization

Pepper is a Next.js 16 TypeScript security scanning app. App routes live in `src/app`, reusable React components in `src/components`, hooks in `src/hooks`, shared helpers in `src/lib`, and types in `src/types`. Scanner engines are organized by domain under `src/scanners` (`sast`, `sca`, `secrets`, `container`, `iac`, `dast`, `zero-day`, and `shared`). Background scan processing lives in `src/worker`. Prisma schema, seed data, and migrations are in `prisma`; generated Prisma client output is under `src/generated/prisma`. Static assets and generated docs are in `public`, with source docs in `docs`.

## Build, Test, and Development Commands

- `npm run dev`: start the local Next.js development server.
- `npm run build`: create a production build.
- `npm run start`: run the production server after building.
- `npm run lint`: run ESLint with Next core-web-vitals and TypeScript rules.
- `npm test`: run Vitest tests once.
- `npm run worker`: start the BullMQ scan worker.
- `npm run db:migrate`: create/apply Prisma migrations.
- `npm run db:deploy`: apply migrations in deployed environments.
- `npm run db:seed`: seed initial data from `prisma/seed.ts`.
- `npm run docker:up` / `npm run docker:down` / `npm run docker:build`: manage the Docker Compose stack.

## Coding Style & Naming Conventions

Use TypeScript throughout. Prefer the `@/` alias for imports from `src`. Keep React components in PascalCase files or existing kebab-case component files, and keep scanner utilities close to their scanner domain. Tests use `*.test.ts`. Follow the existing two-space indentation and double-quote style.

## Testing Guidelines

Vitest runs in a Node environment and includes `src/**/*.test.ts`. Add focused unit tests beside scanner, parser, or shared logic changes; examples include `src/scanners/diff-parser.test.ts` and `src/scanners/container/index.test.ts`. Run `npm test` before submitting changes, and `npm run lint` for UI, API route, or TypeScript-heavy edits.

## Commit & Pull Request Guidelines

Recent commits use imperative, concise subjects such as `Fix Redis ETIMEDOUT crash` and `Add PDF security assessment report matching Dapper format`. Follow that pattern: start with `Fix`, `Add`, `Update`, or similar, and describe the user-visible change. Pull requests should include a short summary, testing performed, linked issues when relevant, and screenshots for UI changes. Mention schema, environment, Docker, or worker changes explicitly.

## Security & Configuration Tips

Do not commit `.env`, credentials, tokens, scan artifacts, or customer data. Keep secrets in environment files or deployment secret stores. When changing Prisma schema, include a migration under `prisma/migrations` and note any required `npm run db:generate` or deployment steps.
