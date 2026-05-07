import "dotenv/config";
import { PrismaClient } from "../src/generated/prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import pg from "pg";
import bcrypt from "bcryptjs";

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL! });
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

async function main() {
  console.log("Seeding database...");

  const llmProvider = process.env.LLM_PROVIDER || "openrouter";
  const llmBaseUrl =
    process.env.LLM_BASE_URL || "https://openrouter.ai/api/v1";
  const llmModel = process.env.LLM_MODEL || "google/gemini-2.5-flash";
  const llmApiKey = process.env.LLM_API_KEY;

  // Create default organization
  const org = await prisma.organization.upsert({
    where: { slug: "default" },
    update: {},
    create: {
      name: "Default Organization",
      slug: "default",
    },
  });
  console.log(`Organization: ${org.name} (${org.id})`);

  // Create org settings
  await prisma.orgSettings.upsert({
    where: { organizationId: org.id },
    update: {
      llmProvider,
      llmBaseUrl,
      llmModel,
      ...(llmApiKey ? { llmApiKey } : {}),
    },
    create: {
      organizationId: org.id,
      llmProvider,
      llmBaseUrl,
      llmModel,
      ...(llmApiKey ? { llmApiKey } : {}),
    },
  });

  // Create admin user
  const email = process.env.ADMIN_EMAIL || "admin@pepper.local";
  const password = process.env.ADMIN_PASSWORD || "pepper-admin-changeme";
  const passwordHash = await bcrypt.hash(password, 12);

  const admin = await prisma.user.upsert({
    where: { email },
    update: { passwordHash },
    create: {
      email,
      name: "Admin",
      passwordHash,
    },
  });
  console.log(`Admin user: ${admin.email} (${admin.id})`);

  // Create org membership
  await prisma.orgMember.upsert({
    where: {
      userId_organizationId: {
        userId: admin.id,
        organizationId: org.id,
      },
    },
    update: { role: "ADMIN" },
    create: {
      userId: admin.id,
      organizationId: org.id,
      role: "ADMIN",
    },
  });

  // Create a sample project
  const project = await prisma.project.upsert({
    where: { id: "sample-project" },
    update: {},
    create: {
      id: "sample-project",
      name: "Sample Project",
      description: "A sample project for testing scans",
      organizationId: org.id,
    },
  });

  // Create default build gate for sample project
  await prisma.buildGate.upsert({
    where: { projectId: project.id },
    update: {},
    create: {
      projectId: project.id,
      maxCritical: 0,
      maxHigh: 5,
      maxMedium: 20,
      maxLow: -1,
    },
  });

  console.log(`Sample project: ${project.name} (${project.id})`);

  // Create sample security policies
  const samplePolicies = [
    {
      name: "No hardcoded API URLs",
      rule: "Flag any hardcoded HTTP/HTTPS API endpoint URLs in source code (e.g. 'https://api.example.com/v1/users'). All API URLs must come from environment variables or configuration files. Exceptions: localhost URLs in development/test files, documentation strings, and comment-only references.",
      severity: "MEDIUM" as const,
      category: "Configuration",
    },
    {
      name: "PII must be encrypted at rest",
      rule: "Any code that writes personally identifiable information (PII) to a database — including email addresses, phone numbers, SSN, date of birth, physical addresses, IP addresses, or government IDs — must encrypt the data before storage OR use an encrypted column type. Flag direct writes of PII fields to database tables, ORM .create()/.save() calls, or raw INSERT/UPDATE queries that include PII without encryption.",
      severity: "HIGH" as const,
      category: "Data Privacy",
    },
    {
      name: "No direct DB queries in route handlers",
      rule: "Route handlers, controllers, and API endpoint functions must NOT contain direct database queries (raw SQL, Prisma calls, Sequelize calls, Mongoose calls, TypeORM calls). All data access must go through a separate service layer, repository, or data access module. Flag any file in routes/, controllers/, pages/api/, or app/api/ that imports and uses a database client directly.",
      severity: "MEDIUM" as const,
      category: "Architecture",
    },
    {
      name: "All public endpoints must have rate limiting",
      rule: "Every HTTP route handler that is publicly accessible (not behind authentication middleware) must have rate limiting middleware applied. Flag route definitions that handle GET/POST/PUT/DELETE requests without rate limiting. Common rate limit middleware: express-rate-limit, @nestjs/throttler, fastify-rate-limit, Django ratelimit, Flask-Limiter.",
      severity: "HIGH" as const,
      category: "Security",
    },
    {
      name: "No sensitive data in log output",
      rule: "Log statements (console.log, console.error, logger.info, logger.debug, logging.info, log.Printf, etc.) must NOT include passwords, API keys, tokens, credit card numbers, SSNs, session IDs, or JWT tokens. Flag any log statement that directly logs variables named password, secret, token, apiKey, sessionId, creditCard, ssn, authorization, or Bearer tokens. Exception: masked/redacted values (e.g. '***', first 4 chars only) are acceptable.",
      severity: "CRITICAL" as const,
      category: "Compliance",
    },
    {
      name: "Async operations must have error handling",
      rule: "All async/await calls and Promise chains must have proper error handling. Flag: await calls not inside try/catch blocks, .then() chains without .catch(), unhandled Promise rejections. This applies to database operations, HTTP requests, file I/O, and any external service calls. Exception: top-level await in scripts/seeds is acceptable.",
      severity: "MEDIUM" as const,
      category: "Reliability",
    },
    {
      name: "No wildcard CORS origins in production",
      rule: "CORS configuration must NOT use wildcard (*) for Access-Control-Allow-Origin in production code. Flag: cors({ origin: '*' }), cors({ origin: true }), res.setHeader('Access-Control-Allow-Origin', '*'), @CrossOrigin without specific origins. Exception: files explicitly named with 'dev', 'test', or 'local' in their path.",
      severity: "HIGH" as const,
      category: "Security",
    },
    {
      name: "File uploads must validate type and size",
      rule: "Any file upload handler must validate both the file MIME type/extension (via allowlist, NOT blocklist) and enforce a maximum file size limit. Flag upload handlers (multer, formidable, busboy, Django FileField, Flask request.files) that accept files without checking the file type against an explicit allowlist AND without a size limit. Both checks are required.",
      severity: "HIGH" as const,
      category: "Security",
    },
    {
      name: "Object-level authorization required",
      rule: "Any API route, controller, serializer, view, resolver, or service that reads, updates, deletes, exports, or returns a user-owned resource must verify object-level authorization before returning or mutating the object. Flag code that fetches records by id, pk, uuid, slug, invoiceId, orderId, studentId, userId, projectId, scanId, findingId, or organizationId without checking ownership, membership, tenant, role, or permission for that exact object.",
      severity: "CRITICAL" as const,
      category: "Access Control",
    },
    {
      name: "Tenant isolation required",
      rule: "Every database query or ORM call that accesses tenant-scoped data must include a tenant or organization boundary derived from the authenticated session, not from untrusted request input. Flag queries that use ids from params, query strings, or request bodies without also filtering by organizationId, tenantId, accountId, ownerId, or membership tied to the current user.",
      severity: "CRITICAL" as const,
      category: "Multi-Tenant Security",
    },
    {
      name: "No debug mode in production",
      rule: "Production application settings must not enable debug mode, verbose exception pages, development middleware, SQL query logging, hot reload, stack traces, or permissive error responses. Flag DEBUG=True, debug: true, app.debug = True, NODE_ENV defaults that enable development behavior, or production configs that expose detailed errors.",
      severity: "HIGH" as const,
      category: "Configuration",
    },
    {
      name: "Webhook signatures must be verified",
      rule: "Any webhook endpoint must verify the provider signature before processing the payload. Flag GitHub, GitLab, Stripe, Slack, Twilio, Razorpay, PayPal, generic webhook, or callback handlers that trust request bodies without validating HMAC/signature headers, timestamps, replay windows, and shared secrets.",
      severity: "HIGH" as const,
      category: "Security",
    },
    {
      name: "JWT verification must be strict",
      rule: "JWT validation must verify signature, algorithm allowlist, expiration, issuer, and audience before trusting claims. Flag code that decodes JWTs without verification, accepts alg=none, trusts role/userId/orgId claims without validation, disables expiration checks, or uses token payloads directly for authorization decisions.",
      severity: "CRITICAL" as const,
      category: "Authentication",
    },
    {
      name: "No server-side request forgery sinks",
      rule: "Server-side HTTP clients must not request arbitrary user-controlled URLs or hosts. Flag fetch, axios, requests, urllib, http.Client, curl, or proxy/download/import handlers where URL, host, redirect target, or path comes from request input without allowlisting schemes and trusted domains and blocking private/internal IP ranges.",
      severity: "HIGH" as const,
      category: "SSRF",
    },
    {
      name: "No unsafe dynamic execution",
      rule: "Application code must not execute user-controlled strings as code, shell commands, templates, expressions, SQL, or scripts. Flag eval, Function, exec, spawn with shell=true, os.system, subprocess with shell=True, template rendering from user input, dynamic import paths, or expression evaluators when influenced by request data.",
      severity: "CRITICAL" as const,
      category: "Code Execution",
    },
    {
      name: "Password reset tokens must be single-use",
      rule: "Password reset, email verification, magic link, invitation, and one-time login tokens must be random, expire quickly, be stored hashed, and be invalidated after first use. Flag token flows that use predictable values, store raw tokens, do not check expiry, do not mark tokens as used, or allow reuse.",
      severity: "HIGH" as const,
      category: "Authentication",
    },
    {
      name: "Dangerous mass assignment must be blocked",
      rule: "Create and update handlers must not bind request bodies directly to models/entities when sensitive fields exist. Flag mass assignment or over-posting where clients can set role, isAdmin, permissions, ownerId, organizationId, tenantId, balance, price, status, approved, verified, or security flags without an explicit allowlist.",
      severity: "HIGH" as const,
      category: "API Security",
    },
    {
      name: "Sensitive files must not be served",
      rule: "Static file serving, download, export, preview, or attachment handlers must prevent path traversal and must not expose environment files, database files, source maps, backups, private keys, logs, or internal config. Flag handlers that join user-controlled paths or filenames without canonical path validation and an allowlisted storage root.",
      severity: "HIGH" as const,
      category: "Data Exposure",
    },
    {
      name: "Payment amounts must be server calculated",
      rule: "Payment, invoice, order, checkout, subscription, wallet, refund, and credit flows must calculate amount, currency, discount, tax, balance, and entitlement server-side from trusted records. Flag code that trusts client-provided amount, price, quantity, discount, plan, paid status, or payment success without server-side verification.",
      severity: "CRITICAL" as const,
      category: "Business Logic",
    },
    {
      name: "State transitions must be authorized",
      rule: "Business state changes such as approve, reject, publish, cancel, refund, reset, complete, activate, deactivate, promote, or role change must verify the actor is allowed to perform that transition from the current state. Flag direct status assignment from request input or admin actions without role, ownership, and current-state validation.",
      severity: "HIGH" as const,
      category: "Business Logic",
    },
  ];

  for (const policy of samplePolicies) {
    await prisma.securityPolicy.upsert({
      where: {
        id: `seed-policy-${policy.name.toLowerCase().replace(/\s+/g, "-")}`,
      },
      update: {
        rule: policy.rule,
        severity: policy.severity,
        category: policy.category,
      },
      create: {
        id: `seed-policy-${policy.name.toLowerCase().replace(/\s+/g, "-")}`,
        organizationId: org.id,
        name: policy.name,
        rule: policy.rule,
        severity: policy.severity,
        category: policy.category,
        enabled: true,
      },
    });
  }
  console.log(
    `Security policies: ${samplePolicies.length} sample policies created`,
  );

  console.log("Seed complete!");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
