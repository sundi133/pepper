import "dotenv/config";
import { PrismaClient } from "../src/generated/prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import pg from "pg";
import bcrypt from "bcryptjs";

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL! });
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter }) as any;

async function main() {
  console.log("Seeding database...");

  // Create default organization
  const org = await (prisma as any).organization.upsert({
    where: { slug: "default" },
    update: {},
    create: {
      name: "Default Organization",
      slug: "default",
    },
  });
  console.log(`Organization: ${org.name} (${org.id})`);

  // Create org settings
  await (prisma as any).orgSettings.upsert({
    where: { organizationId: org.id },
    update: {},
    create: {
      organizationId: org.id,
      llmProvider: "openai",
      llmBaseUrl: "https://api.openai.com/v1",
      llmModel: "gpt-4o-mini",
    },
  });

  // Create admin user
  const email = process.env.ADMIN_EMAIL || "admin@pepper.local";
  const password = process.env.ADMIN_PASSWORD || "pepper-admin-changeme";
  const passwordHash = await bcrypt.hash(password, 12);

  const admin = await (prisma as any).user.upsert({
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
  await (prisma as any).orgMember.upsert({
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
  const project = await (prisma as any).project.upsert({
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
  await (prisma as any).buildGate.upsert({
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
  console.log("Seed complete!");
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await (prisma as any).$disconnect();
  });
