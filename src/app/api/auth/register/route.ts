import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { logger } from "@/lib/logger";
import {
  isPublicRegistrationEnabled,
  registerNewUser,
  RegisterUserError,
} from "@/lib/register-user";

const registerSchema = z.object({
  email: z.string().trim().toLowerCase().email(),
  password: z.string().min(8, "Password must be at least 8 characters"),
  name: z.string().trim().max(100).optional(),
  organizationName: z
    .string()
    .trim()
    .min(2, "Organization name must be at least 2 characters")
    .max(100),
});

export async function POST(req: NextRequest) {
  if (!isPublicRegistrationEnabled()) {
    return NextResponse.json(
      {
        error:
          "Public registration is disabled. Ask an administrator to invite you.",
      },
      { status: 403 },
    );
  }

  try {
    const body = await req.json();
    const data = registerSchema.parse(body);
    const { user, organization } = await registerNewUser(data);

    return NextResponse.json(
      {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
        },
        organization: {
          id: organization.id,
          name: organization.name,
          slug: organization.slug,
        },
      },
      { status: 201 },
    );
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        {
          error: error.issues[0]?.message || "Invalid input",
          details: error.issues,
        },
        { status: 400 },
      );
    }
    if (error instanceof RegisterUserError) {
      const status = error.code === "EMAIL_EXISTS" ? 409 : 403;
      return NextResponse.json({ error: error.message, code: error.code }, { status });
    }
    logger.error({ error }, "Registration failed");
    return NextResponse.json(
      { error: "Registration failed. Please try again." },
      { status: 500 },
    );
  }
}
