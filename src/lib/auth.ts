import { PrismaAdapter } from "@auth/prisma-adapter";
import { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import GitHubProvider from "next-auth/providers/github";
import bcrypt from "bcryptjs";
import { prisma } from "./prisma";
import { isHcaptchaEnabled, verifyHcaptchaToken } from "./hcaptcha";
import { isSamlEnabled } from "./saml/config";
import { verifySamlHandoffToken } from "./saml/handoff";
import { ipFromHeaderRecord, writeUserAuditEvent } from "./audit-log";

/** Record a failed sign-in (never the password) against the account, if it exists. */
async function auditLoginFailure(
  userId: string | null,
  details: Record<string, unknown>,
  ipAddress: string | null,
) {
  await writeUserAuditEvent({ userId, action: "user.login_failed", details, ipAddress });
}

export const authOptions: NextAuthOptions = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  adapter: PrismaAdapter(prisma as any) as NextAuthOptions["adapter"],
  session: { strategy: "jwt" },
  providers: [
    CredentialsProvider({
      name: "credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
        captchaToken: { label: "Captcha", type: "text" },
      },
      async authorize(credentials, req) {
        if (!credentials?.email || !credentials?.password) return null;
        const ipAddress = ipFromHeaderRecord(req?.headers);

        if (isHcaptchaEnabled()) {
          const forwarded = (req?.headers?.["x-forwarded-for"] as
            | string
            | undefined)?.split(",")[0]?.trim();
          const ok = await verifyHcaptchaToken(
            credentials.captchaToken,
            forwarded,
          );
          if (!ok) {
            await auditLoginFailure(null, { method: "password", email: credentials.email, reason: "captcha" }, ipAddress);
            return null;
          }
        }

        const user = await prisma.user.findUnique({
          where: { email: credentials.email },
        });
        if (!user?.passwordHash) {
          await auditLoginFailure(
            user?.id ?? null,
            { method: "password", email: credentials.email, reason: user ? "no_password_set" : "unknown_user" },
            ipAddress,
          );
          return null;
        }
        const valid = await bcrypt.compare(
          credentials.password,
          user.passwordHash,
        );
        if (!valid) {
          await auditLoginFailure(user.id, { method: "password", email: user.email, reason: "wrong_password" }, ipAddress);
          return null;
        }
        await writeUserAuditEvent({ userId: user.id, action: "user.login", details: { method: "password" }, ipAddress });
        return { id: user.id, email: user.email, name: user.name };
      },
    }),
    // SAML SSO: a validated assertion is exchanged (server-side, in the ACS
    // route) for a short-lived signed handoff token; this provider verifies the
    // token and establishes the NextAuth session. Only registered when SSO is
    // enabled and configured, so default installs are unaffected.
    ...(isSamlEnabled()
      ? [
          CredentialsProvider({
            id: "saml",
            name: "SSO",
            credentials: {
              token: { label: "SSO token", type: "text" },
            },
            async authorize(credentials, req) {
              const ipAddress = ipFromHeaderRecord(req?.headers);
              const userId = verifySamlHandoffToken(credentials?.token);
              if (!userId) {
                await auditLoginFailure(null, { method: "saml", reason: "invalid_sso_token" }, ipAddress);
                return null;
              }
              const user = await prisma.user.findUnique({
                where: { id: userId },
                select: { id: true, email: true, name: true },
              });
              if (!user) return null;
              await writeUserAuditEvent({ userId: user.id, action: "user.login", details: { method: "saml" }, ipAddress });
              return { id: user.id, email: user.email, name: user.name };
            },
          }),
        ]
      : []),
    ...(process.env.GITHUB_ID
      ? [
          GitHubProvider({
            clientId: process.env.GITHUB_ID!,
            clientSecret: process.env.GITHUB_SECRET!,
          }),
        ]
      : []),
  ],
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.userId = user.id;
      }

      const userId =
        (typeof user?.id === "string" ? user.id : undefined) ??
        (typeof token.userId === "string" ? token.userId : undefined);
      const shouldLoadMemberships =
        userId !== undefined &&
        (Boolean(user) || token.memberships === undefined);

      if (shouldLoadMemberships) {
        const memberships = await prisma.orgMember.findMany({
          where: { userId },
          orderBy: { createdAt: "asc" },
          include: { organization: { select: { name: true, slug: true } } },
        });
        token.memberships = memberships.map((m) => ({
          organizationId: m.organizationId,
          role: m.role,
          organizationName: m.organization.name,
          organizationSlug: m.organization.slug,
        }));
      }
      return token;
    },
    async session({ session, token }) {
      if (token.userId) {
        session.user.id = token.userId as string;
        session.user.memberships =
          token.memberships as typeof session.user.memberships;
      }
      return session;
    },
  },
  events: {
    // Password and SAML sign-ins are recorded in authorize (with the client
    // IP); this covers OAuth providers.
    async signIn({ user, account }) {
      if (!account || account.provider === "credentials" || account.provider === "saml") return;
      await writeUserAuditEvent({
        userId: typeof user?.id === "string" ? user.id : null,
        action: "user.login",
        details: { method: account.provider },
      });
    },
    async signOut({ token }) {
      const userId = typeof token?.userId === "string" ? token.userId : null;
      if (userId) await writeUserAuditEvent({ userId, action: "user.logout" });
    },
  },
  pages: {
    signIn: "/login",
  },
};
