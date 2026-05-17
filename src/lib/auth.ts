import { PrismaAdapter } from "@auth/prisma-adapter";
import { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import GitHubProvider from "next-auth/providers/github";
import bcrypt from "bcryptjs";
import { prisma } from "./prisma";

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
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) return null;
        const user = await prisma.user.findUnique({
          where: { email: credentials.email },
        });
        if (!user?.passwordHash) return null;
        const valid = await bcrypt.compare(
          credentials.password,
          user.passwordHash,
        );
        if (!valid) return null;
        return { id: user.id, email: user.email, name: user.name };
      },
    }),
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
  pages: {
    signIn: "/login",
  },
};
