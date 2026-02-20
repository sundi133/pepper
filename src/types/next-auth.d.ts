import "next-auth";

declare module "next-auth" {
  interface Session {
    user: {
      id: string;
      name?: string | null;
      email?: string | null;
      image?: string | null;
      memberships?: Array<{
        organizationId: string;
        role: "ADMIN" | "SECURITY" | "DEVELOPER" | "VIEWER";
        organizationName?: string;
        organizationSlug?: string;
      }>;
    };
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    userId?: string;
    memberships?: Array<{
      organizationId: string;
      role: "ADMIN" | "SECURITY" | "DEVELOPER" | "VIEWER";
      organizationName?: string;
      organizationSlug?: string;
    }>;
  }
}
