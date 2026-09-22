import { NextRequest, NextResponse } from "next/server";
import { logger } from "@/lib/logger";
import { isSamlEnabled, appBaseUrl } from "@/lib/saml/config";
import { getSamlClient, extractSamlIdentity } from "@/lib/saml/client";
import { mapSamlRole } from "@/lib/saml/role-mapping";
import { provisionSamlUser } from "@/lib/saml/provision";
import { createSamlHandoffToken } from "@/lib/saml/handoff";

/**
 * Assertion Consumer Service (ACS). The IdP POSTs the signed SAMLResponse here.
 * We validate it, JIT-provision the user, and hand a short-lived signed token to
 * a client page that completes the NextAuth session. All failures fall back to
 * the login page with an error flag — never a stack trace.
 */
export const dynamic = "force-dynamic";

function loginError(reason: string): NextResponse {
  // 303 so the IdP's POST becomes a GET on the redirect target.
  return NextResponse.redirect(
    `${appBaseUrl()}/login?error=${encodeURIComponent(reason)}`,
    303,
  );
}

export async function POST(req: NextRequest) {
  if (!isSamlEnabled()) {
    return NextResponse.json({ error: "SSO not enabled" }, { status: 404 });
  }

  let SAMLResponse: string | undefined;
  let RelayState: string | undefined;
  try {
    const form = await req.formData();
    const sr = form.get("SAMLResponse");
    const rs = form.get("RelayState");
    SAMLResponse = typeof sr === "string" ? sr : undefined;
    RelayState = typeof rs === "string" ? rs : undefined;
  } catch {
    return loginError("sso");
  }
  if (!SAMLResponse) return loginError("sso");

  try {
    const { saml, cfg } = getSamlClient();
    const { profile } = await saml.validatePostResponseAsync({
      SAMLResponse,
      ...(RelayState ? { RelayState } : {}),
    });
    if (!profile) return loginError("sso");

    const identity = extractSamlIdentity(
      profile as Record<string, unknown>,
      cfg,
    );
    if (!identity.email) {
      logger.warn("SAML: assertion had no resolvable email");
      return loginError("sso_no_email");
    }

    const role = mapSamlRole(identity.groups, {
      roleMap: cfg.roleMap,
      defaultRole: cfg.defaultRole,
    });

    const { userId } = await provisionSamlUser({
      email: identity.email,
      name: identity.name,
      role,
      defaultOrgSlug: cfg.defaultOrgSlug,
    });

    const token = createSamlHandoffToken(userId);
    const url = new URL("/login/sso-callback", appBaseUrl());
    url.searchParams.set("token", token);
    return NextResponse.redirect(url.toString(), 303);
  } catch (err) {
    logger.warn({ err }, "SAML: assertion validation or provisioning failed");
    return loginError("sso");
  }
}
