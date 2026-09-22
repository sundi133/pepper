import { NextResponse } from "next/server";
import { logger } from "@/lib/logger";
import { isSamlEnabled, appBaseUrl } from "@/lib/saml/config";
import { getSamlClient } from "@/lib/saml/client";

/** Begin SP-initiated SSO: redirect the browser to the IdP's login URL. */
export const dynamic = "force-dynamic";

export async function GET() {
  if (!isSamlEnabled()) {
    return NextResponse.json({ error: "SSO not enabled" }, { status: 404 });
  }
  try {
    const { saml } = getSamlClient();
    const url = await saml.getAuthorizeUrlAsync("", undefined, {});
    return NextResponse.redirect(url);
  } catch (err) {
    logger.warn({ err }, "SAML: failed to build authorize URL");
    return NextResponse.redirect(`${appBaseUrl()}/login?error=sso`);
  }
}
