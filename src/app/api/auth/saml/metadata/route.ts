import { NextResponse } from "next/server";
import { isSamlEnabled } from "@/lib/saml/config";
import { getSamlClient } from "@/lib/saml/client";

/** SP metadata XML for IdP configuration (entity id, ACS URL). */
export const dynamic = "force-dynamic";

export async function GET() {
  if (!isSamlEnabled()) {
    return new NextResponse("SSO not enabled", { status: 404 });
  }
  const { saml } = getSamlClient();
  const xml = saml.generateServiceProviderMetadata(null, null);
  return new NextResponse(xml, {
    headers: { "Content-Type": "application/xml; charset=utf-8" },
  });
}
