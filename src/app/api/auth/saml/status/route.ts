import { NextResponse } from "next/server";
import { isSamlEnabled } from "@/lib/saml/config";

/** Public: whether the SSO button should be shown on the login page. */
export const dynamic = "force-dynamic";

export async function GET() {
  return NextResponse.json({ enabled: isSamlEnabled() });
}
