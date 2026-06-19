import { NextResponse } from "next/server";
import { isBitbucketOAuthConfigured } from "@/lib/bitbucket-oauth-config";

export async function GET() {
  return NextResponse.json({
    oauthConfigured: isBitbucketOAuthConfigured(),
  });
}
