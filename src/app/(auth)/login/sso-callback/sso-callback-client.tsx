"use client";

import { useEffect, useRef } from "react";
import { signIn } from "next-auth/react";
import { useRouter, useSearchParams } from "next/navigation";

/**
 * Completes SSO: takes the signed handoff token from the ACS redirect and
 * exchanges it for a NextAuth session via the "saml" provider. On any failure
 * it returns to the login page, which renders the SSO error banner.
 */
export function SsoCallback() {
  const params = useSearchParams();
  const router = useRouter();
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    const token = params.get("token");
    if (!token) {
      router.replace("/login?error=sso");
      return;
    }
    signIn("saml", { token, redirect: false })
      .then((res) => {
        if (res?.error || !res?.ok) {
          router.replace("/login?error=sso");
        } else {
          router.push("/dashboard");
          router.refresh();
        }
      })
      .catch(() => router.replace("/login?error=sso"));
  }, [params, router]);

  return (
    <div className="flex min-h-screen flex-col items-center justify-center px-4 text-center">
      <p className="text-sm text-muted-foreground" role="status">
        Signing you in…
      </p>
    </div>
  );
}
