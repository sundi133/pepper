import { Suspense } from "react";
import { SsoCallback } from "./sso-callback-client";

export const dynamic = "force-dynamic";

export default function SsoCallbackPage() {
  return (
    <Suspense fallback={null}>
      <SsoCallback />
    </Suspense>
  );
}
