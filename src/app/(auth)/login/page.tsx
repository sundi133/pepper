import { getHcaptchaSiteKey } from "@/lib/hcaptcha";
import { isSamlEnabled } from "@/lib/saml/config";
import { LoginForm } from "./login-form";

// Read the captcha site key from runtime env on each request so it can be
// supplied via deployment variables without rebuilding the image.
export const dynamic = "force-dynamic";

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const { error } = await searchParams;
  return (
    <LoginForm
      captchaSiteKey={getHcaptchaSiteKey()}
      samlEnabled={isSamlEnabled()}
      initialError={typeof error === "string" ? error : undefined}
    />
  );
}
