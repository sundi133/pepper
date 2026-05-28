import { getHcaptchaSiteKey } from "@/lib/hcaptcha";
import { RegisterForm } from "./register-form";

// Read the captcha site key from runtime env on each request so it can be
// supplied via deployment variables without rebuilding the image.
export const dynamic = "force-dynamic";

export default function RegisterPage() {
  return <RegisterForm captchaSiteKey={getHcaptchaSiteKey()} />;
}
