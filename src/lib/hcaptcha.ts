/**
 * hCaptcha bot / brute-force protection for the login and registration flows.
 *
 * Enable by setting both env vars (get keys at https://dashboard.hcaptcha.com/):
 *   NEXT_PUBLIC_HCAPTCHA_SITE_KEY  - public site key, rendered in the browser widget
 *   HCAPTCHA_SECRET_KEY            - server secret, used only for token verification
 *
 * When the secret is unset, verification is skipped so local/dev sign-in keeps working.
 */

const HCAPTCHA_VERIFY_URL = "https://api.hcaptcha.com/siteverify";

/** Public site key for the browser widget (empty string when not configured). */
export function getHcaptchaSiteKey(): string {
  return process.env.NEXT_PUBLIC_HCAPTCHA_SITE_KEY?.trim() || "";
}

/** True when server-side captcha enforcement is configured. */
export function isHcaptchaEnabled(): boolean {
  return Boolean(process.env.HCAPTCHA_SECRET_KEY?.trim());
}

/**
 * Verify a captcha response token against the hCaptcha API.
 * Returns true (skips the check) when no secret is configured.
 */
export async function verifyHcaptchaToken(
  token: string | undefined | null,
  remoteIp?: string | null,
): Promise<boolean> {
  const secret = process.env.HCAPTCHA_SECRET_KEY?.trim();
  if (!secret) return true; // not configured -> do not block
  if (!token) return false;

  const body = new URLSearchParams();
  body.set("secret", secret);
  body.set("response", token);
  if (remoteIp) body.set("remoteip", remoteIp);

  try {
    const res = await fetch(HCAPTCHA_VERIFY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    if (!res.ok) return false;
    const data = (await res.json()) as { success?: boolean };
    return data.success === true;
  } catch {
    return false;
  }
}
