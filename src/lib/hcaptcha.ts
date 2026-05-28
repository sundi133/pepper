/**
 * hCaptcha bot / brute-force protection for the login and registration flows.
 *
 * Enable by setting both env vars (get keys at https://dashboard.hcaptcha.com/):
 *   HCAPTCHA_SITE_KEY    - public site key, read on the server at runtime and
 *                          passed to the browser widget (no rebuild needed)
 *   HCAPTCHA_SECRET_KEY  - server secret, used only for token verification
 *
 * When the secret is unset, verification is skipped so local/dev sign-in keeps working.
 */

const HCAPTCHA_VERIFY_URL = "https://api.hcaptcha.com/siteverify";

/**
 * Public site key for the browser widget (empty string when not configured).
 *
 * Read at runtime on the server so the key can be supplied via deployment env
 * without rebuilding the image. `NEXT_PUBLIC_HCAPTCHA_SITE_KEY` is accepted as
 * a fallback for setups that prefer build-time inlining.
 */
export function getHcaptchaSiteKey(): string {
  return (
    process.env.HCAPTCHA_SITE_KEY?.trim() ||
    process.env.NEXT_PUBLIC_HCAPTCHA_SITE_KEY?.trim() ||
    ""
  );
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
