export function verify(token: string, secret: string, sig: string, expectedSig: string, password: string, passwordRepeat: string) {
  // ruleid: pepper.js.timing-unsafe-secret-compare
  if (token === secret) return true;
  // ruleid: pepper.js.timing-unsafe-secret-compare
  if (sig !== expectedSig) return false;
  // ok: pepper.js.timing-unsafe-secret-compare
  if (token === null) return false;
  // ok: pepper.js.timing-unsafe-secret-compare
  if (password !== passwordRepeat) return false;
  // ok: pepper.js.timing-unsafe-secret-compare
  if (typeof token === "string") return true;
  return false;
}
