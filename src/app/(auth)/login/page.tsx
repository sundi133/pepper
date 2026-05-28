"use client";

import { signIn } from "next-auth/react";
import Link from "next/link";
import { useRef, useState } from "react";
import { useRouter } from "next/navigation";
import {
  HcaptchaField,
  type HcaptchaFieldHandle,
} from "@/components/hcaptcha-field";
import { getHcaptchaSiteKey } from "@/lib/hcaptcha";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { ThemeToggle } from "@/components/layout/theme-toggle";
import { getSourceCodeUrl } from "@/lib/app-source";
import { Code2, Github, Shield } from "lucide-react";

const LOGIN_SNIPPET = `// Credential sign-in (illustrative)
import { signIn } from "next-auth/react";

async function onSubmit(email: string, password: string) {
  return signIn("credentials", {
    email,
    password,
    redirect: false,
  });
}`;

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [captchaToken, setCaptchaToken] = useState("");
  const captchaRef = useRef<HcaptchaFieldHandle>(null);
  const sourceUrl = getSourceCodeUrl();
  const captchaSiteKey = getHcaptchaSiteKey();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setMessage("");

    if (captchaSiteKey && !captchaToken) {
      setMessage("Please complete the captcha.");
      return;
    }

    setLoading(true);

    const result = await signIn("credentials", {
      email,
      password,
      captchaToken,
      redirect: false,
    });

    setLoading(false);

    if (result?.error) {
      setMessage("Invalid email or password");
      setCaptchaToken("");
      captchaRef.current?.reset();
    } else {
      router.push("/dashboard");
      router.refresh();
    }
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="absolute right-4 top-4 z-10 flex items-center gap-2">
        {sourceUrl ? (
          <Button variant="outline" size="sm" className="gap-2" asChild>
            <a
              href={sourceUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="text-muted-foreground hover:text-foreground"
            >
              <Github className="h-4 w-4" aria-hidden />
              Source
            </a>
          </Button>
        ) : null}
        <ThemeToggle />
      </div>

      <div className="grid min-h-screen lg:grid-cols-2">
        <div className="relative hidden flex-col justify-center border-border/60 bg-gradient-to-br from-muted/60 via-accent/20 to-background px-8 py-12 font-mono text-[13px] leading-relaxed text-muted-foreground lg:flex lg:border-r">
          <div className="absolute left-6 top-6 flex items-center gap-2 text-foreground">
            <Code2 className="h-5 w-5 text-primary" aria-hidden />
            <span className="text-sm font-semibold tracking-tight">
              Overview
            </span>
          </div>
          <pre className="mt-10 overflow-x-auto whitespace-pre rounded-xl border border-border/50 bg-card/80 p-5 text-left shadow-sm ring-1 ring-border/30">
            <code>{LOGIN_SNIPPET}</code>
          </pre>
          <p className="mt-6 max-w-md text-sm text-muted-foreground">
            Pepper runs static analysis, secrets detection, and policy checks
            before code ships. Use only on code you are authorized to analyze.
          </p>
        </div>

        <div className="flex flex-col items-center justify-center px-4 py-16 sm:px-6">
          <Card className="surface-card w-full max-w-md border-border/60">
            <CardHeader className="space-y-1 text-center">
              <div className="mx-auto mb-2 flex h-12 w-12 items-center justify-center rounded-xl bg-primary/15 text-primary ring-1 ring-primary/25">
                <Shield className="h-6 w-6" aria-hidden />
              </div>
              <CardTitle className="text-2xl font-bold tracking-tight">
                Pepper
              </CardTitle>
              <CardDescription className="text-base">
                Sign in to your organization workspace
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="email">Email</Label>
                  <Input
                    id="email"
                    type="email"
                    autoComplete="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    className="h-11"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password">Password</Label>
                  <Input
                    id="password"
                    type="password"
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    className="h-11"
                  />
                </div>
                {captchaSiteKey ? (
                  <HcaptchaField
                    ref={captchaRef}
                    siteKey={captchaSiteKey}
                    onVerify={setCaptchaToken}
                    onExpire={() => setCaptchaToken("")}
                  />
                ) : null}
                {message ? (
                  <p className="text-sm text-muted-foreground" role="status">
                    {message}
                  </p>
                ) : null}
                <Button type="submit" className="h-11 w-full" disabled={loading}>
                  {loading ? "Signing in…" : "Sign in"}
                </Button>
              </form>
              <p className="mt-4 text-center text-sm text-muted-foreground">
                No account?{" "}
                <Link
                  href="/register"
                  className="font-medium text-primary underline-offset-4 transition-colors hover:text-primary/80 hover:underline"
                >
                  Create one
                </Link>
              </p>
              <p className="mt-6 text-center text-xs text-muted-foreground">
                By signing in you agree to use Pepper only on code you are
                authorized to analyze.
              </p>
              {sourceUrl ? (
                <p className="mt-4 text-center text-xs">
                  <a
                    href={sourceUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary underline-offset-4 hover:underline"
                  >
                    View project source on GitHub
                  </a>
                </p>
              ) : null}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
