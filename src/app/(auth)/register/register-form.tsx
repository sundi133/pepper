"use client";

import { signIn } from "next-auth/react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useRef, useState } from "react";
import {
  HcaptchaField,
  type HcaptchaFieldHandle,
} from "@/components/hcaptcha-field";
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
import { Code2, Github, UserPlus } from "lucide-react";

export function RegisterForm({ captchaSiteKey }: { captchaSiteKey: string }) {
  const router = useRouter();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [captchaToken, setCaptchaToken] = useState("");
  const captchaRef = useRef<HcaptchaFieldHandle>(null);
  const sourceUrl = getSourceCodeUrl();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setMessage("");

    if (captchaSiteKey && !captchaToken) {
      setMessage("Please complete the captcha.");
      return;
    }

    setLoading(true);

    try {
      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          password,
          name: name.trim() || undefined,
          organizationName,
          captchaToken,
        }),
      });
      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        setMessage(
          typeof data.error === "string"
            ? data.error
            : "Registration failed. Please try again.",
        );
        setCaptchaToken("");
        captchaRef.current?.reset();
        setLoading(false);
        return;
      }

      const signInResult = await signIn("credentials", {
        email,
        password,
        redirect: false,
      });

      setLoading(false);

      if (signInResult?.error) {
        setMessage(
          "Account created. Sign in with your email and password on the login page.",
        );
        router.push("/login");
        return;
      }

      router.push("/dashboard");
      router.refresh();
    } catch {
      setLoading(false);
      setMessage("Registration failed. Please try again.");
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
        <div className="relative hidden flex-col justify-center border-border/60 bg-muted/40 px-8 py-12 font-mono text-[13px] leading-relaxed text-muted-foreground lg:flex lg:border-r">
          <div className="absolute left-6 top-6 flex items-center gap-2 text-foreground">
            <Code2 className="h-5 w-5 text-primary" aria-hidden />
            <span className="text-sm font-semibold tracking-tight">
              New workspace
            </span>
          </div>
          <p className="mt-10 max-w-md text-sm text-muted-foreground">
            Registration creates your own organization. You are the first admin.
            Invite teammates from Settings → Team after sign-in.
          </p>
        </div>

        <div className="flex flex-col items-center justify-center px-4 py-16 sm:px-6">
          <Card className="w-full max-w-md border-border/60 shadow-lg">
            <CardHeader className="space-y-1 text-center">
              <div className="mx-auto mb-2 flex h-12 w-12 items-center justify-center rounded-xl bg-primary/15 text-primary ring-1 ring-primary/25">
                <UserPlus className="h-6 w-6" aria-hidden />
              </div>
              <CardTitle className="text-2xl font-bold tracking-tight">
                Create account
              </CardTitle>
              <CardDescription className="text-base">
                Register a new organization on Pepper
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="organizationName">Organization name</Label>
                  <Input
                    id="organizationName"
                    value={organizationName}
                    onChange={(e) => setOrganizationName(e.target.value)}
                    placeholder="Acme Security"
                    required
                    minLength={2}
                    className="h-11"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="name">Your name</Label>
                  <Input
                    id="name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Jane Doe"
                    className="h-11"
                  />
                </div>
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
                    autoComplete="new-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    minLength={8}
                    className="h-11"
                  />
                  <p className="text-xs text-muted-foreground">
                    Minimum 8 characters.
                  </p>
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
                  {loading ? "Creating account…" : "Create account"}
                </Button>
              </form>
              <p className="mt-6 text-center text-sm text-muted-foreground">
                Already have an account?{" "}
                <Link
                  href="/login"
                  className="font-medium text-foreground underline-offset-4 hover:underline"
                >
                  Sign in
                </Link>
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
