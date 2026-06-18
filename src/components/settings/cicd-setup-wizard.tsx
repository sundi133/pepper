"use client";

import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Copy, Check, Download, Github, GitBranch, Code2 } from "lucide-react";
import { toast } from "sonner";

type Platform = "github" | "gitlab" | "jenkins";

interface Step {
  number: number;
  title: string;
  content: React.ReactNode;
}

export function CicdSetupWizard() {
  const [currentStep, setCurrentStep] = useState(0);
  const [apiKey, setApiKey] = useState<string | null>(null);
  const [apiKeyName, setApiKeyName] = useState("cicd");
  const [creatingKey, setCreatingKey] = useState(false);
  const [selectedPlatform, setSelectedPlatform] = useState<Platform>("github");
  const [copied, setCopied] = useState<string | null>(null);

  const apiUrl = typeof window !== "undefined" ? window.location.origin : "";

  async function createApiKey() {
    setCreatingKey(true);
    try {
      const res = await fetch("/api/apikeys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: apiKeyName.trim() || "cicd" }),
      });
      if (!res.ok) {
        throw new Error("Failed to create API key");
      }
      const data = (await res.json()) as { plaintext: string };
      setApiKey(data.plaintext);
      toast.success("API key created! Copy it now.");
      setCurrentStep(1);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to create API key");
    } finally {
      setCreatingKey(false);
    }
  }

  function copyToClipboard(text: string, label: string) {
    navigator.clipboard.writeText(text);
    toast.success(`Copied ${label}`);
    setCopied(label);
    setTimeout(() => setCopied(null), 2000);
  }

  function downloadTemplate(platform: Platform) {
    window.location.href = `/api/cicd-templates/${platform}`;
  }

  const platformConfig = {
    github: {
      name: "GitHub Actions",
      icon: Github,
      description: "Scan on pull requests and pushes to main",
      steps: [
        {
          number: 1,
          title: "Set GitHub Secrets",
          content: (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Go to your repository → Settings → Secrets and variables → Actions
              </p>
              <div className="space-y-2">
                <div>
                  <div className="text-xs font-medium mb-1">PEPPER_API_URL</div>
                  <div className="flex gap-2">
                    <Input value={apiUrl} readOnly className="text-xs" />
                    <Button
                      size="icon"
                      variant="outline"
                      onClick={() => copyToClipboard(apiUrl, "PEPPER_API_URL")}
                    >
                      {copied === "PEPPER_API_URL" ? (
                        <Check className="h-4 w-4" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                </div>
                <div>
                  <div className="text-xs font-medium mb-1">PEPPER_API_KEY</div>
                  <div className="flex gap-2">
                    <Input type="password" value={apiKey || ""} readOnly className="text-xs font-mono" />
                    <Button
                      size="icon"
                      variant="outline"
                      onClick={() => copyToClipboard(apiKey || "", "PEPPER_API_KEY")}
                    >
                      {copied === "PEPPER_API_KEY" ? (
                        <Check className="h-4 w-4" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                </div>
              </div>
            </div>
          ),
        },
        {
          number: 2,
          title: "Add Workflow File",
          content: (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Download the workflow template and add it to your repository:
              </p>
              <Button
                onClick={() => downloadTemplate("github")}
                className="w-full"
                variant="outline"
              >
                <Download className="h-4 w-4 mr-2" />
                Download .github/workflows/pepper.yml
              </Button>
              <p className="text-xs text-muted-foreground">
                or manually create <code className="bg-muted px-1 rounded">.github/workflows/pepper.yml</code> with the template content
              </p>
            </div>
          ),
        },
        {
          number: 3,
          title: "Commit and Push",
          content: (
            <div className="space-y-2 text-sm">
              <p className="text-muted-foreground">Push the workflow file to your repository:</p>
              <code className="block bg-muted p-2 rounded text-xs overflow-x-auto">
                git add .github/workflows/pepper.yml && git commit -m "Add Pepper security scan" && git push
              </code>
            </div>
          ),
        },
      ],
    },
    gitlab: {
      name: "GitLab CI",
      icon: GitBranch,
      description: "Scan as part of your CI/CD pipeline",
      steps: [
        {
          number: 1,
          title: "Set GitLab Variables",
          content: (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Go to your project → Settings → CI/CD → Variables
              </p>
              <div className="space-y-2">
                <div>
                  <div className="text-xs font-medium mb-1">PEPPER_API_URL</div>
                  <div className="flex gap-2">
                    <Input value={apiUrl} readOnly className="text-xs" />
                    <Button
                      size="icon"
                      variant="outline"
                      onClick={() => copyToClipboard(apiUrl, "PEPPER_API_URL")}
                    >
                      {copied === "PEPPER_API_URL" ? (
                        <Check className="h-4 w-4" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                </div>
                <div>
                  <div className="text-xs font-medium mb-1">PEPPER_API_KEY</div>
                  <div className="flex gap-2">
                    <Input type="password" value={apiKey || ""} readOnly className="text-xs font-mono" />
                    <Button
                      size="icon"
                      variant="outline"
                      onClick={() => copyToClipboard(apiKey || "", "PEPPER_API_KEY")}
                    >
                      {copied === "PEPPER_API_KEY" ? (
                        <Check className="h-4 w-4" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                </div>
              </div>
              <p className="text-xs text-muted-foreground">Mark both as "Protected" and "Masked"</p>
            </div>
          ),
        },
        {
          number: 2,
          title: "Add Pipeline Configuration",
          content: (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Download and add to your existing .gitlab-ci.yml or create a new file:
              </p>
              <Button
                onClick={() => downloadTemplate("gitlab")}
                className="w-full"
                variant="outline"
              >
                <Download className="h-4 w-4 mr-2" />
                Download .gitlab-ci.pepper.yml
              </Button>
            </div>
          ),
        },
      ],
    },
    jenkins: {
      name: "Jenkins",
      icon: Code2,
      description: "Add as a pipeline stage",
      steps: [
        {
          number: 1,
          title: "Create Jenkins Credentials",
          content: (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Go to Manage Jenkins → Credentials and create two secret text credentials:
              </p>
              <div className="space-y-2">
                <div>
                  <div className="text-xs font-medium mb-1">Credential: PEPPER_API_URL</div>
                  <div className="flex gap-2">
                    <Input value={apiUrl} readOnly className="text-xs" />
                    <Button
                      size="icon"
                      variant="outline"
                      onClick={() => copyToClipboard(apiUrl, "PEPPER_API_URL")}
                    >
                      {copied === "PEPPER_API_URL" ? (
                        <Check className="h-4 w-4" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                </div>
                <div>
                  <div className="text-xs font-medium mb-1">Credential: PEPPER_API_KEY</div>
                  <div className="flex gap-2">
                    <Input type="password" value={apiKey || ""} readOnly className="text-xs font-mono" />
                    <Button
                      size="icon"
                      variant="outline"
                      onClick={() => copyToClipboard(apiKey || "", "PEPPER_API_KEY")}
                    >
                      {copied === "PEPPER_API_KEY" ? (
                        <Check className="h-4 w-4" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                </div>
              </div>
            </div>
          ),
        },
        {
          number: 2,
          title: "Add Jenkinsfile",
          content: (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Download the Jenkinsfile template or create one with your pipeline configuration:
              </p>
              <Button
                onClick={() => downloadTemplate("jenkins")}
                className="w-full"
                variant="outline"
              >
                <Download className="h-4 w-4 mr-2" />
                Download Jenkinsfile
              </Button>
            </div>
          ),
        },
      ],
    },
  };

  const config = platformConfig[selectedPlatform];
  const IconComponent = config.icon;

  if (!apiKey) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            CI/CD Security Scan Setup
          </CardTitle>
          <CardDescription>
            Auto-generate API key and get platform-specific setup instructions
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <label className="text-sm font-medium">API Key Name (optional)</label>
            <Input
              placeholder="cicd"
              value={apiKeyName}
              onChange={(e) => setApiKeyName(e.target.value)}
              disabled={creatingKey}
            />
            <p className="text-xs text-muted-foreground">
              A descriptive name to identify this key in your API keys list
            </p>
          </div>
          <Button
            onClick={() => void createApiKey()}
            disabled={creatingKey}
            className="w-full"
            size="lg"
          >
            {creatingKey ? "Creating API Key…" : "Create API Key & Continue"}
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <IconComponent className="h-5 w-5" />
          Set up {config.name}
        </CardTitle>
        <CardDescription>{config.description}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="grid grid-cols-3 gap-2">
          {(["github", "gitlab", "jenkins"] as Platform[]).map((platform) => (
            <Button
              key={platform}
              variant={selectedPlatform === platform ? "default" : "outline"}
              onClick={() => {
                setSelectedPlatform(platform);
                setCurrentStep(0);
              }}
              className="text-xs"
            >
              {platformConfig[platform].name}
            </Button>
          ))}
        </div>

        <div className="space-y-4">
          {config.steps.map((step, idx) => (
            <div key={idx} className={`space-y-3 p-3 rounded-lg border ${
              idx <= currentStep ? "border-primary/20 bg-primary/5" : "border-muted"
            }`}>
              <div className="flex items-center gap-2">
                <Badge variant={idx <= currentStep ? "default" : "outline"}>
                  Step {step.number}
                </Badge>
                <h3 className="font-medium text-sm">{step.title}</h3>
              </div>
              {idx <= currentStep && <div>{step.content}</div>}
            </div>
          ))}
        </div>

        <div className="flex gap-2 justify-end">
          <Button
            variant="outline"
            onClick={() => setCurrentStep(Math.max(0, currentStep - 1))}
            disabled={currentStep === 0}
          >
            Previous
          </Button>
          <Button
            onClick={() => setCurrentStep(Math.min(config.steps.length - 1, currentStep + 1))}
            disabled={currentStep === config.steps.length - 1}
          >
            Next
          </Button>
          <Button
            variant="outline"
            onClick={() => {
              setApiKey(null);
              setCurrentStep(0);
            }}
          >
            Start Over
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
