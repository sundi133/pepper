"use client";

import { useState, useEffect } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Plus, Pencil, Trash2, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

interface Policy {
  id: string;
  name: string;
  description?: string;
  rule: string;
  severity: string;
  category?: string;
  enabled: boolean;
  createdAt: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "bg-red-100 text-red-800",
  HIGH: "bg-orange-100 text-orange-800",
  MEDIUM: "bg-yellow-100 text-yellow-800",
  LOW: "bg-blue-100 text-blue-800",
};

const EXAMPLE_POLICIES = [
  {
    name: "No hardcoded API URLs",
    rule: "Flag any hardcoded API endpoint URLs (http:// or https://) in source code. All API URLs should come from environment variables or configuration files.",
    severity: "MEDIUM",
    category: "Configuration",
  },
  {
    name: "PII must be encrypted at rest",
    rule: "Any code that stores personally identifiable information (PII) — such as email, phone, SSN, date of birth, address — to a database must use encryption. Flag database writes of PII fields that are not encrypted before storage.",
    severity: "HIGH",
    category: "Data Privacy",
  },
  {
    name: "No direct database queries in controllers",
    rule: "Controller/handler functions should not contain direct SQL queries or ORM calls. All data access must go through a service or repository layer. Flag any raw SQL, Prisma, Sequelize, or ORM calls inside route handlers or controllers.",
    severity: "MEDIUM",
    category: "Architecture",
  },
  {
    name: "All API endpoints must have rate limiting",
    rule: "Every public API endpoint must have rate limiting middleware applied. Flag routes or controllers that handle HTTP requests without rate limiting.",
    severity: "HIGH",
    category: "Security",
  },
  {
    name: "Logging must not contain sensitive data",
    rule: "Log statements (console.log, logger.info, etc.) must not include passwords, tokens, API keys, credit card numbers, SSNs, or other sensitive data. Flag any logging of variables that could contain sensitive information.",
    severity: "CRITICAL",
    category: "Compliance",
  },
];

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null);
  const [form, setForm] = useState({
    name: "",
    description: "",
    rule: "",
    severity: "HIGH",
    category: "",
    enabled: true,
  });

  useEffect(() => {
    fetchPolicies();
  }, []);

  async function fetchPolicies() {
    try {
      const res = await fetch("/api/settings/policies");
      const data = await res.json();
      setPolicies(data.policies || []);
    } catch {
      toast.error("Failed to load policies");
    } finally {
      setLoading(false);
    }
  }

  function openCreate() {
    setEditingPolicy(null);
    setForm({
      name: "",
      description: "",
      rule: "",
      severity: "HIGH",
      category: "",
      enabled: true,
    });
    setDialogOpen(true);
  }

  function openEdit(policy: Policy) {
    setEditingPolicy(policy);
    setForm({
      name: policy.name,
      description: policy.description || "",
      rule: policy.rule,
      severity: policy.severity,
      category: policy.category || "",
      enabled: policy.enabled,
    });
    setDialogOpen(true);
  }

  function loadExample(example: (typeof EXAMPLE_POLICIES)[0]) {
    setForm((f) => ({
      ...f,
      name: example.name,
      rule: example.rule,
      severity: example.severity,
      category: example.category,
    }));
  }

  async function handleSave() {
    if (!form.name || !form.rule) {
      toast.error("Name and rule are required");
      return;
    }

    try {
      if (editingPolicy) {
        const res = await fetch(`/api/settings/policies/${editingPolicy.id}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(form),
        });
        if (!res.ok) throw new Error("Failed to update");
        toast.success("Policy updated");
      } else {
        const res = await fetch("/api/settings/policies", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(form),
        });
        if (!res.ok) throw new Error("Failed to create");
        toast.success("Policy created");
      }

      setDialogOpen(false);
      fetchPolicies();
    } catch {
      toast.error("Failed to save policy");
    }
  }

  async function handleDelete(id: string) {
    if (!confirm("Delete this policy?")) return;

    try {
      await fetch(`/api/settings/policies/${id}`, { method: "DELETE" });
      toast.success("Policy deleted");
      fetchPolicies();
    } catch {
      toast.error("Failed to delete policy");
    }
  }

  async function handleToggle(id: string, enabled: boolean) {
    try {
      await fetch(`/api/settings/policies/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled }),
      });
      fetchPolicies();
    } catch {
      toast.error("Failed to update policy");
    }
  }

  return (
    <div className="max-w-4xl space-y-6">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Policies" },
        ]}
      />
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Custom Security Policies</h1>
          <p className="text-muted-foreground">
            Define organization-specific security rules that the AI scanner
            checks during every scan
          </p>
        </div>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button onClick={openCreate}>
              <Plus className="mr-2 h-4 w-4" />
              New Policy
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-2xl">
            <DialogHeader>
              <DialogTitle>
                {editingPolicy ? "Edit Policy" : "Create Security Policy"}
              </DialogTitle>
              <DialogDescription>
                Write a natural language rule that the AI will enforce during
                code scanning. Be specific about what to flag and what is
                acceptable.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4 py-2">
              <div className="space-y-2">
                <Label>Policy Name</Label>
                <Input
                  value={form.name}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, name: e.target.value }))
                  }
                  placeholder="e.g., No hardcoded API URLs"
                />
              </div>

              <div className="space-y-2">
                <Label>Rule (natural language — describe what to flag)</Label>
                <Textarea
                  value={form.rule}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, rule: e.target.value }))
                  }
                  placeholder="e.g., Flag any hardcoded API endpoint URLs in source code. All API URLs should come from environment variables."
                  rows={4}
                />
                <p className="text-xs text-muted-foreground">
                  Be specific: describe what pattern is bad, what is acceptable,
                  and any exceptions.
                </p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Severity</Label>
                  <Select
                    value={form.severity}
                    onValueChange={(v) =>
                      setForm((f) => ({ ...f, severity: v }))
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="CRITICAL">Critical</SelectItem>
                      <SelectItem value="HIGH">High</SelectItem>
                      <SelectItem value="MEDIUM">Medium</SelectItem>
                      <SelectItem value="LOW">Low</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>Category (optional)</Label>
                  <Input
                    value={form.category}
                    onChange={(e) =>
                      setForm((f) => ({ ...f, category: e.target.value }))
                    }
                    placeholder="e.g., Compliance, Architecture"
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label>Description (optional)</Label>
                <Input
                  value={form.description}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, description: e.target.value }))
                  }
                  placeholder="Brief context for why this policy exists"
                />
              </div>

              {/* Example policies */}
              {!editingPolicy && (
                <div className="space-y-2">
                  <Label className="text-xs text-muted-foreground">
                    Quick start — load an example:
                  </Label>
                  <div className="flex flex-wrap gap-1.5">
                    {EXAMPLE_POLICIES.map((ex, i) => (
                      <button
                        key={i}
                        type="button"
                        onClick={() => loadExample(ex)}
                        className="rounded-md border px-2 py-1 text-xs hover:bg-muted transition-colors"
                      >
                        {ex.name}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={() => setDialogOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleSave}>
                {editingPolicy ? "Update" : "Create"} Policy
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* How it works */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldCheck className="h-5 w-5" />
            How Custom Policies Work
          </CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-2">
          <p>
            Custom policies are{" "}
            <strong>injected into the AI scanner prompt</strong> during every
            scan. The LLM checks each code chunk against your policies alongside
            standard vulnerability detection —{" "}
            <strong>no extra LLM calls</strong> for the first 10 policies.
          </p>
          <p>
            If you have more than 10 policies, additional ones are checked in a
            separate lightweight pass (batches of 10, ~1 extra LLM call per
            batch per file).
          </p>
          <p>
            Write rules in plain English. Be specific about what is bad, what is
            acceptable, and mention exceptions. The more precise your rule, the
            fewer false positives.
          </p>
        </CardContent>
      </Card>

      {/* Policy List */}
      <Card>
        <CardHeader>
          <CardTitle>Policies ({policies.length})</CardTitle>
          <CardDescription>
            Enabled policies are enforced during every scan
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <p className="text-muted-foreground text-center py-8">Loading...</p>
          ) : policies.length === 0 ? (
            <p className="text-muted-foreground text-center py-8">
              No policies yet. Create your first custom security policy.
            </p>
          ) : (
            <div className="space-y-3">
              {policies.map((policy) => (
                <div
                  key={policy.id}
                  className={`rounded-lg border p-4 ${!policy.enabled ? "opacity-50" : ""}`}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-medium">{policy.name}</span>
                        <Badge
                          variant="outline"
                          className={`text-[10px] ${SEVERITY_COLORS[policy.severity] || ""}`}
                        >
                          {policy.severity}
                        </Badge>
                        {policy.category && (
                          <Badge variant="secondary" className="text-[10px]">
                            {policy.category}
                          </Badge>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground line-clamp-2">
                        {policy.rule}
                      </p>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <Switch
                        checked={policy.enabled}
                        onCheckedChange={(v) => handleToggle(policy.id, v)}
                      />
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8"
                        onClick={() => openEdit(policy)}
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8 text-destructive"
                        onClick={() => handleDelete(policy.id)}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
