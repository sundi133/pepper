"use client";

import { useState, useEffect, useCallback } from "react";
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";
import { toast } from "sonner";
import { Loader2, Plus, Trash2, ShieldOff } from "lucide-react";

type SuppressionRule = {
  id: string;
  ruleId: string | null;
  cweId: string | null;
  scanner: string | null;
  filePathPattern: string | null;
  titlePattern: string | null;
  snippetHash: string | null;
  reason: string;
  source: string;
  enabled: boolean;
  createdAt: string;
  createdBy: string | null;
};

export default function SuppressionsPage() {
  const [rules, setRules] = useState<SuppressionRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);

  const loadRules = useCallback(async () => {
    try {
      const res = await fetch("/api/settings/suppressions?limit=200");
      if (!res.ok) throw new Error("Failed to load");
      const data = await res.json();
      setRules(data.rules || []);
    } catch {
      toast.error("Failed to load suppression rules");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadRules();
  }, [loadRules]);

  async function toggleRule(id: string, enabled: boolean) {
    try {
      const res = await fetch(`/api/settings/suppressions/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled }),
      });
      if (!res.ok) throw new Error("Failed to update");
      setRules((prev) => prev.map((r) => (r.id === id ? { ...r, enabled } : r)));
      toast.success(enabled ? "Rule enabled" : "Rule disabled");
    } catch {
      toast.error("Failed to update rule");
    }
  }

  async function deleteRule(id: string) {
    setDeleting(id);
    try {
      const res = await fetch(`/api/settings/suppressions/${id}`, {
        method: "DELETE",
      });
      if (!res.ok) throw new Error("Failed to delete");
      setRules((prev) => prev.filter((r) => r.id !== id));
      toast.success("Rule deleted");
    } catch {
      toast.error("Failed to delete rule");
    } finally {
      setDeleting(null);
    }
  }

  const activeCount = rules.filter((r) => r.enabled).length;

  return (
    <div className="space-y-6 pb-10">
      <PageBreadcrumb
        items={[
          { label: "Dashboard", href: "/dashboard" },
          { label: "Settings" },
          { label: "Suppression Rules" },
        ]}
      />

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <ShieldOff className="h-5 w-5" />
                Suppression Rules
              </CardTitle>
              <CardDescription className="mt-1">
                Rules are auto-created when you mark findings as false positive.
                Matching findings in future scans are automatically suppressed.
                {activeCount > 0 && (
                  <Badge variant="secondary" className="ml-2">
                    {activeCount} active
                  </Badge>
                )}
              </CardDescription>
            </div>
            <Button onClick={() => setCreateOpen(true)} size="sm" className="gap-1.5">
              <Plus className="h-4 w-4" />
              Add Rule
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-12 text-muted-foreground">
              <Loader2 className="h-5 w-5 animate-spin mr-2" />
              Loading rules...
            </div>
          ) : rules.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <ShieldOff className="h-10 w-10 mx-auto mb-3 opacity-50" />
              <p className="font-medium">No suppression rules yet</p>
              <p className="text-sm mt-1">
                Mark findings as &quot;False Positive&quot; to auto-create rules, or add one manually.
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-12">Active</TableHead>
                  <TableHead>Matcher</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead className="w-20">Source</TableHead>
                  <TableHead className="w-32">Created</TableHead>
                  <TableHead className="w-12" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.map((rule) => (
                  <TableRow key={rule.id} className={!rule.enabled ? "opacity-50" : ""}>
                    <TableCell>
                      <Switch
                        checked={rule.enabled}
                        onCheckedChange={(v) => void toggleRule(rule.id, v)}
                      />
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1.5">
                        {rule.scanner && (
                          <Badge variant="outline" className="text-[10px]">
                            {rule.scanner}
                          </Badge>
                        )}
                        {rule.cweId && (
                          <Badge variant="outline" className="text-[10px]">
                            {rule.cweId}
                          </Badge>
                        )}
                        {rule.ruleId && (
                          <Badge variant="outline" className="text-[10px]">
                            {rule.ruleId}
                          </Badge>
                        )}
                        {rule.titlePattern && (
                          <span className="text-xs text-muted-foreground truncate max-w-[200px]">
                            &quot;{rule.titlePattern}&quot;
                          </span>
                        )}
                        {rule.filePathPattern && (
                          <code className="text-[10px] bg-muted px-1 rounded truncate max-w-[200px]">
                            {rule.filePathPattern}
                          </code>
                        )}
                        {rule.snippetHash && (
                          <Badge variant="secondary" className="text-[10px]">
                            snippet match
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <p className="text-sm text-muted-foreground line-clamp-2 max-w-[300px]">
                        {rule.reason}
                      </p>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={rule.source === "user" ? "default" : "secondary"}
                        className="text-[10px]"
                      >
                        {rule.source}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {new Date(rule.createdAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8"
                        disabled={deleting === rule.id}
                        onClick={() => void deleteRule(rule.id)}
                      >
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <CreateRuleDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={() => void loadRules()}
      />
    </div>
  );
}

function CreateRuleDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: () => void;
}) {
  const [saving, setSaving] = useState(false);
  const [form, setForm] = useState({
    scanner: "",
    cweId: "",
    ruleId: "",
    filePathPattern: "",
    titlePattern: "",
    reason: "",
  });

  async function handleSubmit() {
    if (!form.reason.trim()) {
      toast.error("Reason is required");
      return;
    }
    setSaving(true);
    try {
      const res = await fetch("/api/settings/suppressions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scanner: form.scanner || undefined,
          cweId: form.cweId || undefined,
          ruleId: form.ruleId || undefined,
          filePathPattern: form.filePathPattern || undefined,
          titlePattern: form.titlePattern || undefined,
          reason: form.reason,
        }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error || "Failed to create");
      }
      toast.success("Suppression rule created");
      onOpenChange(false);
      setForm({ scanner: "", cweId: "", ruleId: "", filePathPattern: "", titlePattern: "", reason: "" });
      onCreated();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to create rule");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Create Suppression Rule</DialogTitle>
          <DialogDescription>
            Findings matching all specified fields will be auto-suppressed.
            Leave fields empty to match any value.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div>
            <Label>Scanner (optional)</Label>
            <Input
              placeholder="e.g. SAST_PATTERN, SCA, IAC"
              value={form.scanner}
              onChange={(e) => setForm({ ...form, scanner: e.target.value })}
            />
          </div>
          <div>
            <Label>CWE ID (optional)</Label>
            <Input
              placeholder="e.g. CWE-79"
              value={form.cweId}
              onChange={(e) => setForm({ ...form, cweId: e.target.value })}
            />
          </div>
          <div>
            <Label>Rule ID (optional)</Label>
            <Input
              placeholder="e.g. no-eval, hardcoded-secret"
              value={form.ruleId}
              onChange={(e) => setForm({ ...form, ruleId: e.target.value })}
            />
          </div>
          <div>
            <Label>File path pattern (optional)</Label>
            <Input
              placeholder="e.g. test/, *.test.ts, migrations/"
              value={form.filePathPattern}
              onChange={(e) => setForm({ ...form, filePathPattern: e.target.value })}
            />
          </div>
          <div>
            <Label>Title contains (optional)</Label>
            <Input
              placeholder="e.g. Missing rate limit"
              value={form.titlePattern}
              onChange={(e) => setForm({ ...form, titlePattern: e.target.value })}
            />
          </div>
          <div>
            <Label>Reason (required)</Label>
            <Textarea
              placeholder="Why should matching findings be suppressed?"
              value={form.reason}
              onChange={(e) => setForm({ ...form, reason: e.target.value })}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={() => void handleSubmit()} disabled={saving}>
            {saving ? "Creating..." : "Create Rule"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
