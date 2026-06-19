"use client";

import { IntegrationsDashboard } from "@/components/settings/integrations-dashboard";
import { WebhookIntegrations } from "@/components/settings/webhook-integrations";

export default function IntegrationsPage() {
  return (
    <div className="space-y-0">
      <IntegrationsDashboard />
      <div className="max-w-2xl space-y-6 px-8 py-8">
        <div>
          <h2 className="text-2xl font-bold">Webhook Setup</h2>
          <p className="text-muted-foreground mt-2">
            Configure webhooks for incremental scanning on pull requests and pushes.
          </p>
        </div>
        <WebhookIntegrations />
      </div>
    </div>
  );
}
