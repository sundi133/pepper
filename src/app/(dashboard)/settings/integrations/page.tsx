"use client";

import { IntegrationsDashboard } from "@/components/settings/integrations-dashboard";
import { WebhookIntegrations } from "@/components/settings/webhook-integrations";

export default function IntegrationsPage() {
  return (
    <div className="space-y-0">
      <IntegrationsDashboard />
      <WebhookIntegrations />
    </div>
  );
}
