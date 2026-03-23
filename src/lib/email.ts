import nodemailer from "nodemailer";
import { prisma } from "./prisma";
import { logger } from "./logger";

interface SmtpConfig {
  host: string;
  port: number;
  user?: string;
  password?: string;
  fromAddress: string;
  useTls: boolean;
}

async function getSmtpConfig(orgId: string): Promise<SmtpConfig | null> {
  // First check env vars (simple setup)
  if (process.env.SMTP_HOST) {
    return {
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || "587"),
      user: process.env.SMTP_USER,
      password: process.env.SMTP_PASSWORD,
      fromAddress: process.env.SMTP_FROM || "noreply@pepper-sast.local",
      useTls: process.env.SMTP_TLS !== "false",
    };
  }

  // Then check org settings
  const settings = await prisma.orgSettings.findUnique({
    where: { organizationId: orgId },
  });

  if (!settings?.smtpHost) return null;

  return {
    host: settings.smtpHost,
    port: settings.smtpPort || 587,
    user: settings.smtpUser || undefined,
    password: settings.smtpPassword || undefined,
    fromAddress: settings.smtpFromAddress || "noreply@pepper-sast.local",
    useTls: settings.smtpUseTls,
  };
}

function createTransport(config: SmtpConfig) {
  return nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.port === 465,
    auth:
      config.user && config.password
        ? { user: config.user, pass: config.password }
        : undefined,
    tls: config.useTls ? { rejectUnauthorized: false } : undefined,
  });
}

interface ScanCompleteEmailParams {
  to: string;
  userName?: string;
  projectName: string;
  scanId: string;
  branch?: string;
  severityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  gateResult: string;
  duration?: number;
  baseUrl?: string;
}

export async function sendScanCompleteEmail(
  orgId: string,
  params: ScanCompleteEmailParams,
): Promise<boolean> {
  try {
    const config = await getSmtpConfig(orgId);
    if (!config) {
      logger.info("Email notification skipped: no SMTP configured");
      return false;
    }

    const transport = createTransport(config);
    const total =
      params.severityCounts.critical +
      params.severityCounts.high +
      params.severityCounts.medium +
      params.severityCounts.low;

    const baseUrl =
      params.baseUrl || process.env.NEXTAUTH_URL || "http://localhost:3000";
    const scanUrl = `${baseUrl}/scans/${params.scanId}`;

    const gateBadge =
      params.gateResult === "PASSED"
        ? '<span style="color:#16a34a;font-weight:bold;">PASSED</span>'
        : params.gateResult === "FAILED"
          ? '<span style="color:#dc2626;font-weight:bold;">FAILED</span>'
          : '<span style="color:#6b7280;">PENDING</span>';

    const subject = `[Pepper] Scan complete: ${params.projectName} — ${params.severityCounts.critical + params.severityCounts.high} critical/high findings`;

    const html = `
      <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:600px;margin:0 auto;color:#374151;">
        <div style="background:#1e1b4b;padding:24px;border-radius:8px 8px 0 0;color:white;">
          <h2 style="margin:0;">Scan Complete</h2>
          <p style="margin:4px 0 0;opacity:0.8;">${params.projectName}${params.branch ? ` (${params.branch})` : ""}</p>
        </div>

        <div style="border:1px solid #e5e7eb;border-top:none;padding:24px;border-radius:0 0 8px 8px;">
          <p>Hi ${params.userName || "there"},</p>
          <p>Your security scan has completed. Here's a summary:</p>

          <table style="width:100%;border-collapse:collapse;margin:16px 0;">
            <tr>
              <td style="padding:8px 12px;border:1px solid #e5e7eb;background:#fef2f2;color:#dc2626;font-weight:bold;text-align:center;">Critical<br/>${params.severityCounts.critical}</td>
              <td style="padding:8px 12px;border:1px solid #e5e7eb;background:#fff7ed;color:#ea580c;font-weight:bold;text-align:center;">High<br/>${params.severityCounts.high}</td>
              <td style="padding:8px 12px;border:1px solid #e5e7eb;background:#fefce8;color:#ca8a04;font-weight:bold;text-align:center;">Medium<br/>${params.severityCounts.medium}</td>
              <td style="padding:8px 12px;border:1px solid #e5e7eb;background:#eff6ff;color:#2563eb;font-weight:bold;text-align:center;">Low<br/>${params.severityCounts.low}</td>
            </tr>
          </table>

          <p><strong>Total findings:</strong> ${total}</p>
          <p><strong>Build gate:</strong> ${gateBadge}</p>
          ${params.duration ? `<p><strong>Duration:</strong> ${Math.floor(params.duration / 60)}m ${params.duration % 60}s</p>` : ""}

          <div style="text-align:center;margin:24px 0;">
            <a href="${scanUrl}" style="display:inline-block;background:#4f46e5;color:white;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;">View Full Report</a>
          </div>

          <p style="font-size:12px;color:#9ca3af;text-align:center;margin-top:24px;">
            Pepper SAST — AI-Powered Security Testing
          </p>
        </div>
      </div>
    `;

    await transport.sendMail({
      from: config.fromAddress,
      to: params.to,
      subject,
      html,
    });

    logger.info(
      { to: params.to, scanId: params.scanId },
      "Scan completion email sent",
    );
    return true;
  } catch (err) {
    logger.error(
      { err, to: params.to },
      "Failed to send scan completion email",
    );
    return false;
  }
}
