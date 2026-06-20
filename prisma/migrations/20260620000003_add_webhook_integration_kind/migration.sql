-- Add WEBHOOK to IntegrationKind enum
ALTER TYPE "IntegrationKind" ADD VALUE IF NOT EXISTS 'WEBHOOK';
