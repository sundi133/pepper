-- Add dedicated scan types for IaC and zero-day (manual New Scan + API).
ALTER TYPE "ScanType" ADD VALUE IF NOT EXISTS 'IAC_ONLY';
ALTER TYPE "ScanType" ADD VALUE IF NOT EXISTS 'ZERO_DAY_ONLY';
