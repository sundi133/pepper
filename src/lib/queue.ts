import { Queue } from "bullmq";
import { redisConnection } from "./redis";

export const SCAN_QUEUE_NAME = "pepper-scans";

let _scanQueue: Queue | undefined;

export function getScanQueue(): Queue {
  if (!_scanQueue) {
    _scanQueue = new Queue(SCAN_QUEUE_NAME, {
      connection: redisConnection,
      defaultJobOptions: {
        attempts: 2,
        backoff: { type: "exponential", delay: 5000 },
        removeOnComplete: { count: 1000 },
        removeOnFail: { count: 500 },
      },
    });
  }
  return _scanQueue;
}

// Keep backward compat — lazy getter
export const scanQueue = new Proxy({} as Queue, {
  get(_target, prop) {
    return Reflect.get(getScanQueue(), prop);
  },
});

export interface ScanJobData {
  scanId: string;
  projectId: string;
  sourceType: "UPLOAD" | "GIT_CLONE" | "SVN_CHECKOUT" | "WEBHOOK";
  sourceRef: string;
  scanType: "FULL" | "INCREMENTAL" | "SAST_ONLY" | "SCA_ONLY" | "SECRETS_ONLY";
  baseSha?: string;
  commitSha?: string;
  repoUrl?: string;
  svnUrl?: string;
  svnRevision?: string;
  svnUsername?: string;
  svnPassword?: string;
  branch?: string;
  orgSettings: {
    llmProvider: string;
    llmBaseUrl: string;
    llmModel: string;
    llmApiKey?: string;
    enableLlmSast: boolean;
    enableLlmSecrets: boolean;
    osvApiUrl: string;
  };
  buildGate?: {
    maxCritical: number;
    maxHigh: number;
    maxMedium: number;
    maxLow: number;
    failOnNew: boolean;
  };
}
