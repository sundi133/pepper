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
  sourceType:
    | "UPLOAD"
    | "GIT_CLONE"
    | "SVN_CHECKOUT"
    | "WEBHOOK"
    | "CONTAINER_IMAGE"
    | "DAST_TARGET"
    | "PRECOMMIT";
  sourceRef: string;
  scanType:
    | "FULL"
    | "INCREMENTAL"
    | "SAST_ONLY"
    | "SCA_ONLY"
    | "SECRETS_ONLY"
    | "IAC_ONLY"
    | "ZERO_DAY_ONLY"
    | "CONTAINER_ONLY"
    | "DAST_ONLY";
  baseSha?: string;
  commitSha?: string;
  repoUrl?: string;
  /** Original repo URL without credentials (for logs / parity). */
  repoUrlDisplay?: string;
  svnUrl?: string;
  svnRevision?: string;
  svnUsername?: string;
  svnPassword?: string;
  branch?: string;
  /** Resolve org GitHub OAuth token at worker runtime (never sent from browser). */
  useOrgGithubToken?: boolean;
  /** Resolve org Bitbucket app password at worker runtime (never sent from browser). */
  useOrgBitbucketToken?: boolean;
  useOrgAzureDevOpsToken?: boolean;
  orgSettings: {
    llmProvider: string;
    llmBaseUrl: string;
    llmModel: string;
    llmApiKey?: string;
    enableLlmSast: boolean;
    enableLlmSecrets: boolean;
    osvApiUrl: string;
    vulnDbMode: "online" | "mirror" | "offline";
    orgId?: string;
    dastEnabled?: boolean;
    dastTargetUrl?: string;
    dastEndpoint?: string;
    dastApiKey?: string;
    dastConfigYaml?: string;
  };
  dastTargetUrl?: string;
  buildGate?: {
    maxCritical: number;
    maxHigh: number;
    maxMedium: number;
    maxLow: number;
    failOnNew: boolean;
  };
}
