import * as fs from "fs";
import * as path from "path";

export type ArtifactKind = "container" | "serverless" | "vm";

export interface ImageRef {
  image: string;
  filePath: string;
  line: number;
  kind: ArtifactKind;
}

const DOCKERFILE_NAMES = new Set(["Dockerfile", "dockerfile", "Containerfile"]);
const COMPOSE_NAMES = new Set([
  "docker-compose.yml",
  "docker-compose.yaml",
  "compose.yml",
  "compose.yaml",
]);
const SERVERLESS_NAMES = new Set(["serverless.yml", "serverless.yaml"]);

function isScannableImageRef(image: string): boolean {
  const lower = image.toLowerCase();
  if (lower === "scratch") return false;
  if (image.startsWith("$") || image.startsWith("${")) return false;
  return true;
}

function pushRef(
  refs: ImageRef[],
  image: string,
  filePath: string,
  line: number,
  kind: ArtifactKind,
): void {
  const trimmed = image.replace(/^['"]|['"]$/g, "").trim();
  if (!trimmed || !isScannableImageRef(trimmed)) return;
  refs.push({ image: trimmed, filePath, line, kind });
}

export function parseDockerfile(content: string, filePath: string): ImageRef[] {
  const refs: ImageRef[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)/i);
    if (m) pushRef(refs, m[1], filePath, i + 1, "container");
  }
  return refs;
}

export function parseCompose(content: string, filePath: string): ImageRef[] {
  const refs: ImageRef[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^\s*image:\s*["']?([^"'\s#]+)/);
    if (m) pushRef(refs, m[1], filePath, i + 1, "container");
  }
  return refs;
}

export function parseServerless(content: string, filePath: string): ImageRef[] {
  const refs: ImageRef[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const image = line.match(/^\s*image:\s*["']?([^"'\s#]+)/i);
    if (image) pushRef(refs, image[1], filePath, i + 1, "serverless");
    const uri = line.match(/^\s*ImageUri:\s*["']?([^"'\s#]+)/i);
    if (uri) pushRef(refs, uri[1], filePath, i + 1, "serverless");
  }
  return refs;
}

export function parseTerraformImages(content: string, filePath: string): ImageRef[] {
  const refs: ImageRef[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const ami =
      line.match(/^\s*(?:ami|image_id)\s*=\s*["']?(ami-[a-f0-9]+)/i) ||
      line.match(/^\s*image\s*=\s*["']?(ami-[a-f0-9]+)/i);
    if (ami) pushRef(refs, ami[1], filePath, i + 1, "vm");

    const uri = line.match(
      /^\s*(?:image_uri|repository_uri|container_image)\s*=\s*["']([^"']+)["']/i,
    );
    if (uri && uri[1].includes("/")) {
      pushRef(refs, uri[1], filePath, i + 1, "vm");
    }
  }
  return refs;
}

export function parseSamTemplate(content: string, filePath: string): ImageRef[] {
  const refs: ImageRef[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const uri = line.match(/^\s*ImageUri:\s*["']?([^"'\s#]+)/i);
    if (uri) pushRef(refs, uri[1], filePath, i + 1, "serverless");
    const image = line.match(/^\s*Image:\s*["']?([^"'\s#]+)/i);
    if (image && image[1].includes("/")) {
      pushRef(refs, image[1], filePath, i + 1, "serverless");
    }
  }
  return refs;
}

export function parsePacker(content: string, filePath: string): ImageRef[] {
  const refs: ImageRef[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const ami = line.match(
      /^\s*(?:source_ami|ami_filter|image_id)\s*=\s*["']?(ami-[a-f0-9]+)/i,
    );
    if (ami) pushRef(refs, ami[1], filePath, i + 1, "vm");
    const image = line.match(/^\s*image\s*=\s*["']([^"']+)["']/i);
    if (image && image[1].includes("/")) {
      pushRef(refs, image[1], filePath, i + 1, "vm");
    }
  }
  return refs;
}

function classifyFile(rel: string): "dockerfile" | "compose" | "serverless" | "terraform" | "sam" | "packer" | null {
  const base = path.basename(rel);
  const lower = rel.toLowerCase();
  if (DOCKERFILE_NAMES.has(base) || /\.dockerfile$/i.test(base)) return "dockerfile";
  if (COMPOSE_NAMES.has(base)) return "compose";
  if (SERVERLESS_NAMES.has(base)) return "serverless";
  if (lower.endsWith(".tf") || lower.endsWith(".tfvars")) return "terraform";
  if (
    lower.includes("/sam/") ||
    (base.startsWith("template.") &&
      (lower.endsWith(".yaml") || lower.endsWith(".yml") || lower.endsWith(".json")))
  ) {
    return "sam";
  }
  if (/\.pkr\.(hcl|json)$/i.test(base) || lower.includes("packer")) return "packer";
  return null;
}

/** Discover container, serverless, and VM image references across supported artifact manifests. */
export function discoverArtifactImages(
  workDir: string,
  fileList: string[],
): ImageRef[] {
  const refs: ImageRef[] = [];
  for (const rel of fileList) {
    const kind = classifyFile(rel);
    if (!kind) continue;
    try {
      const content = fs.readFileSync(path.join(workDir, rel), "utf-8");
      switch (kind) {
        case "dockerfile":
          refs.push(...parseDockerfile(content, rel));
          break;
        case "compose":
          refs.push(...parseCompose(content, rel));
          break;
        case "serverless":
          refs.push(...parseServerless(content, rel));
          break;
        case "terraform":
          refs.push(...parseTerraformImages(content, rel));
          break;
        case "sam":
          refs.push(...parseSamTemplate(content, rel));
          break;
        case "packer":
          refs.push(...parsePacker(content, rel));
          break;
      }
    } catch {
      continue;
    }
  }
  const seen = new Set<string>();
  return refs.filter((r) => {
    if (seen.has(r.image)) return false;
    seen.add(r.image);
    return true;
  });
}

export function isVmAmiRef(ref: ImageRef): boolean {
  return ref.kind === "vm" && /^ami-[a-f0-9]+$/i.test(ref.image);
}
