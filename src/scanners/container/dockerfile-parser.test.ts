import { describe, it, expect } from "vitest";
import { parseDockerfile, lintDockerfile } from "./dockerfile-parser";

describe("Dockerfile Parser", () => {
  it("parses single-stage Dockerfile", () => {
    const content = `FROM node:20-alpine
USER nobody
EXPOSE 3000
HEALTHCHECK CMD curl http://localhost:3000`;
    const stages = parseDockerfile(content, "Dockerfile");
    expect(stages).toHaveLength(1);
    expect(stages[0].baseImage).toBe("node:20-alpine");
    expect(stages[0].user).toBe("nobody");
    expect(stages[0].exposedPorts).toContain(3000);
    expect(stages[0].hasHealthcheck).toBe(true);
  });

  it("parses multi-stage Dockerfile with named stages", () => {
    const content = `FROM node:20 AS builder
RUN npm install
FROM node:20-alpine AS runtime
COPY --from=builder /app/node_modules .
USER app`;
    const stages = parseDockerfile(content, "Dockerfile");
    expect(stages).toHaveLength(2);
    expect(stages[0].stageName).toBe("builder");
    expect(stages[1].stageName).toBe("runtime");
    expect(stages[1].copyFromStages).toContain("builder");
  });

  it("detects untagged base images", () => {
    const content = "FROM ubuntu";
    const stages = parseDockerfile(content, "Dockerfile");
    expect(stages[0].baseHasTag).toBe(false);
  });

  it("detects :latest tag", () => {
    const content = "FROM node:latest";
    const stages = parseDockerfile(content, "Dockerfile");
    expect(stages[0].baseHasTag).toBe(true);
    expect(stages[0].baseImage.endsWith(":latest")).toBe(true);
  });

  it("detects digest pins", () => {
    const content =
      "FROM node:20@sha256:abcd1234567890abcd1234567890abcd1234567890abcd1234567890abcd1234";
    const stages = parseDockerfile(content, "Dockerfile");
    expect(stages[0].baseHasDigest).toBe(true);
  });

  it("parses ENV variables and detects masked secrets", () => {
    const content = `FROM node:20
ENV API_KEY=sk_live_1234567890
ENV NORMAL_VAR=value
ENV PASSWORD=mysecret123`;
    const stages = parseDockerfile(content, "Dockerfile");
    expect(stages[0].envVars.has("API_KEY")).toBe(true);
    expect(stages[0].envVars.has("NORMAL_VAR")).toBe(true);
    expect(stages[0].envVars.has("PASSWORD")).toBe(true);
    expect(stages[0].envVars.get("API_KEY")?.masked).toBe(true);
    expect(stages[0].envVars.get("PASSWORD")?.masked).toBe(true);
  });

  it("parses ARG directives", () => {
    const content = `FROM node:20
ARG NODE_ENV=production
ARG BUILD_VERSION`;
    const stages = parseDockerfile(content, "Dockerfile");
    expect(stages[0].args.has("NODE_ENV")).toBe(true);
    expect(stages[0].args.get("NODE_ENV")?.value).toBe("production");
    expect(stages[0].args.has("BUILD_VERSION")).toBe(true);
    expect(stages[0].args.get("BUILD_VERSION")?.value).toBeUndefined();
  });

  it("parses EXPOSE ports", () => {
    const content = `FROM node:20
EXPOSE 3000
EXPOSE 8080 9000
EXPOSE 5432/tcp`;
    const stages = parseDockerfile(content, "Dockerfile");
    expect(stages[0].exposedPorts).toContain(3000);
    expect(stages[0].exposedPorts).toContain(8080);
    expect(stages[0].exposedPorts).toContain(9000);
    expect(stages[0].exposedPorts).toContain(5432);
  });

  it("parses LABEL directives", () => {
    const content = `FROM node:20
LABEL maintainer="test@example.com"
LABEL version="1.0.0"
LABEL description="Test image"`;
    const stages = parseDockerfile(content, "Dockerfile");
    expect(stages[0].labels.has("maintainer")).toBe(true);
    expect(stages[0].labels.get("maintainer")?.value).toBe('"test@example.com"');
    expect(stages[0].labels.has("version")).toBe(true);
  });

  it("detects platform flag in FROM", () => {
    const content = "FROM --platform=linux/amd64 node:20";
    const stages = parseDockerfile(content, "Dockerfile");
    expect(stages[0].baseImage).toBe("node:20");
  });

  it("lints Dockerfile for security issues", () => {
    const content = `FROM ubuntu:latest
ENV DATABASE_PASSWORD=secret123
RUN apt-get install -y curl`;
    const stages = parseDockerfile(content, "Dockerfile");
    const lints = lintDockerfile(stages);

    const ruleIds = lints.map((l) => l.ruleId);
    expect(ruleIds).toContain("DOCKERFILE-NO-USER");
    expect(ruleIds).toContain("DOCKERFILE-LATEST-TAG");
    expect(ruleIds).toContain("DOCKERFILE-HARDCODED-SECRET-ENV");
  });

  it("detects missing HEALTHCHECK in exposed services", () => {
    const content = `FROM node:20
EXPOSE 3000
ENTRYPOINT ["node", "server.js"]`;
    const stages = parseDockerfile(content, "Dockerfile");
    const lints = lintDockerfile(stages);
    const hasHealthcheckLint = lints.some((l) => l.ruleId === "DOCKERFILE-NO-HEALTHCHECK");
    expect(hasHealthcheckLint).toBe(true);
  });

  it("does not lint HEALTHCHECK when present", () => {
    const content = `FROM node:20
EXPOSE 3000
HEALTHCHECK CMD curl http://localhost:3000`;
    const stages = parseDockerfile(content, "Dockerfile");
    const lints = lintDockerfile(stages);
    const hasHealthcheckLint = lints.some((l) => l.ruleId === "DOCKERFILE-NO-HEALTHCHECK");
    expect(hasHealthcheckLint).toBe(false);
  });

  it("does not lint when USER is set to non-root", () => {
    const content = `FROM node:20
USER app`;
    const stages = parseDockerfile(content, "Dockerfile");
    const lints = lintDockerfile(stages);
    const hasUserLint = lints.some((l) => l.ruleId === "DOCKERFILE-NO-USER");
    expect(hasUserLint).toBe(false);
  });

  it("detects secret patterns in RUN commands", () => {
    const content = `FROM node:20
RUN npm config set //registry.npmjs.org/:_authToken=sk_live_abc123`;
    const stages = parseDockerfile(content, "Dockerfile");
    const lints = lintDockerfile(stages);
    const hasSecretLint = lints.some((l) => l.ruleId === "DOCKERFILE-HARDCODED-SECRET-RUN");
    expect(hasSecretLint).toBe(true);
  });

  it("detects missing LABEL directives", () => {
    const content = `FROM node:20
USER app`;
    const stages = parseDockerfile(content, "Dockerfile");
    const lints = lintDockerfile(stages);
    const hasLabelLint = lints.some((l) => l.ruleId === "DOCKERFILE-NO-LABELS");
    expect(hasLabelLint).toBe(true);
  });

  it("ignores comments and empty lines", () => {
    const content = `# This is a comment
FROM node:20

# Another comment
USER app`;
    const stages = parseDockerfile(content, "Dockerfile");
    expect(stages).toHaveLength(1);
    expect(stages[0].user).toBe("app");
  });
});
