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

  it("does not report missing LABELs, which is not a security issue", () => {
    const lints = lintDockerfile(parseDockerfile(`FROM node:20\nUSER app`, "Dockerfile"));
    expect(lints.some((l) => l.ruleId === "DOCKERFILE-NO-LABELS")).toBe(false);
  });

  describe("multi-stage builds", () => {
    const rules = (content: string) =>
      lintDockerfile(parseDockerfile(content, "Dockerfile")).map((l) => `${l.ruleId}@${l.line}`);

    it("judges the user of the final image, not of build stages", () => {
      expect(
        rules(`FROM rust:1.80 AS builder
RUN cargo build --release
FROM debian:12-slim
COPY --from=builder /app /app
USER app:app`),
      ).toEqual(["DOCKERFILE-NO-DIGEST-PIN@1"]);
    });

    it("reports a final image that runs as root, once", () => {
      const r = rules(`FROM rust:1.80 AS builder
RUN cargo build
FROM debian:12-slim
CMD ["/app"]`);
      expect(r.filter((x) => x.startsWith("DOCKERFILE-NO-USER"))).toEqual(["DOCKERFILE-NO-USER@3"]);
    });

    it("inherits USER and HEALTHCHECK from the stage the final image is built on", () => {
      const r = rules(`FROM node:20 AS base
USER node
HEALTHCHECK CMD curl -f http://localhost:3000
FROM base
EXPOSE 3000
CMD ["node", "server.js"]`);
      expect(r).toEqual(["DOCKERFILE-NO-DIGEST-PIN@1"]);
    });

    it("does not ask for a tag or digest on scratch, an earlier stage or an ARG image", () => {
      expect(
        rules(`ARG BASE=node:20
FROM rust:1.80@sha256:${"a".repeat(64)} AS builder
FROM builder AS test
FROM \${BASE} AS runtime
USER app
FROM scratch
COPY --from=builder /out /`),
      ).toEqual([]);
    });

    it("reports a floating tag per stage, and the digest pin once, not on top of it", () => {
      expect(
        rules(`FROM rust:latest AS builder
FROM node:20 AS web
FROM debian:12
USER app`),
      ).toEqual(["DOCKERFILE-LATEST-TAG@1", "DOCKERFILE-NO-DIGEST-PIN@2"]);
    });

    it("a scratch image that runs a binary still needs a user", () => {
      expect(rules(`FROM scratch\nCOPY app /app\nENTRYPOINT ["/app"]`)).toEqual(["DOCKERFILE-NO-USER@1"]);
    });

    it("flags USER 0 like USER root", () => {
      expect(rules(`FROM node:20@sha256:${"a".repeat(64)}\nUSER 0`)).toEqual(["DOCKERFILE-ROOT-USER@2"]);
    });
  });

  describe("hardcoded secrets", () => {
    const secretRules = (content: string) =>
      lintDockerfile(parseDockerfile(`FROM node:20\nUSER app\n${content}`, "Dockerfile"))
        .filter((l) => l.ruleId.startsWith("DOCKERFILE-HARDCODED-SECRET"))
        .map((l) => l.ruleId);

    it("ignores names that only look like secrets, references and paths", () => {
      for (const line of [
        "ENV AUTHOR=jane",
        "ENV OAUTH_URL=https://login.corp.example/oauth",
        "ENV TOKENIZERS_PARALLELISM=false",
        "ENV DB_PASSWORD_FILE=/run/secrets/db_password",
        "ENV API_KEY=$API_KEY",
        "ENV API_KEY=${API_KEY}",
        'ENV API_KEY=""',
        "ENV SECRET_KEY=changeme",
        "ENV SESSION_TOKEN_TTL=3600",
        "RUN --mount=type=secret,id=npm_token npm ci",
        "RUN apt-get install -y libauth-dev ca-certificates",
        "RUN pip install --index-url https://pypi.org/simple python-keystoneauth1",
        "RUN curl -H \"Authorization: Bearer $TOKEN\" https://api.corp.example/x",
        "RUN ./configure --password=$DB_PASSWORD",
        "RUN echo token expired, authenticate again",
      ]) {
        expect(secretRules(line), line).toEqual([]);
      }
    });

    it("still reports literal credentials", () => {
      expect(secretRules("ENV DATABASE_PASSWORD=secret123")).toEqual(["DOCKERFILE-HARDCODED-SECRET-ENV"]);
      expect(secretRules("ENV API_KEY 9f8a7b6c5d4e3f2a")).toEqual(["DOCKERFILE-HARDCODED-SECRET-ENV"]);
      expect(secretRules(`ENV AWS_ID=${"AKIA"}${"IOSFODNN7ABCDEFG"}`)).toEqual(["DOCKERFILE-HARDCODED-SECRET-ENV"]);
      expect(secretRules("RUN npm config set //registry.npmjs.org/:_authToken=abc123def456")).toEqual([
        "DOCKERFILE-HARDCODED-SECRET-RUN",
      ]);
      expect(secretRules("RUN mysql --password hunter2pw -e 'select 1'")).toEqual(["DOCKERFILE-HARDCODED-SECRET-RUN"]);
      expect(secretRules("RUN echo \"password=S3cretValue9\" > /etc/app.conf")).toEqual(["DOCKERFILE-HARDCODED-SECRET-RUN"]);
    });
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
