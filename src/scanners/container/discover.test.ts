import { describe, it, expect } from "vitest";
import {
  parseCompose,
  parseDockerfile,
  parsePacker,
  parseSamTemplate,
  parseServerless,
  parseTerraformImages,
  isVmAmiRef,
} from "./discover";

describe("artifact image discovery", () => {
  it("parses Dockerfile FROM lines", () => {
    const refs = parseDockerfile("FROM node:20\nFROM scratch\nFROM $BASE\n", "Dockerfile");
    expect(refs).toHaveLength(1);
    expect(refs[0]).toMatchObject({
      image: "node:20",
      kind: "container",
      line: 1,
    });
  });

  it("parses serverless image and ImageUri", () => {
    const refs = parseServerless(
      `functions:\n  api:\n    image: 123456.dkr.ecr.us-east-1.amazonaws.com/api:latest\n    ImageUri: public.ecr.aws/lambda/nodejs:18\n`,
      "serverless.yml",
    );
    expect(refs.length).toBeGreaterThanOrEqual(2);
    expect(refs.every((r) => r.kind === "serverless")).toBe(true);
  });

  it("parses Terraform AMI and container image_uri", () => {
    const refs = parseTerraformImages(
      `resource "aws_instance" "web" {\n  ami = "ami-0abcdef1234567890"\n}\nimage_uri = "123456789012.dkr.ecr.us-east-1.amazonaws.com/app:v1"\n`,
      "main.tf",
    );
    expect(refs).toHaveLength(2);
    expect(refs[0].kind).toBe("vm");
    expect(refs[0].image).toMatch(/^ami-/);
    expect(refs[1].image).toContain(".dkr.ecr.");
  });

  it("parses SAM template ImageUri", () => {
    const refs = parseSamTemplate(
      `Resources:\n  ApiFunction:\n    Properties:\n      ImageUri: public.ecr.aws/sam/emulation-nodejs18:latest\n`,
      "template.yaml",
    );
    expect(refs).toHaveLength(1);
    expect(refs[0].kind).toBe("serverless");
  });

  it("parses Packer source_ami", () => {
    const refs = parsePacker(
      `source "amazon-ebs" "example" {\n  source_ami = "ami-0abcdef1234567890"\n}\n`,
      "build.pkr.hcl",
    );
    expect(refs).toHaveLength(1);
    expect(isVmAmiRef(refs[0])).toBe(true);
  });

  it("parses compose image entries", () => {
    const refs = parseCompose("services:\n  web:\n    image: nginx:1.25\n", "compose.yml");
    expect(refs[0]).toMatchObject({ image: "nginx:1.25", kind: "container" });
  });
});
