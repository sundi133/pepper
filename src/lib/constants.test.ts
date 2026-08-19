import { describe, it, expect } from "vitest";
import { detectIacFileType, FILE_EXTENSIONS } from "./constants";

describe("FILE_EXTENSIONS", () => {
  it("includes server-rendered template formats so SAST/zero-day scan them", () => {
    const templateExts = [
      ".ejs",
      ".hbs",
      ".handlebars",
      ".njk",
      ".nunjucks",
      ".mustache",
      ".twig",
      ".pug",
      ".jade",
      ".vue",
      ".svelte",
      ".erb",
      ".cshtml",
      ".jinja",
      ".jinja2",
    ];
    for (const ext of templateExts) {
      expect(FILE_EXTENSIONS[ext], ext).toBe("template");
    }
  });

  it("does not scan plain static .html as a server template", () => {
    expect(FILE_EXTENSIONS[".html"]).toBeUndefined();
  });
});

describe("detectIacFileType", () => {
  it("classifies known server/proxy config basenames as server-config", () => {
    const cases = [
      "nginx.conf",
      "etc/nginx/sites-available/default",
      "etc/nginx/nginx.conf",
      "etc/apache2/httpd.conf",
      "etc/apache2/apache2.conf",
      "etc/apache/apache.conf",
      "Caddyfile",
      "etc/caddy/Caddyfile",
      "etc/haproxy/haproxy.cfg",
      "etc/lighttpd/lighttpd.conf",
      "etc/varnish/varnish.vcl",
      "public/.htaccess",
      "web.config",
      "conf/server.xml",
      "src/main/resources/application.properties",
      "src/main/resources/application.yml",
      "src/main/resources/application.yaml",
      "etc/nginx/conf.d/default.conf",
      "etc/nginx/sites-enabled/example",
    ];
    for (const fp of cases) {
      expect(detectIacFileType(fp), fp).toBe("server-config");
    }
  });

  it("does not classify non-config source or unrelated yaml as server-config", () => {
    const cases = [
      "src/app.ts",
      "src/app.js",
      "package.json",
      "k8s/deployment.yaml",
      "docker-compose.yml",
      "main.tf",
      "values.yaml",
      "app.css",
      "Dockerfile",
      ".gitlab-ci.yml",
    ];
    for (const fp of cases) {
      expect(detectIacFileType(fp), fp).not.toBe("server-config");
    }
  });
});
