import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { describe, expect, it } from "vitest";
import { buildGradleParser, gradleLockfileParser, pomXmlParser, versionCatalogParser } from "./pom-xml";
import { csprojParser, directoryPackagesPropsParser, packagesConfigParser, packagesLockJsonParser } from "./csproj";
import { cartfileResolvedParser, podfileLockParser } from "./ios";
import { isDependencyFile, parseDependencies } from "../index";

const coords = (deps: Array<{ name: string; version: string }>) => deps.map((d) => `${d.name}@${d.version}`);

describe("Maven pom.xml", () => {
  it("reads dependencies in any element order and resolves ${properties}", () => {
    const pom = `<project>
      <groupId>com.acme</groupId><artifactId>app</artifactId><version>2.1.0</version>
      <properties><jackson.version>2.15.2</jackson.version><log4j.version>\${log4j2.version}</log4j.version><log4j2.version>2.17.1</log4j2.version></properties>
      <dependencies>
        <dependency><artifactId>jackson-databind</artifactId><groupId>com.fasterxml.jackson.core</groupId><version>\${jackson.version}</version></dependency>
        <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>\${log4j.version}</version></dependency>
        <dependency><groupId>com.acme</groupId><artifactId>shared</artifactId><version>\${project.version}</version></dependency>
        <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.1</version><scope>test</scope></dependency>
        <dependency><groupId>org.springframework</groupId><artifactId>spring-core</artifactId></dependency>
        <!-- <dependency><groupId>x</groupId><artifactId>commented</artifactId><version>1</version></dependency> -->
      </dependencies>
      <dependencyManagement><dependencies>
        <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-dependencies</artifactId><version>3.1.0</version><type>pom</type><scope>import</scope></dependency>
      </dependencies></dependencyManagement>
      <build><plugins><plugin><groupId>p</groupId><artifactId>plugin</artifactId><version>1</version>
        <dependencies><dependency><groupId>p</groupId><artifactId>plugin-dep</artifactId><version>1</version></dependency></dependencies>
      </plugin></plugins></build>
    </project>`;
    const deps = pomXmlParser.parse(pom, "pom.xml");
    expect(coords(deps)).toEqual([
      "com.fasterxml.jackson.core:jackson-databind@2.15.2",
      "org.apache.logging.log4j:log4j-core@2.17.1",
      "com.acme:shared@2.1.0",
      "junit:junit@4.13.1",
    ]);
    expect(deps[3].isDev).toBe(true);
  });

  it("skips versions it can't resolve rather than guessing", () => {
    const pom = `<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>\${from.parent}</version></dependency>
      <dependency><groupId>g</groupId><artifactId>b</artifactId><version>[1.0,2.0)</version></dependency></dependencies></project>`;
    expect(pomXmlParser.parse(pom, "pom.xml")).toEqual([]);
  });
});

describe("Gradle", () => {
  it("reads string, Kotlin DSL, named-argument and variable forms", () => {
    const gradle = `
      def retrofitVersion = '2.9.0'
      val okhttp = "4.10.0"
      ext.kotlin_version = '1.9.0'
      dependencies {
        implementation 'com.google.guava:guava:31.1-jre'
        implementation("com.squareup.okhttp3:okhttp:$okhttp")
        api "com.squareup.retrofit2:retrofit:\${retrofitVersion}"
        implementation "org.jetbrains.kotlin:kotlin-stdlib:$kotlin_version"
        implementation group: 'org.apache.commons', name: 'commons-text', version: '1.9'
        kapt("com.google.dagger:dagger-compiler:2.44")
        testImplementation 'junit:junit:4.13.2'
        implementation "com.example:unknown:$notDefined"
        implementation platform("org.springframework.boot:spring-boot-dependencies:3.1.0")
        implementation 'androidx.core:core-ktx:1.9.0@aar'
      }`;
    const deps = buildGradleParser.parse(gradle, "build.gradle");
    expect(coords(deps).sort()).toEqual(
      [
        "com.google.guava:guava@31.1-jre",
        "com.squareup.okhttp3:okhttp@4.10.0",
        "com.squareup.retrofit2:retrofit@2.9.0",
        "org.jetbrains.kotlin:kotlin-stdlib@1.9.0",
        "org.apache.commons:commons-text@1.9",
        "com.google.dagger:dagger-compiler@2.44",
        "junit:junit@4.13.2",
        "androidx.core:core-ktx@1.9.0",
      ].sort(),
    );
    expect(deps.find((d) => d.name === "junit:junit")!.isDev).toBe(true);
  });

  it("reads gradle.lockfile, including transitive dependencies", () => {
    const lock = `# This is a Gradle generated file
com.google.guava:failureaccess:1.0.1=compileClasspath,runtimeClasspath
com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath
junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath
empty=annotationProcessor`;
    const deps = gradleLockfileParser.parse(lock, "app/gradle.lockfile");
    expect(coords(deps)).toEqual(["com.google.guava:failureaccess@1.0.1", "com.google.guava:guava@31.1-jre", "junit:junit@4.13.2"]);
    expect(deps.map((d) => d.isDev)).toEqual([false, false, true]);
    expect(gradleLockfileParser.parse(lock, "buildscript-gradle.lockfile")).toEqual([]);
  });

  it("reads the version catalog", () => {
    const toml = `[versions]
kotlin = "1.9.0"
okhttp = "4.10.0"

[libraries]
okhttp = { module = "com.squareup.okhttp3:okhttp", version.ref = "okhttp" }
kotlin-stdlib = { group = "org.jetbrains.kotlin", name = "kotlin-stdlib", version.ref = "kotlin" }
gson = "com.google.code.gson:gson:2.10.1"
coil = { module = "io.coil-kt:coil", version = "2.4.0" } # inline comment
bom = { module = "androidx.compose:compose-bom" }

[plugins]
android = { id = "com.android.application", version = "8.1.0" }`;
    expect(coords(versionCatalogParser.parse(toml, "gradle/libs.versions.toml"))).toEqual([
      "com.squareup.okhttp3:okhttp@4.10.0",
      "org.jetbrains.kotlin:kotlin-stdlib@1.9.0",
      "com.google.code.gson:gson@2.10.1",
      "io.coil-kt:coil@2.4.0",
    ]);
  });
});

describe("NuGet", () => {
  it("reads PackageReference in any attribute order, child Version and $(Properties)", () => {
    const csproj = `<Project Sdk="Microsoft.NET.Sdk">
      <PropertyGroup><SerilogVersion>3.0.1</SerilogVersion></PropertyGroup>
      <ItemGroup>
        <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
        <PackageReference Version="6.0.0" Include="Microsoft.Extensions.Http" />
        <PackageReference Include="Serilog" Version="$(SerilogVersion)" />
        <PackageReference Include="Dapper">
          <Version>2.0.123</Version>
        </PackageReference>
        <PackageReference Include="Centrally.Managed" />
        <PackageReference Include="Floating" Version="1.*" />
      </ItemGroup>
    </Project>`;
    expect(coords(csprojParser.parse(csproj, "src/App.csproj"))).toEqual([
      "Newtonsoft.Json@12.0.1",
      "Microsoft.Extensions.Http@6.0.0",
      "Serilog@3.0.1",
      "Dapper@2.0.123",
    ]);
  });

  it("reads central package management and lock files", () => {
    const props = `<Project><ItemGroup>
      <PackageVersion Include="Newtonsoft.Json" Version="13.0.3" />
      <PackageVersion Include="xunit" Version="2.4.2" />
      <GlobalPackageReference Include="StyleCop.Analyzers" Version="1.1.118" />
    </ItemGroup></Project>`;
    expect(coords(directoryPackagesPropsParser.parse(props, "Directory.Packages.props"))).toEqual([
      "Newtonsoft.Json@13.0.3",
      "xunit@2.4.2",
      "StyleCop.Analyzers@1.1.118",
    ]);
    const lock = JSON.stringify({
      version: 1,
      dependencies: {
        "net6.0": {
          "Newtonsoft.Json": { type: "Direct", requested: "[13.0.3, )", resolved: "13.0.3" },
          "System.Text.Encodings.Web": { type: "Transitive", resolved: "4.7.2" },
          "MyLib": { type: "Project" },
        },
        "net7.0": { "Newtonsoft.Json": { type: "Direct", resolved: "13.0.3" } },
      },
    });
    expect(coords(packagesLockJsonParser.parse(lock, "src/packages.lock.json"))).toEqual([
      "Newtonsoft.Json@13.0.3",
      "System.Text.Encodings.Web@4.7.2",
    ]);
  });

  it("keeps packages.config working", () => {
    const cfg = `<packages><package id="jQuery" version="3.4.1" targetFramework="net48" /><package version="1.0" id="Tool" developmentDependency="true" /></packages>`;
    const deps = packagesConfigParser.parse(cfg, "packages.config");
    expect(coords(deps)).toEqual(["jQuery@3.4.1", "Tool@1.0"]);
    expect(deps[1].isDev).toBe(true);
  });
});

describe("iOS", () => {
  it("reads Podfile.lock pods, folding subspecs", () => {
    const lock = `PODS:
  - Alamofire (5.6.4)
  - Firebase/Core (10.0.0):
    - Firebase/CoreOnly
    - FirebaseAnalytics (= 10.0.0)
  - Firebase/CoreOnly (10.0.0):
    - FirebaseCore (= 10.0.0)
  - "GoogleUtilities/Environment (7.10.0)"

DEPENDENCIES:
  - Alamofire (~> 5.6)

SPEC CHECKSUMS:
  Alamofire: 4e95d97098eacb88856099c4fc79b526a299e48c`;
    expect(coords(podfileLockParser.parse(lock, "ios/Podfile.lock"))).toEqual([
      "Alamofire@5.6.4",
      "Firebase@10.0.0",
      "GoogleUtilities@7.10.0",
    ]);
  });

  it("maps Carthage GitHub frameworks to OSV's Swift ecosystem", () => {
    const resolved = `github "Alamofire/Alamofire" "5.6.4"
git "https://github.com/ReactiveX/RxSwift.git" "v6.5.0"
github "owner/pinned" "8f7d0c8b3e2a9f1c4d5e6f7a8b9c0d1e2f3a4b5c"
binary "https://example.com/Framework.json" "1.0.0"`;
    const deps = cartfileResolvedParser.parse(resolved, "Cartfile.resolved");
    expect(coords(deps)).toEqual(["github.com/Alamofire/Alamofire@5.6.4", "github.com/ReactiveX/RxSwift@6.5.0"]);
    expect(deps.every((d) => d.ecosystem === "SwiftURL")).toBe(true);
  });
});

describe("parseDependencies", () => {
  function repo(files: Record<string, string>) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sca-parse-"));
    for (const [p, c] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, p)), { recursive: true });
      fs.writeFileSync(path.join(dir, p), c);
    }
    return { dir, files: Object.keys(files) };
  }

  it("prefers the lock file's version over the manifest range in the same directory", () => {
    const { dir, files } = repo({
      "package.json": JSON.stringify({ dependencies: { lodash: "^4.17.0", express: "^4.18.0" } }),
      "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/lodash": { version: "4.17.21" } } }),
      "packages/web/package.json": JSON.stringify({ dependencies: { lodash: "^4.17.5" } }),
    });
    const { dependencies, directNames } = parseDependencies(dir, files);
    expect(coords(dependencies).sort()).toEqual(["express@4.18.0", "lodash@4.17.21", "lodash@4.17.5"].sort());
    expect(directNames).toEqual(["lodash"]);
    fs.rmSync(dir, { recursive: true });
  });

  it("in a workspace, the root lock file resolves the members' manifests", () => {
    const lock = `version = 3\n\n[[package]]\nname = "openssl"\nversion = "0.10.72"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n[[package]]\nname = "router"\nversion = "0.1.0"\ndependencies = [\n "openssl",\n]\n`;
    const { dir, files } = repo({
      "Cargo.toml": `[workspace]\nmembers = ["crates/*"]\n`,
      "Cargo.lock": lock,
      "crates/router/Cargo.toml": `[package]\nname = "router"\nversion = "0.1.0"\n\n[dependencies]\nopenssl = "0.10"\n`,
    });
    const { dependencies, directNames } = parseDependencies(dir, files);
    // Not openssl@0.10 from the member manifest, and not the workspace's own crate.
    expect(coords(dependencies)).toEqual(["openssl@0.10.72"]);
    expect(directNames).toEqual(["openssl"]);
    fs.rmSync(dir, { recursive: true });
  });

  it("an npm workspace root lock file resolves the packages' manifests", () => {
    const { dir, files } = repo({
      "package.json": JSON.stringify({ workspaces: ["packages/*"] }),
      "package-lock.json": JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/lodash": { version: "4.17.21" } } }),
      "packages/web/package.json": JSON.stringify({ dependencies: { lodash: "^4.17.5" } }),
    });
    expect(coords(parseDependencies(dir, files).dependencies)).toEqual(["lodash@4.17.21"]);
    fs.rmSync(dir, { recursive: true });
  });

  it("recognises every new dependency file", () => {
    for (const f of ["gradle.lockfile", "gradle/libs.versions.toml", "Directory.Packages.props", "src/packages.lock.json", "ios/Podfile.lock", "Cartfile.resolved", "yarn.lock", "pnpm-lock.yaml", "src/App.csproj"]) {
      expect(isDependencyFile(f), f).toBe(true);
    }
    expect(isDependencyFile("src/index.ts")).toBe(false);
  });
});
