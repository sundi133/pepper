import { describe, expect, it } from "vitest";
import { DEFAULT_REPO_CONFIG, globToRegExp, matchesAny, parseRepoConfig } from "./config";
import { botHandles, commandAuthorization, parsePrCommand } from "./commands";
import { decidePrReview, type PrFacts } from "./decision";

describe(".pepper.yaml", () => {
  it("gives today's behaviour by default", () => {
    expect(DEFAULT_REPO_CONFIG).toMatchObject({
      reviews: { auto: true, drafts: true, bots: true, forks: "collaborators", base_branches: ["*"], scan: "incremental" },
      comments: { summary: true, inline: true, inline_min_severity: "INFO", max_inline: 30 },
      paths: { exclude: [] },
    });
    expect(parseRepoConfig(null)).toEqual({ config: DEFAULT_REPO_CONFIG, error: null });
    expect(parseRepoConfig("   \n")).toEqual({ config: DEFAULT_REPO_CONFIG, error: null });
  });

  it("reads a partial file over the defaults and ignores unknown keys", () => {
    const { config, error } = parseRepoConfig("reviews:\n  drafts: false\ncomments:\n  inline_min_severity: HIGH\npaths:\n  exclude: ['docs/**']\nsomething_else: 1\n");
    expect(error).toBeNull();
    expect(config.reviews).toMatchObject({ auto: true, drafts: false });
    expect(config.comments.inline_min_severity).toBe("HIGH");
    expect(config.paths.exclude).toEqual(["docs/**"]);
  });

  it("falls back to the defaults with a message for invalid files", () => {
    const bad = parseRepoConfig("reviews: [unclosed");
    expect(bad.config).toEqual(DEFAULT_REPO_CONFIG);
    expect(bad.error).toMatch(/not valid YAML/);
    const wrong = parseRepoConfig("comments:\n  max_inline: 500\n");
    expect(wrong.config).toEqual(DEFAULT_REPO_CONFIG);
    expect(wrong.error).toMatch(/comments\.max_inline/);
    expect(parseRepoConfig("reviews:\n  drafts: maybe\n").error).toMatch(/reviews\.drafts/);
  });

  it("matches globs like .gitignore-style paths", () => {
    expect(globToRegExp("docs/**").test("docs/a/b.md")).toBe(true);
    expect(matchesAny("src/app.md", ["**/*.md"])).toBe(true);
    expect(matchesAny("README.md", ["**/*.md"])).toBe(true);
    expect(matchesAny("src/app.ts", ["**/*.md", "docs/**"])).toBe(false);
    expect(matchesAny("test/fixtures/x.json", ["test/fixtures/**"])).toBe(true);
    expect(matchesAny("release/1.2", ["release/*"])).toBe(true);
    expect(matchesAny("release/1.2/hot", ["release/*"])).toBe(false);
    expect(matchesAny("main", ["*"])).toBe(true);
    expect(matchesAny("a.b", ["a?b"])).toBe(true);
    expect(matchesAny("./docs/x", ["docs/**"])).toBe(true);
  });
});

describe("commands", () => {
  const handles = botHandles("pepper-sast-acme");
  it("recognizes commands addressed to the bot or the App, first line only", () => {
    expect(parsePrCommand("@pepper review", handles)).toBe("review");
    expect(parsePrCommand("@Pepper FULL   review please", handles)).toBe("full-review");
    expect(parsePrCommand("\n  @pepper-sast-acme[bot] pause\nbecause reasons", handles)).toBe("pause");
    expect(parsePrCommand("@pepper resume", handles)).toBe("resume");
    expect(parsePrCommand("@pepper fix", handles)).toBe("fix");
    expect(parsePrCommand("@pepper", handles)).toBe("help");
    expect(parsePrCommand("@pepper dance", handles)).toBe("unknown");
  });

  it("ignores comments that don't start by addressing the bot", () => {
    expect(parsePrCommand("thanks @pepper review", handles)).toBeNull();
    expect(parsePrCommand("@someone review", handles)).toBeNull();
    expect(parsePrCommand("@pepperoni review", handles)).toBeNull();
    expect(parsePrCommand("", handles)).toBeNull();
    expect(parsePrCommand("looks good\n@pepper review", handles)).toBeNull();
  });

  it("lets only collaborators run commands and ignores bots", () => {
    expect(commandAuthorization({ author_association: "MEMBER", user: { login: "a", type: "User" } })).toBe("allowed");
    expect(commandAuthorization({ author_association: "owner", user: { login: "a" } })).toBe("allowed");
    expect(commandAuthorization({ author_association: "CONTRIBUTOR", user: { login: "a" } })).toBe("not-collaborator");
    expect(commandAuthorization({ author_association: "NONE", user: { login: "a" } })).toBe("not-collaborator");
    expect(commandAuthorization({ author_association: "MEMBER", user: { login: "pepper-sast-acme[bot]", type: "Bot" } })).toBe("bot");
  });
});

describe("review decision", () => {
  const facts = (over: Partial<PrFacts> = {}): PrFacts => ({
    action: "opened", draft: false, baseRef: "main", author: { login: "alice", type: "User" }, authorAssociation: "MEMBER", isFork: false, paused: false, ...over,
  });
  const cfg = (yaml: string) => parseRepoConfig(yaml).config;

  it("reviews opened, new commits and reopened, like before, including drafts and bot PRs by default", () => {
    for (const action of ["opened", "synchronize", "reopened"]) {
      expect(decidePrReview(facts({ action }), DEFAULT_REPO_CONFIG)).toEqual({ review: true, scan: "incremental" });
    }
    expect(decidePrReview(facts({ draft: true }), DEFAULT_REPO_CONFIG).review).toBe(true);
    expect(decidePrReview(facts({ author: { login: "dependabot[bot]", type: "Bot" } }), DEFAULT_REPO_CONFIG).review).toBe(true);
    // A draft was reviewed when opened: marking it ready doesn't rescan the same code.
    expect(decidePrReview(facts({ action: "ready_for_review" }), DEFAULT_REPO_CONFIG)).toMatchObject({ review: false, reason: "already reviewed as a draft" });
    expect(decidePrReview(facts({ action: "ready_for_review" }), parseRepoConfig("reviews:\n  drafts: false").config).review).toBe(true);
    expect(decidePrReview(facts({ action: "labeled" }), DEFAULT_REPO_CONFIG).review).toBe(false);
    expect(decidePrReview(facts(), cfg("reviews:\n  scan: full"))).toEqual({ review: true, scan: "full" });
  });

  it("skips drafts and bots when configured, paused PRs, other base branches and auto-off, with a success status", () => {
    const skipBoth = cfg("reviews:\n  drafts: false\n  bots: false");
    expect(decidePrReview(facts({ draft: true }), skipBoth)).toMatchObject({ review: false, reason: "draft", status: expect.stringMatching(/draft/) });
    expect(decidePrReview(facts({ author: { login: "dependabot[bot]", type: "Bot" } }), skipBoth)).toMatchObject({ review: false, reason: "bot author" });
    expect(decidePrReview(facts({ author: { login: "renovate" } }), skipBoth).review).toBe(false);
    expect((decidePrReview(facts({ draft: true }), skipBoth) as { state?: string }).state).toBeUndefined(); // success
    expect(decidePrReview(facts({ paused: true }), DEFAULT_REPO_CONFIG)).toMatchObject({ review: false, reason: "paused" });
    expect(decidePrReview(facts({ baseRef: "experiment" }), cfg("reviews:\n  base_branches: [main, 'release/*']"))).toMatchObject({ review: false });
    expect(decidePrReview(facts({ baseRef: "release/2" }), cfg("reviews:\n  base_branches: [main, 'release/*']")).review).toBe(true);
    expect(decidePrReview(facts(), cfg("reviews:\n  auto: false"))).toMatchObject({ review: false, status: expect.stringMatching(/@pepper review/) });
  });

  it("reviews fork PRs from collaborators only, unless configured otherwise", () => {
    expect(decidePrReview(facts({ isFork: true, authorAssociation: "COLLABORATOR" }), DEFAULT_REPO_CONFIG).review).toBe(true);
    // Pending, not success: a required check keeps blocking until a collaborator asks.
    expect(decidePrReview(facts({ isFork: true, authorAssociation: "CONTRIBUTOR" }), DEFAULT_REPO_CONFIG)).toMatchObject({ review: false, status: expect.stringMatching(/fork/), state: "pending" });
    expect(decidePrReview(facts({ isFork: true, authorAssociation: "NONE" }), cfg("reviews:\n  forks: all")).review).toBe(true);
    expect(decidePrReview(facts({ isFork: true, authorAssociation: "MEMBER" }), cfg("reviews:\n  forks: none")).review).toBe(false);
  });
});
