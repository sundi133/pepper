// ═════════════════════════════════════════════════════════════════════════════
// File Extension Filters for Different Scanner Types
// ═════════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
// SAST SCANNER - Source code files only (no configs, data, binaries)
// ─────────────────────────────────────────────────────────────────────────────
export const SAST_EXCLUDED_EXTENSIONS = new Set([
  // Dependency and lock files
  ".lock",
  ".lockfile",

  // Configuration files (JSON, YAML, TOML, XML, etc.)
  ".yaml",
  ".yml",
  ".json",
  ".xml",
  ".toml",
  ".ini",
  ".cfg",
  ".conf",
  ".config",
  ".properties",
  ".gradle",
  ".maven",

  // IaC and Container files
  ".dockerfile",
  ".tf",
  ".hcl",
  ".bicep",
  ".cloudformation",
  ".template",

  // Build and package files
  ".sbt",
  ".cargo",
  ".gemspec",
  ".podspec",
  ".nuspec",
  ".csproj",
  ".fsproj",
  ".vbproj",
  ".vcxproj",
  ".vcxproj.user",
  ".sln",
  ".mk",
  ".makefile",
  ".cmake",
  ".make",
  ".ant",
  ".pom",
  ".mvn",
  ".ivy",
  ".sbt.lock",

  // Archive and compression
  ".zip",
  ".tar",
  ".gz",
  ".tgz",
  ".tar.gz",
  ".rar",
  ".7z",
  ".bz2",
  ".tar.bz2",
  ".xz",
  ".tar.xz",
  ".iso",
  ".dmg",
  ".cab",
  ".lz",
  ".lzma",

  // Image and media files
  ".png",
  ".jpg",
  ".jpeg",
  ".jpe",
  ".gif",
  ".bmp",
  ".dib",
  ".svg",
  ".ico",
  ".webp",
  ".tiff",
  ".tif",
  ".heic",
  ".heif",
  ".jp2",
  ".jpx",
  ".mp3",
  ".mp4",
  ".m4a",
  ".m4v",
  ".avi",
  ".mov",
  ".mkv",
  ".wav",
  ".aiff",
  ".flac",
  ".ogg",
  ".opus",
  ".aac",
  ".wma",
  ".wmv",
  ".webm",
  ".3gp",
  ".3g2",
  ".f4v",
  ".m2ts",
  ".mts",
  ".ogv",

  // Document files
  ".pdf",
  ".doc",
  ".docx",
  ".docm",
  ".dot",
  ".dotx",
  ".xls",
  ".xlsx",
  ".xlsm",
  ".xlt",
  ".xltx",
  ".csv",
  ".ppt",
  ".pptx",
  ".pptm",
  ".pot",
  ".potx",
  ".odt",
  ".ods",
  ".odp",
  ".ott",
  ".ots",
  ".otp",
  ".rtf",
  ".txt",
  ".text",
  ".tex",

  // Database files
  ".db",
  ".sqlite",
  ".sqlite3",
  ".mdb",
  ".accdb",
  ".sql",
  ".dbf",
  ".ibd",
  ".frm",
  ".myi",
  ".myd",
  ".ldf",
  ".mdf",

  // Binary and executable files
  ".exe",
  ".com",
  ".dll",
  ".so",
  ".dylib",
  ".a",
  ".lib",
  ".o",
  ".obj",
  ".bin",
  ".dat",
  ".class",
  ".jar",
  ".pyc",
  ".pyo",
  ".pyd",
  ".egg",
  ".whl",
  ".deb",
  ".rpm",
  ".apk",
  ".dmg",
  ".pkg",
  ".msi",
  ".cab",

  // Version control system files
  ".git",
  ".gitkeep",
  ".gitattributes",
  ".gitmodules",
  ".svn",
  ".hg",
  ".bzr",
  ".pijul",

  // Temporary and cache files
  ".tmp",
  ".temp",
  ".cache",
  ".log",
  ".bak",
  ".backup",
  ".orig",
  ".swp",
  ".swo",
  ".swn",
  ".DS_Store",
  ".thumbs",
  ".Thumbs.db",
  ".sass-cache",
  ".pytest_cache",
  ".mypy_cache",
  ".tox",
  ".coverage",
  ".egg-info",

  // Source control metadata
  ".patch",
  ".diff",
  ".rej",
  ".merge",

  // Certificate and key files
  ".pem",
  ".p12",
  ".pfx",
  ".p7b",
  ".crt",
  ".cer",
  ".key",
  ".der",
  ".jks",
  ".keystore",
  ".pks12",
  ".pkcs12",
  ".pub",
  ".asc",
  ".gpg",

  // Environment and secret files
  ".env",
  ".env.local",
  ".env.development.local",
  ".env.test.local",
  ".env.production.local",
  ".env.example",
  ".env.sample",
  ".secrets",
  ".secret",

  // Minified and bundled files
  ".min.js",
  ".min.css",
  ".bundle.js",
  ".chunk.js",

  // IDE and editor config
  ".editorconfig",
  ".vscode",
  ".idea",
  ".eclipse",
  ".netbeans",
  ".sublime-project",
  ".sublime-workspace",

  // Git config
  ".gitignore",
  ".gitconfig",

  // Package manager config
  ".npmrc",
  ".yarnrc",
  ".yarnrc.yml",
  ".pnpmfile.cjs",
  ".npmignore",
  ".yarnignore",

  // Linting and formatting
  ".prettierrc",
  ".prettierrc.json",
  ".prettierrc.yml",
  ".prettierrc.yaml",
  ".prettierrc.js",
  ".prettierrc.cjs",
  ".prettierignore",
  ".eslintrc",
  ".eslintrc.js",
  ".eslintrc.cjs",
  ".eslintrc.yaml",
  ".eslintrc.yml",
  ".eslintrc.json",
  ".eslintignore",
  ".stylelintrc",
  ".stylelintrc.json",
  ".stylelintrc.yaml",
  ".stylelintignore",

  // Babel and build tools
  ".babelrc",
  ".babelrc.js",
  ".babelrc.json",
  ".babelrc.cjs",

  // Test config
  ".mocharc",
  ".mocharc.js",
  ".mocharc.json",
  ".mocharc.yaml",
  ".mocharc.yml",
  ".jestrc",
  ".jestrc.js",
  ".jestrc.json",

  // Web and server config
  ".htaccess",
  ".htpasswd",
  ".htdigest",

  // Documentation
  ".md",
  ".markdown",
  ".rst",
  ".adoc",
  ".asciidoc",
  ".mdown",
  ".mkdown",
  ".mdx",

  // Specifications
  ".openapi",
  ".swagger",
  ".graphql",
  ".proto",
  ".thrift",
  ".wsdl",
  ".xsd",
  ".dtd",
  ".rng",

  // Fonts and assets
  ".ttf",
  ".otf",
  ".woff",
  ".woff2",
  ".eot",
  ".font",
]);

// ─────────────────────────────────────────────────────────────────────────────
// SCA SCANNER - Only dependency manifest files
// ─────────────────────────────────────────────────────────────────────────────
export const SCA_INCLUDED_EXTENSIONS = new Set([
  // JavaScript/TypeScript
  ".json", // package.json, package-lock.json, yarn.lock
  ".lock",

  // Python
  ".txt",   // requirements.txt
  ".toml",  // pyproject.toml
  ".cfg",   // setup.cfg
  ".ini",   // setup.ini

  // Go
  ".mod",
  ".sum",

  // Rust
  ".toml", // Cargo.toml

  // Java/Gradle
  ".gradle",
  ".xml", // pom.xml

  // Ruby
  ".gemfile",
  ".gemspec",

  // PHP
  ".json", // composer.json

  // .NET
  ".csproj",
  ".fsproj",
  ".vbproj",

  // Dart
  ".yaml",
  ".yml",

  // Swift
  ".swift",

  // Elixir
  ".exs",
  ".lock",
]);

// ─────────────────────────────────────────────────────────────────────────────
// IaC SCANNER - Infrastructure as Code files
// ─────────────────────────────────────────────────────────────────────────────
export const IAC_INCLUDED_EXTENSIONS = new Set([
  // Terraform
  ".tf",
  ".hcl",

  // CloudFormation & Bicep
  ".yaml",
  ".yml",
  ".json",
  ".template",

  // Kubernetes
  ".yaml",
  ".yml",

  // Docker
  ".dockerfile",
  ".Dockerfile",

  // Ansible
  ".yaml",
  ".yml",

  // Helm
  ".yaml",
  ".yml",

  // Puppet
  ".pp",

  // Chef
  ".rb",

  // SaltStack
  ".sls",
]);

// ─────────────────────────────────────────────────────────────────────────────
// SECRETS SCANNER - Text-based files where secrets could be
// ─────────────────────────────────────────────────────────────────────────────
export const SECRETS_INCLUDED_EXTENSIONS = new Set([
  // Source code files
  ".js",
  ".ts",
  ".tsx",
  ".jsx",
  ".py",
  ".go",
  ".java",
  ".rb",
  ".php",
  ".cs",
  ".rs",
  ".c",
  ".cpp",
  ".h",
  ".hpp",
  ".swift",
  ".kt",
  ".scala",
  ".sh",
  ".bash",
  ".zsh",
  ".fish",
  ".pl",
  ".r",
  ".lua",
  ".vim",
  ".groovy",
  ".gradle",

  // Configuration files
  ".yaml",
  ".yml",
  ".json",
  ".xml",
  ".toml",
  ".ini",
  ".cfg",
  ".conf",
  ".config",
  ".properties",
  ".env",
  ".env.local",
  ".env.example",

  // IaC files
  ".tf",
  ".hcl",
  ".bicep",

  // Docker
  ".dockerfile",
  ".Dockerfile",

  // Kubernetes
  ".yaml",
  ".yml",

  // Build files
  ".gradle",
  ".maven",
  ".sbt",

  // Documentation
  ".md",
  ".markdown",
  ".rst",
  ".txt",
]);

// ─────────────────────────────────────────────────────────────────────────────
// CONTAINER SCANNER - Container and image files
// ─────────────────────────────────────────────────────────────────────────────
export const CONTAINER_INCLUDED_EXTENSIONS = new Set([
  // Docker
  ".dockerfile",
  ".Dockerfile",

  // Container images (references)
  ".json", // docker-compose.json
  ".yaml", // docker-compose.yml
  ".yml",

  // Kubernetes
  ".yaml",
  ".yml",

  // OCI specs
  ".json",
  ".yaml",
  ".yml",

  // Singularity
  ".def",
]);

// ─────────────────────────────────────────────────────────────────────────────
// SUPPLY CHAIN SCANNER - Package manifest files (focuses on install scripts, metadata)
// ─────────────────────────────────────────────────────────────────────────────
export const SUPPLY_CHAIN_INCLUDED_EXTENSIONS = new Set([
  // JavaScript/Node.js
  ".json", // package.json

  // Python
  ".toml", // pyproject.toml
  ".txt",  // setup.py (as text)
  ".cfg",

  // Ruby
  ".gemspec",
  ".gemfile",

  // Go
  ".mod",
  ".sum",

  // Rust
  ".toml", // Cargo.toml

  // PHP
  ".json", // composer.json

  // Java
  ".gradle",
  ".xml", // pom.xml

  // .NET
  ".csproj",
  ".fsproj",
  ".vbproj",

  // Dart
  ".yaml",
  ".yml",

  // Elixir
  ".exs",
]);

// ─────────────────────────────────────────────────────────────────────────────
// ZERO-DAY SCANNER - Source code files (same as SAST for deep analysis)
// ─────────────────────────────────────────────────────────────────────────────
export const ZERO_DAY_INCLUDED_EXTENSIONS = new Set([
  ".js",
  ".ts",
  ".tsx",
  ".jsx",
  ".py",
  ".go",
  ".java",
  ".rb",
  ".php",
  ".cs",
  ".rs",
  ".c",
  ".cpp",
  ".h",
  ".hpp",
  ".swift",
  ".kt",
  ".scala",
  ".sh",
  ".bash",
]);
