# Review knowledge

Per-language security review guides injected into Pepper's AI SAST prompts
(see `src/scanners/shared/review-knowledge.ts`). The AI receives the guide for
the language of the file it is reviewing, plus `universal.md`.

These guides are a security-focused distillation of the language references in
[awesome-skills/code-review-skill](https://github.com/awesome-skills/code-review-skill)
(MIT License, Copyright (c) 2025 awesome-skills), merged with Pepper's own
source→sink references. Style, performance and formatting advice from the
original was dropped: only items that can cause a vulnerability, data loss or a
logic/authorization flaw are kept.

Guides are knowledge for the model, not detection rules: nothing here is
matched mechanically against code.

## Adding a language
Create `<language>.md` using a key from `FILE_EXTENSIONS` in
`src/lib/constants.ts` and add any aliases in `LANGUAGE_GUIDE`.
