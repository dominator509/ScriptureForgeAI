# Serena Setup Notes

Use this file as the team template for enabling full multi-language Serena indexing in this repository:

```yaml
language_backend: LSP
languages:
  - go
  - typescript
  - rust
  - terraform
  - yaml

additional_workspace_folders:
  - web
  - mobile
  - services/scripture-engine
  - production-readiness
  - tools

ignored_paths:
  - node_modules
  - web/node_modules
  - mobile/node_modules
  - .next
  - web/.next
  - dist
  - coverage
  - target
  - services/scripture-engine/target
  - .terraform
  - build/terraform/.terraform
  - artifacts
  - .tools
  - .gocache
  - .npm-cache
  - .serena/cache
  - "*.tsbuildinfo"
  - "*.tfstate"
  - "*.tfstate.*"
  - "production-readiness/staging-evidence.staging.json"
```

Markdown remains a first-class Obsidian/Codex document format, but it is not
declared as an LSP language in the Windows profile because the bundled Marksman
binary is not executable in the current Serena installation. This keeps semantic
code navigation healthy while preserving Markdown files for direct reading and
Obsidian links.

After saving these values in `.serena/project.yml`, restart Serena so route and symbol
lookups can cross `web`, `mobile`, and Rust workspace files without repeated re-indexes.

`REPO_BRIEF.md` is the compact durable context file for Serena and Obsidian handoff. Link to it instead of copying large sections of roadmap, architecture, or audit files into notes.

```powershell
# Validate Serena/Obsidian drift gate from this repo root.
node tools/validate-serena-obsidian.mjs

# Optional local check (Windows)
Get-Content .serena\\project.yml

# Keep Obsidian readiness tracker synced with staging evidence
node tools/sync-obsidian-readiness.mjs --check --note production-readiness/obsidian-production-readiness.md --manifest production-readiness/staging-evidence.staging.json
```

```text
# Pre-merge requirement:
node tools/validate-serena-obsidian.mjs
```

To keep Obsidian snapshots in sync with the current staging evidence manifest, run:

```text
node tools/sync-obsidian-readiness.mjs --manifest production-readiness/staging-evidence.staging.json --note production-readiness/obsidian-production-readiness.md --apply
node tools/sync-obsidian-readiness.mjs --check --note production-readiness/obsidian-production-readiness.md
```
