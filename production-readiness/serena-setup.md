# Serena Setup Notes

Use this file as the team template for enabling full multi-language Serena indexing in this repository:

```yaml
languages:
  - go
  - typescript
  - rust
  - terraform
  - markdown
  - yaml

additional_workspace_folders:
  - web
  - mobile
  - services/scripture-engine
  - production-readiness
  - tools
```

After saving these values in `.serena/project.yml`, restart Serena so route and symbol
lookups can cross `web`, `mobile`, and Rust workspace files without repeated re-indexes.

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
