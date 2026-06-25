# Dependency Risk Register

Status last updated: 2026-06-25

This register tracks dependency findings that are not yet remediated in code but have a documented release decision. It does not replace fresh `npm audit`, Go/Rust advisory scanning, or CI security gates.

## DRR-001: Expo tooling transitive `uuid <11.1.1` advisory

- Scope: `mobile/package-lock.json`
- Current locked versions: expo@56.0.12, uuid@7.0.3
- Source: `npm audit --audit-level=high --cache C:\dev\ScriptureForgeAI\.npm-cache`
- Severity: Moderate
- Advisory: GHSA-w5hq-g745-h8pq, missing buffer bounds check in `uuid` v3/v5/v6 when caller provides `buf`.
- Dependency path: `expo` -> `@expo/cli` / config tooling -> `xcode` -> `uuid`.
- Current result: `npm audit --audit-level=high` passes, but reports 10 moderate findings.
- Forced fix impact: `npm audit fix --force` proposes `expo@46.0.21`, which is a breaking downgrade from the current Expo `56.0.12` lane and would undermine the current React Native dependency line.
- Risk decision: Accepted temporarily for local/CI readiness because this is Expo CLI/config tooling rather than application runtime journal cryptography, and high-or-worse audit gating is enforced in CI.
- Required closure: Re-check on each dependency refresh; remove this accepted risk when Expo's dependency lane resolves `uuid >=11.1.1` without a breaking downgrade, or when a deliberate Expo lane migration is completed and validated.
