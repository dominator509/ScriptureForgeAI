# Dependency Risk Register

Status last updated: 2026-08-10

This register tracks active dependency findings and recently closed decisions. It does not replace fresh `npm audit`, Go/Rust advisory scanning, or CI security gates.

## DRR-001: Expo tooling transitive `uuid <11.1.1` advisory

- Status: Closed (2026-08-10)
- Scope: `mobile/package.json`, `mobile/package-lock.json`
- Current locked versions: expo@56.0.17, uuid@11.1.1
- Source: `npm audit --audit-level=high --cache C:\dev\ScriptureForgeAI\.npm-cache`
- Historical severity: Moderate
- Advisory: GHSA-w5hq-g745-h8pq, missing buffer bounds check in `uuid` v3/v5/v6 when caller provides `buf`.
- Dependency path: `expo` -> `@expo/cli` / config tooling -> `xcode` -> `uuid`.
- Closure evidence: `mobile/package.json` and `mobile/package-lock.json` resolve the Expo xcode tooling path to `uuid@11.1.1`; `uuid.v4` remains available through CommonJS and the installed xcode consumer loads successfully.
- Runtime reachability guard: `tools/validate-dependency-risk.mjs` continues to scan `mobile/App.tsx` and `mobile/src` for runtime `uuid` imports while validating the closed lifecycle record.
- Required closure: `uuid >=11.1.1` with a passing mobile build/check and compatibility smoke.

## DRR-002: Expo/Metro transitive `image-size` denial of service advisories

- Status: Open - release blocker
- Scope: `mobile/package-lock.json`
- Current locked versions: expo@56.0.17, `@expo/metro@56.0.0`, metro@0.84.4, image-size@1.2.1
- Source: `npm audit --audit-level=high`
- Severity: High
- Advisories: GHSA-w3rx-r6r6-pgpr and GHSA-5p2g-fcmc-qvqq, infinite-loop denial of service in ICNS/JXL/HEIF parsing.
- Current result: leaf fixes for `brace-expansion`, `js-yaml`, `nanoid`, `postcss`, and `uuid` are applied; the mobile high-severity audit still reports 11 findings through the Metro/image-size dependency chain.
- Remediation constraint: npm's forced fix proposes Expo 53.0.27, which is a breaking downgrade from the repo-current Expo 56 / React Native 0.86 lane. `image-size@2.0.2` is still within the affected advisory range, so a blind override would not remediate the finding.
- Interim control: `mobile/metro.config.js` disables the vulnerable `image-size` HEIF/ICNS/JXL parsers and removes `heic`/`avif` asset extensions from Metro's accepted set. Do not process untrusted image inputs through the mobile/Metro build toolchain; keep the current Expo lane and re-check on every Expo/Metro release refresh. `tools/validate-dependency-risk.mjs` verifies these controls.
- Risk owner: Mobile/release owner
- Review due: 2026-08-24
- Required closure: Adopt a patched Metro/image-size dependency line compatible with Expo 56 or complete and validate a deliberate Expo lane migration; then require `npm audit --audit-level=high` to pass.
- Release gate: No 100% production-readiness claim while this high-severity audit finding remains open.
