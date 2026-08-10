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

- Status: Closed (2026-08-10)
- Scope: `mobile/package.json`, `mobile/package-lock.json`, `mobile/vendor/image-size`, `mobile/metro.config.js`
- Current locked versions: expo@56.0.17, `@expo/metro@56.0.0`, metro@0.84.4, repository-owned image-size@2.0.3-scriptureforge.0
- Source: `npm audit --audit-level=high`
- Historical severity: High
- Advisories: GHSA-w3rx-r6r6-pgpr and GHSA-5p2g-fcmc-qvqq, infinite-loop denial of service in ICNS/JXL/HEIF parsing.
- Current result: `npm audit --audit-level=high` reports 0 high, 0 critical, and 0 total findings after the local package is installed from the lockfile.
- Remediation constraint: npm's forced fix proposed Expo 53.0.27, which is a breaking downgrade from the repo-current Expo 56 / React Native 0.86 lane. The available registry `image-size` releases remain within the affected advisory range, so a blind registry override was not accepted.
- Closure evidence: `mobile/vendor/image-size` is a dependency-free, bounded compatibility implementation for Metro's BMP/GIF/JPEG/KTX/PNG/PSD/SVG/TIFF/WebP formats; HEIF/ICNS/JXL/JXL-stream are not registered. `tools/verify-mobile-image-size.test.mjs`, `tools/validate-dependency-risk.mjs`, Metro loading smoke, and mobile `build:check` pass against the refreshed install.
- Runtime/build control: `mobile/metro.config.js` also disables the affected parser names and removes `heic`/`avif`/`heif`/`icns`/`jxl` asset extensions. Re-run the dependency and parser gates on every Expo/Metro refresh and replace the local package with a patched upstream line when one exists.
- Risk owner: Mobile/release owner
- Required follow-up: Re-evaluate the local compatibility package when Expo/Metro or `image-size` releases change; no high-severity audit waiver is active.
- Release gate: The mobile audit gate must remain green and the local package validator must remain enforced in CI.
