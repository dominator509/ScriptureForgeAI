# ScriptureForgeAI

## Local Remediation Prerequisites

The audit remediation work targets the repo-current toolchain:

- Go toolchain `1.24.3`
- Node.js with `npm ci` run inside `web/`
- Rust stable with `protoc` available on `PATH` for `services/scripture-engine`
- Terraform `1.6+`

Useful validation commands:

```bash
rtk go test ./...
rtk npm run typecheck
rtk npm run build
rtk cargo test
rtk terraform fmt -check
rtk terraform validate
```
