# ScriptureForge safe image-size compatibility package

This repository-owned package preserves the CommonJS API Metro needs while
removing the vulnerable HEIF, ICNS, JXL, and JXL stream parsers from the
transitive `image-size` dependency. It accepts only Metro's ten image formats:
BMP, GIF, JPEG, KTX, PNG, PSD, SVG, TIFF, and WebP (with `jpg`/`jpeg` mapped
to the JPEG parser).

All parsers operate on bounded headers and validate offsets, lengths, and
dimensions before reading. Unsupported formats fail closed. The package is
wired through `mobile/package.json` and the lockfile so `npm audit` cannot
silently restore the vulnerable registry package.
