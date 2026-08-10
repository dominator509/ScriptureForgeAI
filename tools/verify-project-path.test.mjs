import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import test from 'node:test';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildPathReport, checkVendoredProtocCoverage, ciPathProofMarkers, ciStrictStagingPathProofMarkers, formatPathReport, requiredCommands, windowsFallbackDirectoriesForCommand } from './verify-project-path.mjs';

test('project path report fails closed when a required command is missing', () => {
  const missing = new Set(['terraform']);
  const report = buildPathReport({
    runner: fakeRunner({ missing }),
  });

  assert.equal(report.threshold_pass, false);
  assert.equal(report.required.find((command) => command.name === 'terraform').ok, false);
  assert.equal(report.required.find((command) => command.name === 'go').ok, true);
});

test('project path report does not require optional staging/manual tools', () => {
  const report = buildPathReport({
    runner: fakeRunner({ missing: new Set(['gopls', 'protoc', 'psql', 'docker', 'kubectl', 'aws', 'gh']) }),
  });

  assert.equal(report.threshold_pass, true);
  assert.equal(report.mode, 'local');
  assert.equal(report.optional.every((command) => command.ok === false), true);
  assert.match(formatPathReport(report), /optional:/);
});

test('project path report can require staging evidence tools without requiring protoc', () => {
  const report = buildPathReport({
    runner: fakeRunner({ missing: new Set(['protoc']) }),
    strictStaging: true,
  });

  assert.equal(report.threshold_pass, true);
  assert.equal(report.mode, 'staging-evidence');
  assert.equal(report.optional.find((command) => command.name === 'protoc').required, false);
  assert.equal(report.optional.find((command) => command.name === 'aws').required, true);
  assert.match(formatPathReport(report), /aws \[staging-evidence\]/);
  assert.match(formatPathReport(report), /vendored protoc: OK/);
  assert.match(formatPathReport(report), /vendored_protoc_covered=true/);
});

test('project path report fails closed if standalone protoc is missing and Rust vendored protoc coverage is removed', () => {
  const report = buildPathReport({
    runner: fakeRunner({ missing: new Set(['protoc']) }),
    vendoredProtocCoverage: () => ({
      ok: false,
      reason: 'test vendored protoc missing',
      details: ['missing protoc-bin-vendored'],
    }),
  });

  assert.equal(report.threshold_pass, false);
  assert.equal(report.vendored_protoc.ok, false);
  assert.match(formatPathReport(report), /vendored protoc: MISSING test vendored protoc missing/);
  assert.match(formatPathReport(report), /missing protoc-bin-vendored/);
});

test('vendored protoc coverage check validates Rust manifest and lockfile', () => {
  const report = checkVendoredProtocCoverage();

  assert.equal(report.ok, true);
  assert.match(report.details.join('\n'), /Cargo\.toml declares protoc-bin-vendored/);
  assert.match(report.details.join('\n'), /Cargo\.lock locks protoc-bin-vendored/);
});

test('project path report CI mode checks CI tools without requiring RTK', () => {
  const report = buildPathReport({
    runner: fakeRunner({ missing: new Set(['rtk']) }),
    ci: true,
  });

  assert.equal(report.threshold_pass, true);
  assert.equal(report.mode, 'ci');
  assert.equal(report.required.some((command) => command.name === 'rtk'), false);
  assert.equal(report.required.some((command) => command.name === 'psql'), true);
  for (const marker of ciPathProofMarkers) {
    assert.match(formatPathReport(report), new RegExp(marker));
  }
});

test('project path report CI mode fails when PostgreSQL client is missing', () => {
  const report = buildPathReport({
    runner: fakeRunner({ missing: new Set(['psql']) }),
    ci: true,
  });

  assert.equal(report.threshold_pass, false);
  assert.equal(report.mode, 'ci');
  assert.equal(report.required.find((command) => command.name === 'psql').ok, false);
  assert.match(formatPathReport(report), /MISSING psql/);
});

test('project path report CI strict staging mode requires staging tools without requiring RTK', () => {
  const report = buildPathReport({
    runner: fakeRunner({ missing: new Set(['rtk']) }),
    ci: true,
    strictStaging: true,
  });

  assert.equal(report.threshold_pass, true);
  assert.equal(report.mode, 'ci-staging-evidence');
  assert.equal(report.required.some((command) => command.name === 'rtk'), false);
  assert.equal(report.optional.find((command) => command.name === 'aws').required, true);
  assert.equal(report.optional.find((command) => command.name === 'kubectl').required, true);
  assert.equal(report.optional.find((command) => command.name === 'gopls').required, true);
  for (const marker of ciStrictStagingPathProofMarkers) {
    assert.match(formatPathReport(report), new RegExp(marker));
  }
});

test('project path report CI strict staging mode fails when staging tools are missing', () => {
  const report = buildPathReport({
    runner: fakeRunner({ missing: new Set(['aws']) }),
    ci: true,
    strictStaging: true,
  });

  assert.equal(report.threshold_pass, false);
  assert.equal(report.mode, 'ci-staging-evidence');
  assert.equal(report.optional.find((command) => command.name === 'aws').ok, false);
  assert.match(formatPathReport(report), /MISSING aws \[staging-evidence\]/);
});

test('project path report fails strict staging mode when an evidence tool has a broken version check', () => {
  const report = buildPathReport({
    runner: fakeRunner({ versionFailures: new Set(['aws']) }),
    strictStaging: true,
  });

  const aws = report.optional.find((command) => command.name === 'aws');
  assert.equal(report.threshold_pass, false);
  assert.equal(aws.required, true);
  assert.equal(aws.ok, false);
  assert.equal(aws.version_ok, false);
  assert.match(aws.version, /version check failed/);
  assert.match(formatPathReport(report), /BROKEN aws \[staging-evidence\]/);
  assert.match(formatPathReport(report), /repair, upgrade, or remove the broken shim/);
});

test('project path report fails strict staging mode when AWS CLI is v1', () => {
  const report = buildPathReport({
    runner: fakeRunner({ versionOutputs: new Map([['aws', 'aws-cli/1.32.0 Python/3.11.0 Linux/6 botocore/1.34.0']]) }),
    strictStaging: true,
  });

  const aws = report.optional.find((command) => command.name === 'aws');
  assert.equal(report.threshold_pass, false);
  assert.equal(aws.required, true);
  assert.equal(aws.ok, false);
  assert.equal(aws.version_ok, false);
  assert.equal(aws.version_matches, false);
  assert.equal(aws.version_requirement, 'AWS CLI v2');
  assert.match(formatPathReport(report), /did not satisfy AWS CLI v2/);
});

test('project path report CI strict staging mode accepts AWS CLI v2 without requiring RTK', () => {
  const report = buildPathReport({
    runner: fakeRunner({
      missing: new Set(['rtk']),
      versionOutputs: new Map([['aws', 'aws-cli/2.17.0 Python/3.11.0 Linux/6 exe/x86_64.ubuntu.22']]),
    }),
    ci: true,
    strictStaging: true,
  });

  const aws = report.optional.find((command) => command.name === 'aws');
  assert.equal(report.threshold_pass, true);
  assert.equal(report.mode, 'ci-staging-evidence');
  assert.equal(report.required.some((command) => command.name === 'rtk'), false);
  assert.equal(aws.ok, true);
  assert.equal(aws.version_ok, true);
  assert.equal(aws.version_matches, true);
});

test('project path report fails strict staging mode when evidence tools are missing', () => {
  const report = buildPathReport({
    runner: fakeRunner({ missing: new Set(['aws', 'kubectl', 'psql', 'docker', 'gh', 'gopls']) }),
    strictStaging: true,
    platformName: 'win32',
  });

  assert.equal(report.threshold_pass, false);
  assert.equal(report.optional.find((command) => command.name === 'aws').required, true);
  assert.equal(report.optional.find((command) => command.name === 'aws').ok, false);
  assert.match(report.optional.find((command) => command.name === 'aws').remediation, /AWS CLI v2/);
  assert.match(report.optional.find((command) => command.name === 'psql').remediation, /PostgreSQL client/);
  assert.ok(report.optional.find((command) => command.name === 'aws').searched_paths.length > 0);
  assert.ok(report.optional.find((command) => command.name === 'psql').searched_paths.length > 0);
  assert.equal(report.optional.find((command) => command.name === 'docker').required, false);
  assert.equal(report.optional.find((command) => command.name === 'protoc').required, false);
  assert.match(formatPathReport(report), /MISSING aws \[staging-evidence\]/);
  assert.match(formatPathReport(report), /remediation: install or expose AWS CLI v2/);
  assert.match(formatPathReport(report), /remediation: install or expose the PostgreSQL client tools/);
  assert.match(formatPathReport(report), /searched fallback paths:/);
});

test('Windows activation scripts expose strict staging verification and common tool paths', async () => {
  const [cmdScript, psScript] = await Promise.all([
    readFile('tools/use-project-path.cmd', 'utf8'),
    readFile('tools/use-project-path.ps1', 'utf8'),
  ]);

  assert.match(cmdScript, /--strict-staging/);
  assert.match(cmdScript, /SCRIPTUREFORGE_USERPROFILE/);
  assert.match(cmdScript, /\.local\\bin/);
  assert.match(cmdScript, /%USERPROFILE%\\go\\bin/);
  assert.match(cmdScript, /%HOMEDRIVE%%HOMEPATH%\\go\\bin/);
  assert.match(cmdScript, /C:\\Users\\domin\\go\\bin/);
  assert.match(cmdScript, /SCRIPTUREFORGE_COMBINED_PATH/);
  assert.match(cmdScript, /set "PATH="/);
  assert.match(cmdScript, /node "%SCRIPTUREFORGE_ROOT%\\tools\\verify-project-path\.mjs" --strict-staging\r?\n    if errorlevel 1 exit \/b 1/);
  assert.match(cmdScript, /if not "%~1"==""/);
  assert.match(cmdScript, /call %\*/);
  assert.match(cmdScript, /exit \/b %ERRORLEVEL%/);
  assert.doesNotMatch(cmdScript, /where aws >nul 2>nul \|\| exit \/b 1/);
  assert.doesNotMatch(cmdScript, /where psql >nul 2>nul \|\| exit \/b 1/);
  assert.match(cmdScript, /exit \/b/);
  assert.match(cmdScript, /GitHub CLI/);
  assert.match(cmdScript, /Amazon\\AWSCLIV2/);
  assert.match(cmdScript, /WinGet\\Links/);
  assert.match(cmdScript, /chocolatey\\bin/);
  assert.match(cmdScript, /scoop\\shims/);
  assert.match(cmdScript, /PostgreSQL\\17\\bin/);
  assert.match(cmdScript, /Program Files \(x86\)\\PostgreSQL\\17\\bin/);

  assert.match(psScript, /StrictStaging/);
  assert.match(psScript, /ValueFromRemainingArguments/);
  assert.match(psScript, /& \$Command\[0\]/);
  assert.match(psScript, /GetFolderPath\("UserProfile"\)/);
  assert.match(psScript, /\.local\\bin/);
  assert.match(psScript, /C:\\Users\\domin\\go\\bin/);
  assert.match(psScript, /\$env:PATH = \$env:Path/);
  assert.match(psScript, /node @verifierArgs\r?\n    if \(\$null -ne \$LASTEXITCODE -and \$LASTEXITCODE -ne 0\)/);
  assert.match(psScript, /go\\bin/);
  assert.match(psScript, /GitHub CLI/);
  assert.match(psScript, /Amazon\\AWSCLIV2/);
  assert.match(psScript, /WinGet\\Links/);
  assert.match(psScript, /chocolatey\\bin/);
  assert.match(psScript, /scoop\\shims/);
  assert.match(psScript, /PostgreSQL\\17\\bin/);
  assert.match(psScript, /Program Files \(x86\)\\PostgreSQL\\17\\bin/);
});

test('Windows fallback directories include common AWS and PostgreSQL installs', () => {
  const env = {
    ProgramFiles: 'C:\\Program Files',
    'ProgramFiles(x86)': 'C:\\Program Files (x86)',
    USERPROFILE: 'C:\\Users\\domin',
    LOCALAPPDATA: 'C:\\Users\\domin\\AppData\\Local',
    ChocolateyInstall: 'C:\\ProgramData\\chocolatey',
  };

  assert.deepEqual(
    windowsFallbackDirectoriesForCommand('aws', env, { platformName: 'win32' }).filter((entry) => entry.includes('AWSCLIV2')),
    [
      'C:\\Program Files\\Amazon\\AWSCLIV2',
      'C:\\Program Files\\AWSCLIV2',
      'C:\\Program Files (x86)\\Amazon\\AWSCLIV2',
      'C:\\Program Files (x86)\\AWSCLIV2',
    ],
  );
  assert.ok(
    windowsFallbackDirectoriesForCommand('aws', env, { platformName: 'win32' }).includes('C:\\Users\\domin\\AppData\\Local\\Microsoft\\WinGet\\Links'),
    'winget link directory should be searched for aws',
  );
  assert.ok(
    windowsFallbackDirectoriesForCommand('aws', env, { platformName: 'win32' }).includes('C:\\ProgramData\\chocolatey\\bin'),
    'Chocolatey bin directory should be searched for aws',
  );
  assert.ok(
    windowsFallbackDirectoriesForCommand('aws', env, { platformName: 'win32' }).includes('C:\\Users\\domin\\scoop\\shims'),
    'Scoop shim directory should be searched for aws',
  );
  assert.ok(
    windowsFallbackDirectoriesForCommand('psql', env, { platformName: 'win32' }).some((entry) => entry.endsWith('PostgreSQL\\13\\bin')),
    'PostgreSQL 13 bin directory should be searched for psql',
  );
  assert.ok(
    windowsFallbackDirectoriesForCommand('psql', env, { platformName: 'win32' }).some((entry) => entry.startsWith('C:\\Program Files (x86)\\PostgreSQL')),
    'Program Files (x86) PostgreSQL directories should be searched for psql',
  );
  assert.deepEqual(windowsFallbackDirectoriesForCommand('node', env, { platformName: 'win32' }), []);
});

test('Windows fallback directories include RTK and GitHub CLI installs', () => {
  const env = {
    ProgramFiles: 'C:\\Program Files',
    'ProgramFiles(x86)': 'C:\\Program Files (x86)',
    USERPROFILE: 'C:\\Users\\domin',
    LOCALAPPDATA: 'C:\\Users\\domin\\AppData\\Local',
    ChocolateyInstall: 'C:\\ProgramData\\chocolatey',
  };

  assert.deepEqual(
    windowsFallbackDirectoriesForCommand('rtk', env, { platformName: 'win32' }),
    [
      'C:\\Users\\domin\\.local\\bin',
    ],
  );
  assert.deepEqual(
    windowsFallbackDirectoriesForCommand('gh', env, { platformName: 'win32' }).filter((entry) => entry.includes('GitHub CLI')),
    [
      'C:\\Program Files\\GitHub CLI',
      'C:\\Program Files (x86)\\GitHub CLI',
    ],
  );
  assert.ok(
    windowsFallbackDirectoriesForCommand('gh', env, { platformName: 'win32' }).includes('C:\\Users\\domin\\AppData\\Local\\Microsoft\\WinGet\\Links'),
    'winget link directory should be searched for gh',
  );
  assert.ok(
    windowsFallbackDirectoriesForCommand('gh', env, { platformName: 'win32' }).includes('C:\\ProgramData\\chocolatey\\bin'),
    'Chocolatey bin directory should be searched for gh',
  );
  assert.ok(
    windowsFallbackDirectoriesForCommand('gh', env, { platformName: 'win32' }).includes('C:\\Users\\domin\\scoop\\shims'),
    'Scoop shim directory should be searched for gh',
  );
});

test('Windows fallback directories include repo-local build toolchains', async () => {
  const env = {
    USERPROFILE: 'C:\\Users\\domin',
  };
  const fixtureRoot = await mkdtemp(join(tmpdir(), 'scriptureforge-path-'));
  await mkdir(join(fixtureRoot, '.tools', 'rustup', 'toolchains', 'stable-x86_64-pc-windows-msvc', 'bin'), { recursive: true });
  const fallbackOptions = { platformName: 'win32', repoRoot: fixtureRoot };

  try {
    assert.ok(
      windowsFallbackDirectoriesForCommand('go', env, fallbackOptions).some((entry) => entry.endsWith('.tools\\go\\bin')),
      'repo-local Go bin should be searched',
    );
    assert.ok(
      windowsFallbackDirectoriesForCommand('cargo', env, fallbackOptions).some((entry) => entry.endsWith('.tools\\cargo\\bin')),
      'repo-local Cargo bin should be searched',
    );
    assert.ok(
      windowsFallbackDirectoriesForCommand('rustc', env, fallbackOptions).some((entry) => entry.endsWith('.tools\\cargo\\bin')),
      'repo-local rustc bin should be searched',
    );
    assert.ok(
      windowsFallbackDirectoriesForCommand('cargo', env, fallbackOptions).some((entry) => entry.includes('.tools\\rustup\\toolchains\\') && entry.endsWith('\\bin')),
      'repo-local Rustup toolchain bin should be searched',
    );
    assert.ok(
      windowsFallbackDirectoriesForCommand('rustc', env, fallbackOptions).some((entry) => entry.includes('.tools\\rustup\\toolchains\\') && entry.endsWith('\\bin')),
      'repo-local rustc toolchain path should be searched',
    );
    assert.ok(
      windowsFallbackDirectoriesForCommand('terraform', env, fallbackOptions).some((entry) => entry.endsWith('.tools\\terraform')),
      'repo-local Terraform dir should be searched',
    );
    assert.ok(
      windowsFallbackDirectoriesForCommand('protoc', env, fallbackOptions).some((entry) => entry.endsWith('.tools\\bin')),
      'repo-local .tools\\bin should be searched',
    );
    assert.ok(
      windowsFallbackDirectoriesForCommand('gopls', env, fallbackOptions).some((entry) => entry.endsWith('go\\bin')),
      'Go tool bin directories should be searched for gopls',
    );
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
});

test('Windows activation scripts include older supported PostgreSQL client bins', async () => {
  const [cmdScript, psScript] = await Promise.all([
    readFile('tools/use-project-path.cmd', 'utf8'),
    readFile('tools/use-project-path.ps1', 'utf8'),
  ]);

  assert.match(cmdScript, /PostgreSQL\\13\\bin/);
  assert.match(cmdScript, /PostgreSQL\\12\\bin/);
  assert.match(psScript, /PostgreSQL\\13\\bin/);
  assert.match(psScript, /PostgreSQL\\12\\bin/);
});

test('Windows user PATH installer persists project and evidence tool directories', async () => {
  const installer = await readFile('tools/install-project-path.ps1', 'utf8');

  assert.match(installer, /SetEnvironmentVariable\("Path", \$newUserPath, "User"\)/);
  assert.match(installer, /\.tools\\go\\bin/);
  assert.match(installer, /\.tools\\cargo\\bin/);
  assert.match(installer, /\.tools\\terraform/);
  assert.match(installer, /\.local\\bin/);
  assert.match(installer, /go\\bin/);
  assert.match(installer, /GitHub CLI/);
  assert.match(installer, /Amazon\\AWSCLIV2/);
  assert.match(installer, /PostgreSQL\\18\\bin/);
  assert.match(installer, /WhatIf/);
  assert.match(installer, /Windows user PATH update did not persist/);
});

function fakeRunner({ missing = new Set(), versionFailures = new Set(), versionOutputs = new Map() } = {}) {
  return (command, args) => {
    if ((command === 'where.exe' || command === 'which') && args.length === 1) {
      const name = args[0];
      if (missing.has(name)) {
        return { status: 1, stdout: '', stderr: '' };
      }
      return { status: 0, stdout: `C:\\tools\\${name}.exe\n`, stderr: '' };
    }
    const name = command.replace(/\.exe$/i, '').replace(/^C:\\tools\\/i, '');
    const normalizedName = name.replace(/\.exe$/i, '');
    if (missing.has(normalizedName)) {
      return { status: 1, stdout: '', stderr: 'missing' };
    }
    if (versionFailures.has(normalizedName)) {
      return { status: 1, stdout: '', stderr: `${normalizedName} broken version shim\n` };
    }
    if (versionOutputs.has(normalizedName)) {
      return { status: 0, stdout: `${versionOutputs.get(normalizedName)}\n`, stderr: '' };
    }
    if (normalizedName === 'aws') {
      return { status: 0, stdout: 'aws-cli/2.99.0 Python/3.12.0 test-version\n', stderr: '' };
    }
    return { status: 0, stdout: `${normalizedName} test-version\n`, stderr: '' };
  };
}
