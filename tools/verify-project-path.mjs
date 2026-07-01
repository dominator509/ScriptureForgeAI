import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { platform } from 'node:os';
import { delimiter, extname, join, win32 as pathWin32 } from 'node:path';

const isWindows = platform() === 'win32';

export const requiredCommands = [
  { name: 'rtk', versionArgs: ['--version'] },
  { name: 'git', versionArgs: ['--version'] },
  { name: 'go', versionArgs: ['version'] },
  { name: 'node', versionArgs: ['--version'] },
  { name: 'npm', versionArgs: ['--version'] },
  { name: 'cargo', versionArgs: ['--version'] },
  { name: 'rustc', versionArgs: ['--version'] },
  { name: 'terraform', versionArgs: ['version'] },
];

export const ciRequiredCommands = requiredCommands
  .filter((command) => command.name !== 'rtk')
  .concat([
    { name: 'psql', versionArgs: ['--version'] },
  ]);

export const optionalCommands = [
  {
    name: 'gopls',
    versionArgs: ['version'],
    reason: 'required for Serena Go semantic navigation; install into the repo-local Go bin or user PATH before Serena onboarding/navigation',
    strict: true,
  },
  {
    name: 'protoc',
    reason: 'optional locally because services/scripture-engine vendors protoc through protoc-bin-vendored',
  },
  {
    name: 'psql',
    versionArgs: ['--version'],
    reason: 'optional for manual local database work; GitHub Actions installs postgresql-client for migration checks',
    remediation: 'install or expose the PostgreSQL client tools so psql resolves on PATH before collecting staging database/RLS evidence',
    strict: true,
  },
  {
    name: 'docker',
    reason: 'optional for local disposable pgvector RLS proof via tools/run-rls-db-integration-docker.mjs',
  },
  {
    name: 'kubectl',
    versionArgs: ['version', '--client=true'],
    reason: 'optional until staging Kubernetes evidence is being collected',
    strict: true,
  },
  {
    name: 'aws',
    versionArgs: ['--version'],
    versionPattern: /^aws-cli\/2\./,
    versionRequirement: 'AWS CLI v2',
    reason: 'optional until staging AWS/Terraform evidence is being collected',
    remediation: 'install or expose AWS CLI v2 so aws resolves on PATH before collecting staging Terraform, IRSA, and Secrets Manager evidence',
    strict: true,
  },
  {
    name: 'gh',
    versionArgs: ['--version'],
    reason: 'optional for local GitHub convenience; CI evidence can be validated from artifacts',
    strict: true,
  },
];

export const projectPathProofMarkers = [
  'project_path_required_tools_resolved=true',
  'project_path_required_versions_checked=true',
  'project_path_optional_tools_reported=true',
  'vendored_protoc_covered=true',
];

export const strictStagingPathProofMarkers = [
  ...projectPathProofMarkers,
  'strict_staging_path_mode=true',
  'strict_staging_tools_resolved=true',
  'strict_staging_versions_checked=true',
  'aws_cli_v2_required=true',
  'strict_staging_broken_shims_rejected=true',
];

export const ciPathProofMarkers = [
  'ci_path_mode=true',
  'ci_required_tools_resolved=true',
  'ci_required_versions_checked=true',
  'ci_database_client_resolved=true',
  'rtk_not_required_in_ci=true',
];

export const ciStrictStagingPathProofMarkers = [
  ...ciPathProofMarkers,
  'ci_strict_staging_path_mode=true',
  'strict_staging_tools_resolved=true',
  'strict_staging_versions_checked=true',
  'aws_cli_v2_required=true',
  'strict_staging_broken_shims_rejected=true',
];

export function resolveCommand(name, runner = spawnSync, platformName = platform()) {
  const runningOnWindows = platformName === 'win32';
  const probe = runningOnWindows
    ? runner('where.exe', [name], { encoding: 'utf8' })
    : runner('which', [name], { encoding: 'utf8' });
  if (probe.status !== 0) {
    return runningOnWindows && runner === spawnSync ? resolveWindowsPathManually(name) : [];
  }
  return probe.stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function resolveWindowsPathManually(name) {
  const pathText = [
    process.env.Path,
    process.env.PATH,
    ...windowsFallbackDirectoriesForCommand(name),
  ].filter(Boolean).join(delimiter);
  const extensions = extname(name)
    ? ['']
    : (process.env.PATHEXT ?? '.COM;.EXE;.BAT;.CMD')
        .split(';')
        .map((extension) => extension.trim())
        .filter(Boolean);
  const matches = [];
  const seen = new Set();
  for (const directory of pathText.split(delimiter)) {
    const trimmedDirectory = directory.trim();
    if (!trimmedDirectory) {
      continue;
    }
    for (const extension of extensions) {
      const candidate = join(trimmedDirectory, `${name}${extension}`);
      const key = candidate.toLowerCase();
      if (!seen.has(key) && existsSync(candidate)) {
        matches.push(candidate);
        seen.add(key);
      }
    }
  }
  return matches;
}

export function windowsFallbackDirectoriesForCommand(name, env = process.env, { platformName = platform() } = {}) {
  if (platformName !== 'win32') {
    return [];
  }
  const pathJoin = platformName === 'win32' ? pathWin32.join : join;
  const repoRoot = process.cwd();
  const programFiles = [
    env.ProgramFiles,
    env['ProgramFiles(x86)'],
    'C:\\Program Files',
    'C:\\Program Files (x86)',
  ].filter(Boolean);
  const userProfile = env.USERPROFILE ?? env.UserProfile ?? '';
  const localAppData = env.LOCALAPPDATA ?? (userProfile ? pathJoin(userProfile, 'AppData', 'Local') : '');
  const directories = [];

  if (name === 'rtk') {
    if (userProfile) {
      directories.push(pathJoin(userProfile, '.local', 'bin'));
    }
    directories.push('C:\\Users\\domin\\.local\\bin');
  }

  if (name === 'go') {
    directories.push(pathJoin(repoRoot, '.tools', 'go', 'bin'));
  }

  if (name === 'cargo' || name === 'rustc') {
    directories.push(pathJoin(repoRoot, '.tools', 'cargo', 'bin'));
  }

  if (name === 'terraform') {
    directories.push(pathJoin(repoRoot, '.tools', 'terraform'));
  }

  if (name === 'gopls') {
    directories.push(pathJoin(repoRoot, '.tools', 'go', 'bin'));
    if (userProfile) {
      directories.push(pathJoin(userProfile, 'go', 'bin'));
    }
    directories.push('C:\\Users\\domin\\go\\bin');
  }

  if (name === 'aws') {
    for (const root of programFiles) {
      directories.push(pathJoin(root, 'Amazon', 'AWSCLIV2'));
      directories.push(pathJoin(root, 'AWSCLIV2'));
    }
    if (localAppData) {
      directories.push(pathJoin(localAppData, 'Microsoft', 'WinGet', 'Links'));
    }
    if (env.ChocolateyInstall) {
      directories.push(pathJoin(env.ChocolateyInstall, 'bin'));
    }
    directories.push('C:\\ProgramData\\chocolatey\\bin');
    if (userProfile) {
      directories.push(pathJoin(userProfile, 'scoop', 'shims'));
    }
  }

  if (name === 'gh') {
    for (const root of programFiles) {
      directories.push(pathJoin(root, 'GitHub CLI'));
    }
    if (localAppData) {
      directories.push(pathJoin(localAppData, 'Microsoft', 'WinGet', 'Links'));
    }
    if (env.ChocolateyInstall) {
      directories.push(pathJoin(env.ChocolateyInstall, 'bin'));
    }
    directories.push('C:\\ProgramData\\chocolatey\\bin');
    if (userProfile) {
      directories.push(pathJoin(userProfile, 'scoop', 'shims'));
    }
  }

  if (name === 'psql') {
    for (const root of programFiles) {
      const postgresRoot = pathJoin(root, 'PostgreSQL');
      for (const version of discoverChildDirectories(postgresRoot)) {
        directories.push(pathJoin(postgresRoot, version, 'bin'));
      }
      for (const version of ['18', '17', '16', '15', '14', '13', '12']) {
        directories.push(pathJoin(postgresRoot, version, 'bin'));
      }
    }
    if (localAppData) {
      directories.push(pathJoin(localAppData, 'Microsoft', 'WinGet', 'Links'));
    }
    if (env.ChocolateyInstall) {
      directories.push(pathJoin(env.ChocolateyInstall, 'bin'));
    }
    directories.push('C:\\ProgramData\\chocolatey\\bin');
    if (userProfile) {
      directories.push(pathJoin(userProfile, 'scoop', 'shims'));
    }
  }

  return [...new Set(directories)];
}

function discoverChildDirectories(root) {
  try {
    return readdirSync(root, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name);
  } catch {
    return [];
  }
}

export function readVersion(command, versionArgs = ['--version'], runner = spawnSync) {
  return readVersionDetails(command, versionArgs, runner).version;
}

function readVersionDetails(command, versionArgs = ['--version'], runner = spawnSync, versionPattern = null) {
  const launch = buildLaunch(command, versionArgs);
  const result = runner(launch.command, launch.args, { encoding: 'utf8' });
  const text = `${result.stdout ?? ''}${result.stderr ?? ''}`.trim();
  const version = result.status === 0 ? firstLine(text) : `<version check failed: ${firstLine(text) || result.error?.message || 'unknown'}>`;
  const versionMatches = result.status === 0 && versionPattern ? versionPattern.test(version) : null;
  return {
    ok: result.status === 0 && (versionMatches ?? true),
    command_ok: result.status === 0,
    version,
    version_matches: versionMatches,
  };
}

export function buildPathReport({
  runner = spawnSync,
  strictStaging = false,
  ci = false,
  vendoredProtocCoverage = checkVendoredProtocCoverage,
  platformName = platform(),
} = {}) {
  const vendoredProtoc = vendoredProtocCoverage();
  const requiredSet = ci ? ciRequiredCommands : requiredCommands;
  const required = requiredSet.map((command) => {
    const paths = resolveCommand(command.name, runner, platformName);
    return {
      name: command.name,
      required: true,
      ok: paths.length > 0,
      paths,
      version: paths.length > 0 ? readVersion(preferredExecutable(paths, command.name), command.versionArgs, runner) : null,
    };
  });
  const optional = optionalCommands.map((command) => {
    const paths = resolveCommand(command.name, runner, platformName);
    const version = paths.length > 0 && command.versionArgs
      ? readVersionDetails(preferredExecutable(paths, command.name), command.versionArgs, runner, command.versionPattern)
      : null;
    const versionOK = version ? version.ok : null;
    return {
      name: command.name,
      required: strictStaging && command.strict === true,
      ok: paths.length > 0 && (!strictStaging || command.strict !== true || versionOK !== false),
      paths,
      version: version?.version ?? null,
      version_ok: versionOK,
      version_requirement: command.versionRequirement,
      version_matches: version?.version_matches ?? null,
      searched_paths: strictStaging && paths.length === 0 ? windowsFallbackDirectoriesForCommand(command.name, process.env, { platformName }) : undefined,
      reason: command.reason,
      remediation: command.remediation,
      strict: command.strict === true,
    };
  });
  const strictCommands = optional.filter((command) => command.strict);
  return {
    schema_version: 1,
    mode: ci && strictStaging ? 'ci-staging-evidence' : ci ? 'ci' : strictStaging ? 'staging-evidence' : 'local',
    threshold_pass: required.every((command) => command.ok) && vendoredProtoc.ok && (!strictStaging || strictCommands.every((command) => command.ok)),
    required,
    optional,
    vendored_protoc: vendoredProtoc,
  };
}

export function formatPathReport(report) {
  const lines = ['ScriptureForgeAI PATH readiness'];
  lines.push(`mode: ${report.mode ?? 'local'}`);
  lines.push(`required: ${report.required.filter((command) => command.ok).length}/${report.required.length}`);
  for (const command of report.required) {
    const marker = command.ok ? 'OK' : 'MISSING';
    lines.push(`- ${marker} ${command.name}${command.version ? ` (${command.version})` : ''}`);
    for (const resolvedPath of command.paths) {
      lines.push(`  ${resolvedPath}`);
    }
  }
  lines.push('optional:');
  for (const command of report.optional) {
    const marker = command.ok
      ? 'OK'
      : command.paths?.length > 0 && command.version_ok === false
        ? 'BROKEN'
        : command.required
          ? 'MISSING'
          : 'not on PATH';
    const strictLabel = command.strict ? ' [staging-evidence]' : '';
    lines.push(`- ${marker} ${command.name}${strictLabel}${command.version ? ` (${command.version})` : ''}: ${command.reason}`);
    if (command.paths?.length > 0 && command.version_ok === false) {
      const requirement = command.version_requirement ? ` or did not satisfy ${command.version_requirement}` : '';
      lines.push(`  remediation: ${command.name} resolves on PATH but its version check failed${requirement}; repair, upgrade, or remove the broken shim before collecting staging evidence`);
    }
    if (!command.ok && command.required && command.remediation) {
      lines.push(`  remediation: ${command.remediation}`);
    }
    if (!command.ok && command.required && command.searched_paths?.length) {
      lines.push('  searched fallback paths:');
      for (const searchedPath of command.searched_paths) {
        lines.push(`  ${searchedPath}`);
      }
    }
    for (const resolvedPath of command.paths) {
      lines.push(`  ${resolvedPath}`);
    }
  }
  if (report.vendored_protoc) {
    const marker = report.vendored_protoc.ok ? 'OK' : 'MISSING';
    lines.push(`vendored protoc: ${marker} ${report.vendored_protoc.reason}`);
    for (const detail of report.vendored_protoc.details ?? []) {
      lines.push(`  ${detail}`);
    }
  }
  const proofMarkers = report.mode === 'ci-staging-evidence'
    ? ciStrictStagingPathProofMarkers
    : report.mode === 'ci'
    ? ciPathProofMarkers
    : report.mode === 'staging-evidence'
      ? strictStagingPathProofMarkers
      : projectPathProofMarkers;
  lines.push(`path readiness proof: ${proofMarkers.join(', ')}`);
  return `${lines.join('\n')}\n`;
}

export function checkVendoredProtocCoverage({ root = process.cwd() } = {}) {
  const cargoTomlPath = join(root, 'services', 'scripture-engine', 'Cargo.toml');
  const cargoLockPath = join(root, 'services', 'scripture-engine', 'Cargo.lock');
  const details = [];
  let cargoToml = '';
  let cargoLock = '';

  try {
    cargoToml = readFileSync(cargoTomlPath, 'utf8');
  } catch {
    details.push(`missing ${cargoTomlPath}`);
  }

  try {
    cargoLock = readFileSync(cargoLockPath, 'utf8');
  } catch {
    details.push(`missing ${cargoLockPath}`);
  }

  const manifestCovered = /protoc-bin-vendored\s*=/.test(cargoToml);
  const lockCovered = /name = "protoc-bin-vendored"/.test(cargoLock) && /name = "protoc-bin-vendored-win32"/.test(cargoLock);
  if (!manifestCovered) {
    details.push('services/scripture-engine/Cargo.toml does not declare protoc-bin-vendored');
  }
  if (!lockCovered) {
    details.push('services/scripture-engine/Cargo.lock does not lock protoc-bin-vendored and win32 package coverage');
  }

  return {
    ok: details.length === 0,
    reason: 'standalone protoc remains optional only while Rust locks protoc-bin-vendored coverage',
    details: details.length > 0 ? details : [
      'services/scripture-engine/Cargo.toml declares protoc-bin-vendored',
      'services/scripture-engine/Cargo.lock locks protoc-bin-vendored including win32 coverage',
    ],
  };
}

function firstLine(text) {
  return text.split(/\r?\n/).map((line) => line.trim()).find(Boolean) ?? '';
}

function preferredExecutable(paths, name) {
  if (isWindows && name === 'npm') {
    return paths.find((path) => /\.cmd$/i.test(path)) ?? paths[0];
  }
  return paths[0];
}

function buildLaunch(command, args) {
  if (isWindows && /\.(cmd|bat)$/i.test(command)) {
    const shimName = command.split(/[\\/]/).pop() ?? command;
    return {
      command: process.env.ComSpec ?? 'cmd.exe',
      args: ['/d', '/s', '/c', [shimName, ...args.map(quoteWindowsArg)].join(' ')],
    };
  }
  return { command, args };
}

function quoteWindowsArg(value) {
  if (/^[A-Za-z0-9_./\\:=+-]+$/.test(value)) {
    return value;
  }
  return `"${value.replaceAll('"', '\\"')}"`;
}

function main() {
  const json = process.argv.includes('--json');
  const strictStaging = process.argv.includes('--strict-staging') || process.argv.includes('--staging-evidence');
  const ci = process.argv.includes('--ci') || process.argv.includes('--ci-workflow');
  const report = buildPathReport({ strictStaging, ci });
  if (json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    process.stdout.write(formatPathReport(report));
  }
  if (!report.threshold_pass) {
    process.exit(1);
  }
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('verify-project-path.mjs')) {
  main();
}
