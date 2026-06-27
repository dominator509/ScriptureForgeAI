import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';

const projectConfigPath = '.serena/project.yml';
const architectureDocPath = 'SF-architecture.md';
const roadmapDocPath = 'SF-roadmap.md';
const obsidianNotePath = 'production-readiness/obsidian-production-readiness.md';
const serenaSetupPath = 'production-readiness/serena-setup.md';
const routeSourcePath = 'cmd/platform-engine/main.go';

export const expectedSerenaLanguages = [
  'go',
  'typescript',
  'rust',
  'terraform',
  'markdown',
  'yaml',
];

export const expectedSerenaWorkspaceFolders = [
  'web',
  'mobile',
  'services/scripture-engine',
  'production-readiness',
  'tools',
];

export const requiredApiRoutes = [
  '/api/v1/auth/register',
  '/api/v1/auth/login',
  '/api/v1/auth/refresh',
  '/api/v1/auth/logout',
  '/api/v1/auth/mfa/verify',
  '/api/v1/auth/mfa/enroll',
  '/api/v1/journal_entries',
  '/api/v1/journal_entries/{id}',
  '/api/v1/journal/bootstrap',
  '/api/v1/ai/generate/study',
  '/api/ai/curriculum',
  '/api/v1/rooms/create',
  '/api/v1/rooms/active',
  '/api/v1/rooms/state/{room_id}',
  '/api/v1/rooms/stream/{room_id}',
  '/api/v1/workspaces/switch',
  '/api/webhooks/zoom',
];

export function extractListFromYaml(text, key) {
  const lines = text.split('\n');
  let sectionStart = -1;
  for (let i = 0; i < lines.length; i += 1) {
    if (/^\s*#/.test(lines[i])) {
      continue;
    }
    if (new RegExp(`^\\s*${key}:`).test(lines[i])) {
      sectionStart = i;
      break;
    }
  }
  if (sectionStart === -1) {
    return [];
  }

  const values = [];
  for (let i = sectionStart + 1; i < lines.length; i += 1) {
    const rawLine = lines[i];
    const line = rawLine.trim();
    if (line === '' || line.startsWith('#')) {
      continue;
    }
    if (line.startsWith('- ')) {
      values.push(line.slice(2).trim());
      continue;
    }
    break;
  }

  return values;
}

export function extractYamlListFromCodeFence(text, key) {
  const fenceRe = /```(?:yaml)?\n([\s\S]*?)```/g;
  let match;
  while ((match = fenceRe.exec(text)) !== null) {
    const blockText = match[1];
    const values = extractListFromYaml(blockText, key);
    if (values.length > 0) {
      return values;
    }
  }
  return [];
}

function normalizeSourceRoute(route) {
  const normalized = [];
  const withoutTrailingSlash = route.endsWith('/') ? route.slice(0, -1) : route;
  normalized.push(withoutTrailingSlash);

  const segments = withoutTrailingSlash.split('/').filter(Boolean);
  const trailingSegment = segments[segments.length - 1];
  const suffixParamMap = {
    stream: 'room_id',
    state: 'room_id',
    journal_entries: 'id',
  };

  if (suffixParamMap[trailingSegment]) {
    normalized.push(`${withoutTrailingSlash}/{${suffixParamMap[trailingSegment]}}`);
  }

  return normalized;
}

export function extractRoutesFromText(text) {
  const routes = new Set();
  const routeRe = /\/api\/(?:v1\/)?[a-zA-Z0-9_\/\-\{\}]+/g;
  const aliasRe = /`([^`]*?)`/g;

  for (const line of text.split('\n')) {
    let match;
    while ((match = aliasRe.exec(line)) !== null) {
      const token = match[1];
      if (routeRe.test(token)) {
        routes.add(token.trim());
      }
      routeRe.lastIndex = 0;
    }
    aliasRe.lastIndex = 0;

    while ((match = routeRe.exec(line)) !== null) {
      routes.add(match[0]);
    }
    routeRe.lastIndex = 0;
  }

  return Array.from(routes);
}

export async function validateSerenaObsidianSync({ workspaceRoot = process.cwd() } = {}) {
  const projectPath = path.join(workspaceRoot, projectConfigPath);
  const architecturePath = path.join(workspaceRoot, architectureDocPath);
  const roadmapPath = path.join(workspaceRoot, roadmapDocPath);
  const obsidianPath = path.join(workspaceRoot, obsidianNotePath);
  const serenaSetupPathAbs = path.join(workspaceRoot, serenaSetupPath);
  const routeSourcePathAbs = path.join(workspaceRoot, routeSourcePath);

  const [projectText, architectureText, roadmapText, obsidianText, serenaSetupText, routeSourceText] = await Promise.all([
    readFile(projectPath, 'utf8'),
    readFile(architecturePath, 'utf8'),
    readFile(roadmapPath, 'utf8'),
    readFile(obsidianPath, 'utf8'),
    readFile(serenaSetupPathAbs, 'utf8'),
    readFile(routeSourcePathAbs, 'utf8'),
  ]);

  const configuredLanguages = extractListFromYaml(projectText, 'languages');
  const configuredWorkspaces = extractListFromYaml(projectText, 'additional_workspace_folders');
  const setupLanguages = extractYamlListFromCodeFence(serenaSetupText, 'languages');
  const setupWorkspaces = extractYamlListFromCodeFence(serenaSetupText, 'additional_workspace_folders');
  const setupText = serenaSetupText;
  const requiredPreMergeTask = 'Serena/Obsidian Pre-Merge Gate';

  assert.ok(configuredLanguages.length > 0, 'Serena project languages must be configured');
  assert.ok(configuredWorkspaces.length > 0, 'Serena workspace folders must be configured');
  assert.ok(configuredLanguages.includes('go'), 'Serena language must include go');
  assert.ok(configuredWorkspaces.includes('web'), 'Serena workspace must include web');
  assert.ok(configuredWorkspaces.includes('mobile'), 'Serena workspace must include mobile');
  assert.ok(configuredWorkspaces.includes('services/scripture-engine'), 'Serena workspace must include services/scripture-engine');
  for (const folder of configuredWorkspaces) {
    assert.ok(
      existsSync(path.join(workspaceRoot, folder)),
      `Configured Serena workspace folder does not exist: ${folder}`,
    );
  }

  assert.ok(projectText.includes('project_name'), 'Serena project_name must be present');
  assert.ok(projectText.includes('encoding'), 'Serena encoding field should be present');
  assert.ok(setupText.includes('languages'), 'Serena setup template should exist');
  assert.ok(setupText.includes('additional_workspace_folders'), 'Serena setup should include workspace folders');
  assert.ok(setupLanguages.length > 0, 'Serena setup language matrix should be defined');
  assert.ok(setupWorkspaces.length > 0, 'Serena setup workspace list should be defined');
  for (const language of expectedSerenaLanguages) {
    assert.ok(setupLanguages.includes(language), `Serena setup missing language ${language}`);
  }
  for (const folder of expectedSerenaWorkspaceFolders) {
    assert.ok(setupWorkspaces.includes(folder), `Serena setup missing workspace folder ${folder}`);
    assert.ok(
      existsSync(path.join(workspaceRoot, folder)),
      `Serena setup workspace folder does not exist: ${folder}`,
    );
  }

  const routeSourceLines = routeSourceText.split('\n');
  const routeFromSource = new Set();
  const routeFromSourceCanonical = new Set();
  for (const line of routeSourceLines) {
    if (line.includes('mux.Handle(') || line.includes('mux.HandleFunc(')) {
      const routeMatch = line.match(/"([^"]+)"/);
      if (routeMatch) {
        routeFromSource.add(routeMatch[1]);
        for (const normalized of normalizeSourceRoute(routeMatch[1])) {
          routeFromSourceCanonical.add(normalized);
        }
      }
    }
  }

  assert.ok(routeFromSource.has('/api/v1/auth/register'), 'Runtime must expose /api/v1/auth/register');
  assert.ok(routeFromSourceCanonical.has('/api/v1/rooms/stream/{room_id}'), 'Runtime must expose /api/v1/rooms/stream/{room_id}');

  const architectureRoutes = extractRoutesFromText(architectureText);
  const roadmapRoutes = extractRoutesFromText(roadmapText);
  const obsidianTextBody = obsidianText;

  const allTracked = new Set([
    ...architectureRoutes,
    ...roadmapRoutes,
    ...obsidianTextBody.match(/(\/api\/[a-zA-Z0-9_\/\{\}\-]+)/g) ?? [],
  ]);

  for (const route of requiredApiRoutes) {
    const normalized = route
      .replace('{id}', '')
      .replace('{room_id}', '');
    assert.ok(allTracked.has(route) || allTracked.has(normalized), `Route ${route} must be referenced in architecture/roadmap/obsidian trackers`);
    assert.ok(routeFromSourceCanonical.has(route) || routeFromSourceCanonical.has(normalized), `Route ${route} must be implemented by runtime router`);
  }

  for (const language of expectedSerenaLanguages) {
    assert.ok(configuredLanguages.includes(language), `Expected Serena language missing: ${language}`);
  }

  for (const folder of expectedSerenaWorkspaceFolders) {
    assert.ok(configuredWorkspaces.includes(folder), `Expected Serena workspace folder missing: ${folder}`);
  }

  assert.ok(obsidianTextBody.includes('serena-setup.md'), 'Obsidian tracker should reference serena setup');
  assert.ok(obsidianTextBody.includes(requiredPreMergeTask), 'Obsidian tracker should include Serena/Obsidian pre-merge gate');
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('validate-serena-obsidian.mjs')) {
  validateSerenaObsidianSync().then(() => {
    console.log('Serena/Obsidian synchronization check passed');
  }).catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
