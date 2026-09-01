import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import {
  expectedSerenaWorkspaceFolders,
  requiredApiRoutes,
  validateSerenaObsidianSync,
} from './validate-serena-obsidian.mjs';

test('serena/obsidian sync validator includes required api routes', () => {
  assert.equal(requiredApiRoutes.length > 0, true);
  assert.equal(requiredApiRoutes.includes('/api/v1/auth/register'), true);
  assert.equal(requiredApiRoutes.includes('/api/v1/rooms/stream/{room_id}'), true);
  assert.equal(requiredApiRoutes.includes('/api/v1/auth/mfa/enroll'), true);
  assert.equal(requiredApiRoutes.includes('/api/v1/workspaces/switch'), true);
  assert.equal(requiredApiRoutes.includes('/api/webhooks/zoom'), true);
  assert.equal(expectedSerenaWorkspaceFolders.includes('production-readiness'), true);
  assert.equal(expectedSerenaWorkspaceFolders.includes('tools'), true);
});

test('serena project and docs are internally aligned', async () => {
  const project = await readFile('.serena/project.yml', 'utf8');
  const readme = await readFile('README.md', 'utf8');
  const roadmap = await readFile('SF-roadmap.md', 'utf8');
  const architecture = await readFile('SF-architecture.md', 'utf8');
  const repoBrief = await readFile('REPO_BRIEF.md', 'utf8');
  const obsidian = await readFile('production-readiness/obsidian-production-readiness.md', 'utf8');

  assert.ok(project.includes('project_name'));
  assert.ok(project.includes('languages'));
  assert.ok(project.includes('additional_workspace_folders'));
  assert.ok(readme.includes('terraform -chdir=build/terraform init -backend=false'));
  assert.ok(readme.includes('terraform -chdir=build/terraform fmt -check -recursive'));
  assert.ok(readme.includes('terraform -chdir=build/terraform validate'));
  assert.equal(readme.includes('terraform fmt -check\n'), false);
  assert.ok(roadmap.includes('Serena'));
  assert.ok(architecture.includes('/api/v1/auth/register'));
  assert.ok(architecture.includes('/api/v1/rooms/stream/{room_id}'));
  assert.ok(repoBrief.includes('terraform fmt -check -recursive'));
  assert.equal(repoBrief.includes('terraform fmt -check &&'), false);
  assert.ok(obsidian.includes('Serena/Obsidian Pre-Merge Gate'));
  assert.ok(obsidian.includes('F-AUD External Evidence Closure'));
});

test('validateSerenaObsidianSync passes for current repo', async () => {
  await validateSerenaObsidianSync();
});
