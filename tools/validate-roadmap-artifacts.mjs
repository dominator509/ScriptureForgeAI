import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

export const phaseSpecs = [
  { number: '01', title: 'Infrastructure & Data Core', file: 'docs/sub_roadmaps/PHASE_01_SUB_ROADMAP.md' },
  { number: '02', title: 'Auth, RBAC & Zero-Knowledge', file: 'docs/sub_roadmaps/PHASE_02_SUB_ROADMAP.md' },
  { number: '03', title: 'Rust Scripture Engine', file: 'docs/sub_roadmaps/PHASE_03_SUB_ROADMAP.md' },
  { number: '04', title: 'AI Orchestrator Pipeline', file: 'docs/sub_roadmaps/PHASE_04_SUB_ROADMAP.md' },
  { number: '05', title: 'Live Sockets & Zoom Sync', file: 'docs/sub_roadmaps/PHASE_05_SUB_ROADMAP.md' },
  { number: '06', title: 'Web & Mobile UX Assembly', file: 'docs/sub_roadmaps/PHASE_06_SUB_ROADMAP.md' },
];

const requiredSections = [
  '## Scope',
  '## Task Matrix',
  '## Acceptance Evidence',
  '## External Blockers',
];

export function validateRoadmapText(text, spec) {
  assert.match(text, new RegExp(`^# Phase ${spec.number}: ${escapeRegExp(spec.title)}$`, 'm'), `${spec.file} title is required`);
  assert.ok(text.includes('Source: `SF-roadmap.md`'), `${spec.file} must identify SF-roadmap.md as its source`);
  assert.ok(text.includes(`Phase ${spec.number}`), `${spec.file} must identify its phase number`);
  for (const section of requiredSections) {
    assert.ok(text.includes(section), `${spec.file} is missing ${section}`);
  }
  assert.match(text, /Local implementation:/, `${spec.file} must record local implementation status`);
  assert.match(text, /External evidence:/, `${spec.file} must record external evidence status`);
  return true;
}

export async function validateRoadmapArtifacts({ workspaceRoot = process.cwd() } = {}) {
  for (const spec of phaseSpecs) {
    const filePath = path.join(workspaceRoot, spec.file);
    const text = await readFile(filePath, 'utf8');
    validateRoadmapText(text, spec);
  }
  return { phase_count: phaseSpecs.length, files: phaseSpecs.map((spec) => spec.file) };
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function main() {
  const result = await validateRoadmapArtifacts();
  console.log(`Roadmap sub-roadmap artifacts validated: ${result.phase_count} phases; roadmap_subroadmap_gate=true; phase_files=${result.files.join(',')}`);
}

if (import.meta.url === `file://${process.argv[1]?.replaceAll('\\', '/')}` || process.argv[1]?.endsWith('validate-roadmap-artifacts.mjs')) {
  main().catch((error) => {
    console.error(`Roadmap sub-roadmap validation failed: ${error.message}`);
    process.exitCode = 1;
  });
}
