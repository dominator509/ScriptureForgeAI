import assert from 'node:assert/strict';
import test from 'node:test';
import { parseArgs, requiredIds, strictProbeFamilies, validateManifest } from './validate-staging-evidence.mjs';
import { ciReleaseEvidenceProofMarkers } from './write-ci-release-evidence.mjs';

test('parseArgs supports manifest path and strict release mode', () => {
  const args = parseArgs(['--manifest', 'production-readiness/staging.json', '--strict-release']);
  assert.equal(args.evidenceFile, 'production-readiness/staging.json');
  assert.equal(args.strictRelease, true);
});

test('strict probe families require semantic marker checks for every probe-backed item', () => {
  const probeBackedIds = requiredIds.filter((id) => id !== 'SEC-SIGNOFF-001').sort();
  assert.deepEqual(Object.keys(strictProbeFamilies).sort(), probeBackedIds);

  for (const [id, requirement] of Object.entries(strictProbeFamilies)) {
    assert.equal(typeof requirement.commandIncludes, 'string', `${id} must declare commandIncludes`);
    assert.equal(typeof requirement.artifactIncludes, 'string', `${id} must declare artifactIncludes`);
    assert.ok(requirement.commandIncludes.length > 0, `${id} commandIncludes must not be empty`);
    assert.ok(requirement.artifactIncludes.length > 0, `${id} artifactIncludes must not be empty`);

    const markers = Array.isArray(requirement.summaryIncludes)
      ? requirement.summaryIncludes
      : [requirement.summaryIncludes];
    assert.ok(markers.length > 0, `${id} must declare strict summary markers`);
    assert.ok(markers.every((marker) => typeof marker === 'string' && marker.length > 0), `${id} strict summary markers must be non-empty strings`);
  }
});

test('validateManifest accepts pending items in contract mode', () => {
  const manifest = baseManifest({
    statusFor: () => 'pending_external',
  });

  const result = validateManifest(manifest);

  assert.equal(result.items, requiredIds.length);
  assert.equal(result.strictRelease, false);
});

test('validateManifest strict release accepts passed items and signoff accepted risk', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });

  assert.doesNotThrow(() => validateManifest(manifest, { strictRelease: true }));
});

test('validateManifest strict release accepts passed security signoff with required markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: () => 'passed',
  });

  assert.doesNotThrow(() => validateManifest(manifest, { strictRelease: true }));
});

test('validateManifest strict release rejects service versions not bound to the release candidate', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: () => 'passed',
  });
  const mobileItem = manifest.items.find((item) => item.id === 'CLIENT-MOBILE-001');
  mobileItem.evidence[0].result_summary = mobileItem.evidence[0].result_summary.replaceAll(
    'service_version=scriptureforge-mobile:0123456789abcdef0123456789abcdef01234567',
    'service_version=scriptureforge-mobile:oldsha',
  );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-MOBILE-001 strict release evidence must include a tools\/mobileprobe JSON report/,
  );
});

test('validateManifest strict release rejects pending, blocked, and failed items', () => {
  for (const status of ['pending_external', 'blocked', 'failed']) {
    const manifest = baseManifest({
      releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
      statusFor: (id) => id === 'DEPLOY-TF-001' ? status : 'passed',
    });

    assert.throws(
      () => validateManifest(manifest, { strictRelease: true }),
      /DEPLOY-TF-001 must be passed/,
    );
  }
});

test('validateManifest strict release rejects accepted risk outside signoff item', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'DEPLOY-TF-001' ? 'accepted_risk' : 'passed',
  });

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-TF-001 must be passed/,
  );
});

test('validateManifest rejects evidence observed after manifest generation', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: () => 'passed',
  });
  const sourceControlItem = manifest.items.find((item) => item.id === 'SRC-CI-001');
  sourceControlItem.evidence[0].observed_at = '2026-06-26T00:00:00Z';

  assert.throws(
    () => validateManifest(manifest),
    /SRC-CI-001 evidence observed_at must not be after manifest generated_at/,
  );
});

test('validateManifest rejects manifests generated after validation date', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: () => 'pending_external',
  });
  manifest.generated_at = '2026-06-26T00:00:00Z';

  assert.throws(
    () => validateManifest(manifest, { today: '2026-06-25' }),
    /staging evidence generated_at must not be after validation date/,
  );
});

test('validateManifest rejects accepted risk without owner and expiry metadata', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const signoffItem = manifest.items.find((item) => item.id === 'SEC-SIGNOFF-001');
  delete signoffItem.expires_at;

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-SIGNOFF-001 accepted risk expires_at must be YYYY-MM-DD/,
  );
});

test('validateManifest strict release rejects signoff accepted risk for the wrong decision record', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const signoffItem = manifest.items.find((item) => item.id === 'SEC-SIGNOFF-001');
  signoffItem.decision_ref = 'security/dependency_risk_register.md#DRR-999';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-SIGNOFF-001 accepted risk must reference security\/dependency_risk_register.md#DRR-001/,
  );
});

test('validateManifest rejects accepted risk that expires before manifest generation', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const signoffItem = manifest.items.find((item) => item.id === 'SEC-SIGNOFF-001');
  signoffItem.review_due_at = '2026-06-01';
  signoffItem.expires_at = '2026-06-24';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-SIGNOFF-001 accepted risk expires_at must not be before manifest generated_at/,
  );
});

test('validateManifest rejects accepted risk that expires before validation date', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const signoffItem = manifest.items.find((item) => item.id === 'SEC-SIGNOFF-001');
  signoffItem.review_due_at = '2026-07-25';
  signoffItem.expires_at = '2026-08-25';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true, today: '2026-08-26' }),
    /SEC-SIGNOFF-001 accepted risk expires_at must not be before validation date/,
  );
});

test('validateManifest rejects accepted risk with overdue review before expiry', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const signoffItem = manifest.items.find((item) => item.id === 'SEC-SIGNOFF-001');
  signoffItem.review_due_at = '2026-07-25';
  signoffItem.expires_at = '2026-08-25';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true, today: '2026-07-26' }),
    /SEC-SIGNOFF-001 accepted risk review_due_at must not be before validation date/,
  );
});

test('validateManifest rejects invalid validation date input', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true, today: 'not-a-date' }),
    /today must be YYYY-MM-DD/,
  );
});

test('validateManifest rejects accepted risk review dates after expiry', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const signoffItem = manifest.items.find((item) => item.id === 'SEC-SIGNOFF-001');
  signoffItem.review_due_at = '2026-09-01';
  signoffItem.expires_at = '2026-08-25';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-SIGNOFF-001 accepted risk review_due_at must be on or before expires_at/,
  );
});

test('validateManifest strict release rejects generic source-control CI evidence', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const sourceControlItem = manifest.items.find((item) => item.id === 'SRC-CI-001');
  sourceControlItem.evidence = [
    {
      observed_at: '2026-06-25T12:00:00Z',
      command_or_probe: 'manual upload check',
      artifact: 'artifacts/manual-ci-summary.txt',
      result_summary: 'github actions passed',
    },
  ];

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /tools\/ciprobe JSON report/,
  );
});

test('validateManifest strict release rejects CI evidence for a different release candidate', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const sourceControlItem = manifest.items.find((item) => item.id === 'SRC-CI-001');
  sourceControlItem.evidence[0].result_summary = sourceControlItem.evidence[0].result_summary
    .replaceAll('release_candidate=0123456789abcdef0123456789abcdef01234567', 'release_candidate=oldsha');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SRC-CI-001 strict release evidence must include a tools\/ciprobe JSON report/,
  );
});

test('validateManifest strict release rejects CI evidence without release proof markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const sourceControlItem = manifest.items.find((item) => item.id === 'SRC-CI-001');
  sourceControlItem.evidence[0].result_summary = sourceControlItem.evidence[0].result_summary
    .replace('local_gate_markers_included=true, ', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SRC-CI-001 strict release evidence must include a tools\/ciprobe JSON report/,
  );
});

test('validateManifest strict release rejects CI evidence recorded from a local artifact file', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const sourceControlItem = manifest.items.find((item) => item.id === 'SRC-CI-001');
  sourceControlItem.evidence[0].command_or_probe = 'go run ./tools/ciprobe -run-artifact-file artifacts/ci-release-evidence.txt';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SRC-CI-001 strict release evidence must include a tools\/ciprobe JSON report/,
  );
});

test('validateManifest strict release rejects generic probe-backed production evidence', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const tenantItem = manifest.items.find((item) => item.id === 'DATA-RLS-001');
  tenantItem.evidence = [
    {
      observed_at: '2026-06-25T12:00:00Z',
      command_or_probe: 'manual staging smoke',
      artifact: 'artifacts/data-rls-manual.json',
      result_summary: 'same tenant passed and cross tenant denied',
    },
  ];

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-RLS-001 strict release evidence must include a tools\/tenantprobe JSON report/,
  );
});

test('validateManifest strict release rejects local probe report artifacts', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const tenantItem = manifest.items.find((item) => item.id === 'DATA-RLS-001');
  tenantItem.evidence[0].artifact = 'artifacts/tenantprobe.json';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-RLS-001 strict release evidence must include a tools\/tenantprobe JSON report/,
  );
});

test('validateManifest strict release rejects private-network probe report artifacts', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const tenantItem = manifest.items.find((item) => item.id === 'DATA-RLS-001');
  tenantItem.evidence[0].artifact = 'https://10.0.0.12/tenantprobe.json';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-RLS-001 strict release evidence must include a tools\/tenantprobe JSON report/,
  );
});

test('validateManifest strict release rejects unspecified probe report artifacts', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const tenantItem = manifest.items.find((item) => item.id === 'DATA-RLS-001');
  tenantItem.evidence[0].artifact = 'https://0.0.0.0/tenantprobe.json';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-RLS-001 strict release evidence must include a tools\/tenantprobe JSON report/,
  );
});

test('validateManifest strict release rejects private IPv6 probe report artifacts', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const tenantItem = manifest.items.find((item) => item.id === 'DATA-RLS-001');
  tenantItem.evidence[0].artifact = 'https://[fd00::12]/tenantprobe.json';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-RLS-001 strict release evidence must include a tools\/tenantprobe JSON report/,
  );
});

test('validateManifest strict release rejects IPv4-mapped private IPv6 probe report artifacts', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const tenantItem = manifest.items.find((item) => item.id === 'DATA-RLS-001');
  tenantItem.evidence[0].artifact = 'https://[::ffff:10.0.0.12]/tenantprobe.json';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-RLS-001 strict release evidence must include a tools\/tenantprobe JSON report/,
  );
});

test('validateManifest strict release rejects reserved placeholder artifact hosts', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const tenantItem = manifest.items.find((item) => item.id === 'DATA-RLS-001');
  tenantItem.evidence[0].artifact = 'https://example.com/tenantprobe.json';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-RLS-001 strict release evidence must include a tools\/tenantprobe JSON report/,
  );
});

test('validateManifest strict release rejects mock or local-only probe report evidence', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const tenantItem = manifest.items.find((item) => item.id === 'DATA-RLS-001');
  tenantItem.evidence[0].result_summary = 'DATA-RLS-001 passed from mock local-only staging rehearsal';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-RLS-001 strict release evidence must include a tools\/tenantprobe JSON report/,
  );
});

test('validateManifest strict release rejects admitted private-network probe report evidence', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const tenantItem = manifest.items.find((item) => item.id === 'DATA-RLS-001');
  tenantItem.evidence[0].result_summary = `${tenantItem.evidence[0].result_summary} private-network link-local unspecified ipv4-mapped rehearsal`;

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-RLS-001 strict release evidence must include a tools\/tenantprobe JSON report/,
  );
});

test('validateManifest strict release rejects tenant evidence without API and DB RLS markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-RLS-001');
  item.evidence[0].result_summary = 'DATA-RLS-001 passed with tenantprobe report';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-RLS-001 strict release evidence must include a tools\/tenantprobe JSON report/,
  );
});

test('validateManifest strict release rejects tenant evidence without API write-denial markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-RLS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('blocked-journal-tenant-override-write-denied cross-tenant journal write denied tenant override rejected', 'blocked-journal-tenant-override-write-denied cross-tenant journal write denied')
    .replace('blocked-room-tenant-override-write-denied cross-tenant room write denied tenant override rejected', 'blocked-room-tenant-override-write-denied cross-tenant room write denied');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-RLS-001 strict release evidence must include a tools\/tenantprobe JSON report/,
  );
});

test('validateManifest strict release rejects tenant journal write proof borrowed from DB segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-RLS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'owner-create-encrypted-journal same-tenant journal write accepted encrypted journal created plaintext not returned plaintext-shaped journal payload denied malformed encrypted envelope rejected, journal_id=entry-1',
      'owner-create-encrypted-journal',
    )
    .replace(
      'database-rls-context-proof staging artifact',
      'database-rls-context-proof same-tenant journal write accepted encrypted journal created plaintext not returned plaintext-shaped journal payload denied malformed encrypted envelope rejected, journal_id=entry-1 staging artifact',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-RLS-001 strict release evidence must include tenant markers on owner-create-encrypted-journal/,
  );
});

test('validateManifest strict release rejects tenant room-state denial proof borrowed from same-tenant segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-RLS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'owner-room-state same-tenant room state visible created room state returned, room_id=room-1',
      'owner-room-state same-tenant room state visible created room state returned, room_id=room-1 cross-tenant room state denied created room state hidden, room_id=room-1',
    )
    .replace(
      'blocked-room-state-denied cross-tenant room state denied created room state hidden, room_id=room-1',
      'blocked-room-state-denied',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-RLS-001 strict release evidence must include tenant markers on blocked-room-state-denied/,
  );
});

test('validateManifest strict release rejects tenant DB proof borrowed from API segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-RLS-001');
  const dbMarkers = "staging artifact current_user=scriptureforge_app non-superuser superuser=false bypassrls=false app.current_org_id app.current_org_id=11111111-1111-4111-8111-111111111111 current_setting('app.current_org_id') blocked_org_id=22222222-2222-4222-8222-222222222222 row_security=on FORCE ROW LEVEL SECURITY rls_tables_verified=9 rls_forced_tables=9 rls_policy_scope=app.current_org_id organizations users scripture_texts refresh_tokens journal_entries live_rooms room_participants ai_request_logs citation_trails same-tenant read visible cross-tenant read hidden cross-tenant write denied auth_refresh_session_rls=true auth_mfa_rls=true workspace_switch_tenant_match=true privileged_mfa_enrollment_rls=true ai_audit_rls=true generated_curriculum_audit_rls=true distinct_db_rls_artifact=true";
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'owner-create-encrypted-journal same-tenant journal write accepted encrypted journal created plaintext not returned plaintext-shaped journal payload denied malformed encrypted envelope rejected, journal_id=entry-1',
      `owner-create-encrypted-journal same-tenant journal write accepted encrypted journal created plaintext not returned plaintext-shaped journal payload denied malformed encrypted envelope rejected, journal_id=entry-1 ${dbMarkers}`,
    )
    .replace(
      `database-rls-context-proof ${dbMarkers}`,
      'database-rls-context-proof',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-RLS-001 strict release evidence must include tenant markers on database-rls-context-proof/,
  );
});

test('validateManifest strict release rejects tenant DB proof without tenant-pair binding markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-RLS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('app.current_org_id=11111111-1111-4111-8111-111111111111 ', '')
    .replace('blocked_org_id=22222222-2222-4222-8222-222222222222 ', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-RLS-001 strict release evidence must include tenant markers on database-rls-context-proof/,
  );
});

test('validateManifest strict release rejects tenant DB proof with non-UUID tenant-pair markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-RLS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('app.current_org_id=11111111-1111-4111-8111-111111111111', 'app.current_org_id=owner-org')
    .replace('blocked_org_id=22222222-2222-4222-8222-222222222222', 'blocked_org_id=blocked-org');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-RLS-001 database-rls-context-proof must include UUID app\.current_org_id=<id>/,
  );
});

test('validateManifest strict release rejects tenant evidence with mismatched journal IDs', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-RLS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('blocked-read-created-journal cross-tenant journal read denied created journal hidden, journal_id=entry-1', 'blocked-read-created-journal cross-tenant journal read denied created journal hidden, journal_id=entry-2');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-RLS-001 strict release journal_id values must match across created journal read\/list\/blocked segments/,
  );
});

test('validateManifest strict release rejects tenant evidence with mismatched room IDs', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-RLS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('blocked-room-state-denied cross-tenant room state denied created room state hidden, room_id=room-1', 'blocked-room-state-denied cross-tenant room state denied created room state hidden, room_id=room-2');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-RLS-001 strict release room_id values must match across created room list\/state\/blocked segments/,
  );
});

test('validateManifest strict release rejects tenant DB proof without bypassrls disabled marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-RLS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary.replace('bypassrls=false ', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-RLS-001 strict release evidence must include tenant markers on database-rls-context-proof/,
  );
});

test('validateManifest strict release rejects tenant DB proof without distinct artifact marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-RLS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary.replace('distinct_db_rls_artifact=true ', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-RLS-001 strict release evidence must include a tools\/tenantprobe JSON report/,
  );
});

test('validateManifest strict release rejects Terraform deployment evidence without remote state and release markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-TF-001');
  item.evidence[0].result_summary = 'DEPLOY-TF-001 passed with deploymentprobe report';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-TF-001 strict release evidence must include a tools\/deploymentprobe JSON report/,
  );
});

test('validateManifest strict release rejects Terraform approval evidence without change ticket ID', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-TF-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary.replace('change_ticket=PLATFORM-123 ', 'change_ticket= ');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-TF-001 strict release approval evidence must include change_ticket=<ticket-id>/,
  );
});

test('validateManifest strict release rejects Terraform apply evidence without distinct artifact marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-TF-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary.replace(' distinct_terraform_artifacts=true', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-TF-001 strict release evidence must include a tools\/deploymentprobe JSON report/,
  );
});

test('validateManifest strict release rejects Terraform apply evidence without zero-destroy proof', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-TF-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary.replace(
    'terraform-staging-apply-or-approval staging artifact deployment approval approved DEPLOY-TF-001 change_ticket=PLATFORM-123 release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123 distinct_terraform_artifacts=true',
    'terraform-staging-apply-or-approval staging artifact Apply complete Resources: release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123 distinct_terraform_artifacts=true',
  );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-TF-001 strict release evidence must include apply or approval markers on terraform-staging-apply-or-approval/,
  );
});

test('validateManifest strict release rejects Terraform backend proof borrowed from plan segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-TF-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'terraform-remote-backend-init staging artifact terraform s3 backend bucket key encrypt=true dynamodb_table successfully initialized',
      'terraform-remote-backend-init',
    )
    .replace(
      'terraform-staging-plan staging artifact Terraform Plan:',
      'terraform-staging-plan terraform s3 backend bucket key encrypt=true dynamodb_table successfully initialized staging artifact Terraform Plan:',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-TF-001 strict release evidence must include Terraform markers on terraform-remote-backend-init/,
  );
});

test('validateManifest strict release rejects Terraform init and plan segments without release binding', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-TF-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'terraform-remote-backend-init staging artifact terraform s3 backend bucket key encrypt=true dynamodb_table successfully initialized release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123',
      'terraform-remote-backend-init staging artifact terraform s3 backend bucket key encrypt=true dynamodb_table successfully initialized',
    )
    .replace(
      'terraform-staging-plan staging artifact Terraform Plan: aws_eks_cluster aws_eks_node_group aws_rds_cluster aws_elasticache_replication_group aws_ecr_repository kubernetes_deployment kubernetes_ingress_v1 kubernetes_horizontal_pod_autoscaler_v2 kubernetes_pod_disruption_budget_v1 kubernetes_manifest aws_iam_role release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123',
      'terraform-staging-plan staging artifact Terraform Plan: aws_eks_cluster aws_eks_node_group aws_rds_cluster aws_elasticache_replication_group aws_ecr_repository kubernetes_deployment kubernetes_ingress_v1 kubernetes_horizontal_pod_autoscaler_v2 kubernetes_pod_disruption_budget_v1 kubernetes_manifest aws_iam_role',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-TF-001 strict release evidence must include Terraform markers on terraform-remote-backend-init/,
  );
});

test('validateManifest strict release rejects Terraform deployment segments without load run binding', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-TF-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'terraform-remote-backend-init staging artifact terraform s3 backend bucket key encrypt=true dynamodb_table successfully initialized release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123',
      'terraform-remote-backend-init staging artifact terraform s3 backend bucket key encrypt=true dynamodb_table successfully initialized release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-TF-001 strict release evidence must include Terraform markers on terraform-remote-backend-init/,
  );
});

test('validateManifest strict release rejects Terraform plan proof borrowed from backend segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-TF-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'terraform-remote-backend-init staging artifact terraform',
      'terraform-remote-backend-init Terraform Plan: aws_eks_cluster aws_eks_node_group aws_rds_cluster aws_elasticache_replication_group aws_ecr_repository kubernetes_deployment kubernetes_ingress_v1 kubernetes_horizontal_pod_autoscaler_v2 kubernetes_pod_disruption_budget_v1 kubernetes_manifest aws_iam_role release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123 staging artifact terraform',
    )
    .replace(
      'terraform-staging-plan staging artifact Terraform Plan: aws_eks_cluster aws_eks_node_group aws_rds_cluster aws_elasticache_replication_group aws_ecr_repository kubernetes_deployment kubernetes_ingress_v1 kubernetes_horizontal_pod_autoscaler_v2 kubernetes_pod_disruption_budget_v1 kubernetes_manifest aws_iam_role release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123',
      'terraform-staging-plan',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-TF-001 strict release evidence must include Terraform markers on terraform-staging-plan/,
  );
});

test('validateManifest strict release rejects Terraform apply proof borrowed from plan segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-TF-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'terraform-staging-plan staging artifact Terraform',
      'terraform-staging-plan deployment approval approved DEPLOY-TF-001 change_ticket=PLATFORM-123 release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123 distinct_terraform_artifacts=true staging artifact Terraform',
    )
    .replace(
      'terraform-staging-apply-or-approval staging artifact deployment approval approved DEPLOY-TF-001 change_ticket=PLATFORM-123 release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123 distinct_terraform_artifacts=true',
      'terraform-staging-apply-or-approval',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-TF-001 strict release evidence must include apply or approval markers on terraform-staging-apply-or-approval/,
  );
});

test('validateManifest strict release rejects Terraform evidence with admitted failure marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-TF-001');
  item.evidence[0].result_summary += '; terraform plan failed';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-TF-001 strict release evidence must include a tools\/deploymentprobe JSON report/,
  );
});

test('validateManifest strict release rejects Kubernetes deployment evidence without workload safety markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-K8S-001');
  item.evidence[0].result_summary = 'DEPLOY-K8S-001 passed with deploymentprobe report';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-K8S-001 strict release evidence must include a tools\/deploymentprobe JSON report/,
  );
});

test('validateManifest strict release rejects Kubernetes workload proof borrowed from rollout segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-K8S-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'kubernetes-rollout-status staging artifact namespace staging deployment',
      'kubernetes-rollout-status service ingress hpa pdb targets minavailable readinessProbe livenessProbe rollingUpdate maxUnavailable=0 minReplicas maxReplicas tls SecretProviderClass image sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123 staging artifact namespace staging deployment',
    )
    .replace(
      'kubernetes-workload-resources staging artifact namespace staging deployment service ingress hpa pdb ready available targets minavailable readinessProbe livenessProbe rollingUpdate maxUnavailable=0 minReplicas maxReplicas tls SecretProviderClass image scriptureforge-api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa scriptureforge-web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb scriptureforge-rust-engine@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123 scriptureforge-api scriptureforge-web scriptureforge-rust-engine distinct_kubernetes_artifacts=true',
      'kubernetes-workload-resources',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-K8S-001 strict release evidence must include Kubernetes markers on kubernetes-workload-resources/,
  );
});

test('validateManifest strict release rejects Kubernetes evidence with admitted rollout failure marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-K8S-001');
  item.evidence[0].result_summary += '; rollout failed';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-K8S-001 strict release evidence must include a tools\/deploymentprobe JSON report/,
  );
});

test('validateManifest strict release rejects Kubernetes rollout without release linkage markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-K8S-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      ' successfully rolled out ready available release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123;',
      ' successfully rolled out ready available;',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-K8S-001 strict release evidence must include Kubernetes markers on kubernetes-rollout-status/,
  );
});

test('validateManifest strict release rejects Kubernetes rollout without load run binding', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-K8S-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      ' successfully rolled out ready available release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123;',
      ' successfully rolled out ready available release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567;',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-K8S-001 strict release evidence must include Kubernetes markers on kubernetes-rollout-status/,
  );
});

test('validateManifest strict release rejects Kubernetes evidence without distinct artifact marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-K8S-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' distinct_kubernetes_artifacts=true', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-K8S-001 strict release evidence must include Kubernetes markers on kubernetes-workload-resources/,
  );
});

test('validateManifest strict release rejects Kubernetes deployment evidence without image digest markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-K8S-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary.replaceAll(/@sha256:[0-9a-f]{64}/g, '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-K8S-001 strict release evidence must include a tools\/deploymentprobe JSON report/,
  );
});

test('validateManifest strict release rejects Kubernetes deployment evidence with fewer than three image digests', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-K8S-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('scriptureforge-web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ', '')
    .replace('scriptureforge-rust-engine@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc ', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-K8S-001 strict release Kubernetes workload resources must include at least 3 immutable image digests, found 1/,
  );
});

test('validateManifest strict release rejects Kubernetes deployment evidence with unbound image digests', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-K8S-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('scriptureforge-api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ', 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ')
    .replace('scriptureforge-web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ', 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ')
    .replace('scriptureforge-rust-engine@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc ', 'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc ');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-K8S-001 strict release Kubernetes workload resources must include immutable image digest bound to scriptureforge-api/,
  );
});

test('validateManifest strict release rejects deployment evidence without exact manifest release candidate', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const terraform = manifest.items.find((candidate) => candidate.id === 'DEPLOY-TF-001');
  terraform.evidence[0].result_summary = terraform.evidence[0].result_summary
    .replaceAll('release_candidate=0123456789abcdef0123456789abcdef01234567', 'release_candidate');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-TF-001 strict release evidence must include a tools\/deploymentprobe JSON report/,
  );
});

test('validateManifest strict release rejects TLS evidence without health TLS and redirect markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-TLS-001');
  item.evidence[0].result_summary = 'DEPLOY-TLS-001 passed with stagingprobe report';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-TLS-001 strict release evidence must include a tools\/stagingprobe JSON report/,
  );
});

test('validateManifest strict release rejects TLS evidence for a different release candidate', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-TLS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replaceAll('release_candidate=0123456789abcdef0123456789abcdef01234567', 'release_candidate=oldsha')
    .replaceAll('service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123', 'service_version=scriptureforge-api:oldsha');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-TLS-001 strict release evidence must include a tools\/stagingprobe JSON report/,
  );
});

test('validateManifest strict release rejects API TLS proof borrowed from web TLS segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-TLS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'web-tls TLS certificate cert_not_after cert_hostname=app.staging.scriptureforge.ai cert_issuer=Amazon_RSA_2048_M02',
      'web-tls TLS certificate cert_not_after cert_hostname=app.staging.scriptureforge.ai cert_issuer=Amazon_RSA_2048_M02 api-tls certificate cert_not_after',
    )
    .replace(
      'api-tls TLS certificate cert_not_after cert_hostname=api.staging.scriptureforge.ai cert_issuer=Amazon_RSA_2048_M02',
      'api-tls',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-TLS-001 strict release evidence must include TLS\/web markers on api-tls/,
  );
});

test('validateManifest strict release rejects TLS evidence without concrete certificate issuer', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-TLS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('api-tls TLS certificate cert_not_after cert_hostname=api.staging.scriptureforge.ai cert_issuer=Amazon_RSA_2048_M02', 'api-tls TLS certificate cert_not_after cert_hostname=api.staging.scriptureforge.ai cert_issuer=');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-TLS-001 api-tls must include concrete cert_issuer=<issuer>/,
  );
});

test('validateManifest strict release rejects web redirect proof borrowed from API redirect segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DEPLOY-TLS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'api-http-redirect HTTP HTTPS redirect',
      'api-http-redirect HTTP HTTPS redirect web-http-redirect',
    )
    .replace(
      'web-http-redirect HTTP HTTPS redirect',
      'web-http-redirect',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DEPLOY-TLS-001 strict release evidence must include TLS\/web markers on web-http-redirect/,
  );
});

test('validateManifest strict release rejects web smoke evidence without browser flow markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-WEB-001');
  item.evidence[0].result_summary = 'CLIENT-WEB-001 passed with stagingprobe report';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-WEB-001 strict release evidence must include a tools\/stagingprobe JSON report/,
  );
});

test('validateManifest strict release rejects web journal proof borrowed from auth segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-WEB-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'web-auth-browser-smoke staging artifact login register authenticated https:// user_id=user-staging organization_id=org-staging distinct_web_artifacts=true',
      'web-auth-browser-smoke staging artifact login register authenticated https:// user_id=user-staging organization_id=org-staging journal_id=journal-staging distinct_web_artifacts=true journal encrypted save load plaintext absent associated data wrong associated data rejected',
    )
    .replace(
      'web-journal-browser-smoke staging artifact journal encrypted save load plaintext absent associated data wrong associated data rejected user_id=user-staging organization_id=org-staging journal_id=journal-staging distinct_web_artifacts=true',
      'web-journal-browser-smoke staging artifact',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-WEB-001 strict release evidence must include web client markers on web-journal-browser-smoke/,
  );
});

test('validateManifest strict release rejects web journal proof without associated-data markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-WEB-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' associated data', '')
    .replace(' wrong associated data rejected', '')
    .replace(
      'web-auth-browser-smoke staging artifact login register authenticated https:// user_id=user-staging organization_id=org-staging distinct_web_artifacts=true',
      'web-auth-browser-smoke staging artifact login register authenticated https:// user_id=user-staging organization_id=org-staging distinct_web_artifacts=true associated data wrong associated data rejected',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-WEB-001 strict release evidence must include web client markers on web-journal-browser-smoke/,
  );
});

test('validateManifest strict release rejects web room proof borrowed from journal segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-WEB-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'web-journal-browser-smoke staging artifact journal encrypted save load plaintext absent associated data wrong associated data rejected user_id=user-staging organization_id=org-staging journal_id=journal-staging distinct_web_artifacts=true',
      'web-journal-browser-smoke staging artifact journal encrypted save load plaintext absent associated data wrong associated data rejected user_id=user-staging organization_id=org-staging journal_id=journal-staging room_id=room-staging distinct_web_artifacts=true room create select WebSocket connected',
    )
    .replace(
      'web-room-browser-smoke staging artifact room create select WebSocket connected user_id=user-staging organization_id=org-staging room_id=room-staging distinct_web_artifacts=true',
      'web-room-browser-smoke staging artifact',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-WEB-001 strict release evidence must include web client markers on web-room-browser-smoke/,
  );
});

test('validateManifest strict release rejects web evidence without distinct browser smoke artifacts marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-WEB-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' distinct_web_artifacts=true', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-WEB-001 strict release evidence must include web client markers on web-auth-browser-smoke/,
  );
});

test('validateManifest strict release rejects web evidence without concrete browser smoke IDs', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-WEB-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('journal_id=journal-staging', 'journal_id=');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-WEB-001 strict release journal smoke must include concrete journal_id/,
  );
});

test('validateManifest strict release rejects web smoke user mismatch', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-WEB-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('web-room-browser-smoke staging artifact room create select WebSocket connected user_id=user-staging', 'web-room-browser-smoke staging artifact room create select WebSocket connected user_id=user-other');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-WEB-001 strict release room smoke user_id must match auth smoke/,
  );
});

test('validateManifest strict release rejects web smoke evidence with hardcoded production endpoints', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-WEB-001');
  item.evidence[0].result_summary += '; web-auth-browser-smoke NEXT_PUBLIC_API_BASE_URL=https://api.scriptureforge.com; web-room-browser-smoke NEXT_PUBLIC_WS_BASE_URL=wss://api.scriptureforge.com';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-WEB-001 strict release evidence must include a tools\/stagingprobe JSON report/,
  );
});

test('validateManifest strict release rejects tenant DB proof without RLS table count markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-RLS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('rls_tables_verified=9 ', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-RLS-001 strict release evidence must include tenant markers on database-rls-context-proof/,
  );
});

test('validateManifest strict release rejects Zoom evidence without webhook and mapping markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-ZOOM-001');
  item.evidence[0].result_summary = 'EXT-ZOOM-001 passed with zoomprobe report';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-ZOOM-001 strict release evidence must include a tools\/zoomprobe JSON report/,
  );
});

test('validateManifest strict release rejects Zoom OAuth proof without staging artifact provenance', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-ZOOM-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('zoom-oauth-readiness staging artifact oauth account_credentials', 'zoom-oauth-readiness oauth account_credentials');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-ZOOM-001 strict release evidence must include Zoom markers on zoom-oauth-readiness/,
  );
});

test('validateManifest strict release rejects Zoom webhook proof without concrete signature values', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-ZOOM-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'x-zm-signature=v0=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      'x-zm-signature=not-a-v0-signature',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-ZOOM-001 zoom-webhook-signature-delivery must include concrete x-zm-signature=<v0 signature>/,
  );
});

test('validateManifest strict release rejects Zoom URL validation proof without concrete callback tokens', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-ZOOM-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('plain_token=zoom-plain-123', 'plainToken')
    .replace('encrypted_token=zoom-encrypted-456', 'encryptedToken')
    .replace('validation_response=200', '200');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-ZOOM-001 strict release evidence must include a tools\/zoomprobe JSON report/,
  );
});

test('validateManifest strict release accepts Zoom meeting offline fallback proof', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-ZOOM-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('zoom-meeting-create-or-fallback staging artifact meeting join_url zoom.us', 'zoom-meeting-create-or-fallback staging artifact offline://in-person fallback Zoom');

  assert.doesNotThrow(() => validateManifest(manifest, { strictRelease: true }));
});

test('validateManifest strict release rejects Zoom evidence with disabled signature verification marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-ZOOM-001');
  item.evidence[0].result_summary = `${item.evidence[0].result_summary}; zoom-webhook-signature-delivery signature verification disabled`;

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-ZOOM-001 strict release evidence must include a tools\/zoomprobe JSON report/,
  );
});

test('validateManifest strict release rejects Zoom meeting fallback proof borrowed from timeout probe', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-ZOOM-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('zoom-meeting-create-or-fallback staging artifact meeting join_url zoom.us', 'zoom-meeting-create-or-fallback staging artifact artifact fetched');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-ZOOM-001 strict release evidence must include meeting-create or offline-fallback markers on zoom-meeting-create-or-fallback/,
  );
});

test('validateManifest strict release rejects Zoom duplicate proof without structured delivery ID on duplicate segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-ZOOM-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('zoom-duplicate-webhook-idempotency staging artifact duplicate x-zm-trackingid=zm-track-123 delivery_id=zm-delivery-123 delivery id', 'zoom-duplicate-webhook-idempotency staging artifact duplicate x-zm-trackingid=zm-track-123 delivery id')
    .replace('zoom-meeting-room-mapping staging artifact meeting_external_id=zoom-123', 'zoom-meeting-room-mapping delivery_id=zm-delivery-123 staging artifact meeting_external_id=zoom-123');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-ZOOM-001 strict release evidence must include Zoom markers on zoom-duplicate-webhook-idempotency/,
  );
});

test('validateManifest strict release rejects Zoom duplicate proof without tracking header marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-ZOOM-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('zoom-duplicate-webhook-idempotency staging artifact duplicate x-zm-trackingid=zm-track-123 delivery_id=zm-delivery-123', 'zoom-duplicate-webhook-idempotency staging artifact duplicate delivery_id=zm-delivery-123')
    .replace('zoom-meeting-room-mapping staging artifact meeting_external_id=zoom-123', 'zoom-meeting-room-mapping x-zm-trackingid=zm-track-123 staging artifact meeting_external_id=zoom-123');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-ZOOM-001 strict release evidence must include Zoom markers on zoom-duplicate-webhook-idempotency/,
  );
});

test('validateManifest strict release rejects Zoom duplicate proof without concrete tracking ID', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-ZOOM-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('zoom-duplicate-webhook-idempotency staging artifact duplicate x-zm-trackingid=zm-track-123 delivery_id=zm-delivery-123', 'zoom-duplicate-webhook-idempotency staging artifact duplicate x-zm-trackingid= delivery_id=zm-delivery-123');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-ZOOM-001 zoom-duplicate-webhook-idempotency must include concrete x-zm-trackingid=<id>/,
  );
});

test('validateManifest strict release rejects Zoom duplicate proof without structured side-effect markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-ZOOM-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' single_state_mutation=true no_duplicate_side_effects=true', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-ZOOM-001 strict release evidence must include Zoom markers on zoom-duplicate-webhook-idempotency/,
  );
});

test('validateManifest strict release rejects Zoom evidence without distinct artifact marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-ZOOM-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' distinct_zoom_artifacts=true', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-ZOOM-001 strict release evidence must include a tools\/zoomprobe JSON report/,
  );
});

test('validateManifest strict release rejects Zoom room mapping without concrete IDs', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-ZOOM-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('meeting_external_id=zoom-123', 'meeting_external_id')
    .replace('internal_room_id=room-abc', 'internal_room_id');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-ZOOM-001 strict release evidence must include a tools\/zoomprobe JSON report/,
  );
});

test('validateManifest strict release rejects Zoom evidence for a different release candidate', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-ZOOM-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replaceAll('release_candidate=0123456789abcdef0123456789abcdef01234567', 'release_candidate=oldsha')
    .replaceAll('service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123', 'service_version=scriptureforge-api:oldsha');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-ZOOM-001 strict release evidence must include a tools\/zoomprobe JSON report/,
  );
});

test('validateManifest strict release rejects Zoom evidence without segment load run marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-ZOOM-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('zoom-oauth-readiness staging artifact oauth account_credentials status ok release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123', 'zoom-oauth-readiness staging artifact oauth account_credentials status ok release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-ZOOM-001 strict release evidence must include Zoom markers on zoom-oauth-readiness/,
  );
});

test('validateManifest strict release rejects AI evidence without citation and audit markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-AI-001');
  item.evidence[0].result_summary = 'EXT-AI-001 passed with aiprobe report';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-AI-001 strict release evidence must include a tools\/aiprobe JSON report/,
  );
});

test('validateManifest strict release rejects AI citation proof borrowed from audit segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-AI-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('ai-citation-verification staging artifact no-citation rejected hallucinated citation rejected verified citation accepted citation_trails citation_id=cite-123', 'ai-citation-verification staging artifact artifact fetched')
    .replace('ai-audit-persistence staging artifact ai_request_logs', 'ai-audit-persistence staging artifact no-citation rejected hallucinated citation rejected verified citation accepted citation_id=cite-123 ai_request_logs');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-AI-001 strict release evidence must include citation rejection\/acceptance markers on ai-citation-verification/,
  );
});

test('validateManifest strict release rejects AI provider proof without staging artifact provenance', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-AI-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('ai-provider-config staging artifact AI_PROVIDER', 'ai-provider-config AI_PROVIDER');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-AI-001 strict release evidence must include AI markers on ai-provider-config/,
  );
});

test('validateManifest strict release rejects AI generation proof borrowed from provider segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-AI-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'ai-provider-config staging artifact AI_PROVIDER',
      'ai-provider-config staging artifact /api/v1/ai/generate/study authenticated JWT claims organization_id=org-staging user_id=user-staging request_id=req-123 200 generated_curriculum [Genesis 1:1] AI_PROVIDER',
    )
    .replace(
      'ai-generation-route staging artifact /api/v1/ai/generate/study authenticated JWT claims organization_id=org-staging user_id=user-staging request_id=req-123 200 generated_curriculum [Genesis 1:1]',
      'ai-generation-route staging artifact organization_id=org-staging user_id=user-staging request_id=req-123 artifact fetched',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-AI-001 strict release evidence must include AI markers on ai-generation-route/,
  );
});

test('validateManifest strict release rejects AI timeout proof borrowed from generation segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-AI-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'ai-generation-route staging artifact /api/v1/ai/generate/study',
      'ai-generation-route staging artifact provider timeout degradation retry exhausted 503 fail closed AI_ORCHESTRATION_ENGINE_FAULT /api/v1/ai/generate/study',
    )
    .replace(
      'ai-timeout-degradation staging artifact provider timeout degradation retry exhausted 503 fail closed AI_ORCHESTRATION_ENGINE_FAULT',
      'ai-timeout-degradation staging artifact artifact fetched',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-AI-001 strict release evidence must include AI markers on ai-timeout-degradation/,
  );
});

test('validateManifest strict release rejects AI audit proof borrowed from citation segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-AI-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('ai-audit-persistence staging artifact ai_request_logs citation_trails organization_id=org-staging user_id=user-staging request_id=req-123 citation_id=cite-123 succeeded failed verified tenant rls cross-tenant hidden', 'ai-audit-persistence staging artifact artifact fetched')
    .replace('ai-citation-verification staging artifact no-citation rejected', 'ai-citation-verification staging artifact ai_request_logs organization_id=org-staging user_id=user-staging request_id=req-123 citation_id=cite-123 succeeded failed tenant rls cross-tenant hidden no-citation rejected');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-AI-001 strict release evidence must include tenant-RLS audit markers on ai-audit-persistence/,
  );
});

test('validateManifest strict release rejects AI audit citation ID mismatch', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-AI-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('ai-audit-persistence staging artifact ai_request_logs citation_trails organization_id=org-staging user_id=user-staging request_id=req-123 citation_id=cite-123', 'ai-audit-persistence staging artifact ai_request_logs citation_trails organization_id=org-staging user_id=user-staging request_id=req-123 citation_id=cite-other');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-AI-001 strict release ai-audit-persistence citation_id must match ai-citation-verification citation_id/,
  );
});

test('validateManifest strict release rejects AI audit request ID mismatch', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-AI-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('ai-audit-persistence staging artifact ai_request_logs citation_trails organization_id=org-staging user_id=user-staging request_id=req-123 citation_id=cite-123', 'ai-audit-persistence staging artifact ai_request_logs citation_trails organization_id=org-staging user_id=user-staging request_id=req-other citation_id=cite-123');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-AI-001 strict release ai-audit-persistence request_id must match ai-generation-route request_id/,
  );
});

test('validateManifest strict release rejects AI audit organization ID mismatch', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-AI-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('ai-audit-persistence staging artifact ai_request_logs citation_trails organization_id=org-staging user_id=user-staging request_id=req-123 citation_id=cite-123', 'ai-audit-persistence staging artifact ai_request_logs citation_trails organization_id=org-other user_id=user-staging request_id=req-123 citation_id=cite-123');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-AI-001 strict release ai-audit-persistence organization_id must match ai-generation-route organization_id/,
  );
});

test('validateManifest strict release rejects AI audit user ID mismatch', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-AI-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('ai-audit-persistence staging artifact ai_request_logs citation_trails organization_id=org-staging user_id=user-staging request_id=req-123 citation_id=cite-123', 'ai-audit-persistence staging artifact ai_request_logs citation_trails organization_id=org-staging user_id=user-other request_id=req-123 citation_id=cite-123');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-AI-001 strict release ai-audit-persistence user_id must match ai-generation-route user_id/,
  );
});

test('validateManifest strict release rejects AI evidence with disabled citation or audit marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-AI-001');
  item.evidence[0].result_summary = `${item.evidence[0].result_summary}; ai-audit-persistence audit logging disabled`;

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-AI-001 strict release evidence must include a tools\/aiprobe JSON report/,
  );
});

test('validateManifest strict release rejects AI evidence without distinct artifact marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-AI-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' distinct_ai_artifacts=true', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-AI-001 strict release evidence must include a tools\/aiprobe JSON report/,
  );
});

test('validateManifest strict release rejects AI evidence for a different release candidate', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-AI-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replaceAll('release_candidate=0123456789abcdef0123456789abcdef01234567', 'release_candidate=oldsha')
    .replaceAll('service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123', 'service_version=scriptureforge-api:oldsha');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-AI-001 strict release evidence must include a tools\/aiprobe JSON report/,
  );
});

test('validateManifest strict release rejects AI evidence without segment load run marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-AI-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('ai-provider-config staging artifact AI_PROVIDER AI_CHAT_MODEL AI_CHAT_ENDPOINT AI_HTTP_TIMEOUT_MS AI_MAX_RETRIES OPENAI_API_KEY redacted configured AI_PROVIDER=openai AI_CHAT_MODEL=gpt-staging AI_CHAT_ENDPOINT=https://api.openai.com/v1/chat/completions AI_HTTP_TIMEOUT_MS=3500 AI_MAX_RETRIES=1 release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123', 'ai-provider-config staging artifact AI_PROVIDER AI_CHAT_MODEL AI_CHAT_ENDPOINT AI_HTTP_TIMEOUT_MS AI_MAX_RETRIES OPENAI_API_KEY redacted configured AI_PROVIDER=openai AI_CHAT_MODEL=gpt-staging AI_CHAT_ENDPOINT=https://api.openai.com/v1/chat/completions AI_HTTP_TIMEOUT_MS=3500 AI_MAX_RETRIES=1 release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /EXT-AI-001 strict release evidence must include AI markers on ai-provider-config/,
  );
});

test('validateManifest strict release rejects OTEL evidence without metrics and trace correlation markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'OBS-OTEL-001');
  item.evidence[0].result_summary = 'OBS-OTEL-001 passed with observabilityprobe report';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /OBS-OTEL-001 strict release evidence must include a tools\/observabilityprobe JSON report/,
  );
});

test('validateManifest strict release rejects OTEL trace proof borrowed from log segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'OBS-OTEL-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('trace-backend-search staging artifact trace_id=11112222333344445555666677778888 scriptureforge-api scriptureforge-rust-engine', 'trace-backend-search staging artifact trace_id=11112222333344445555666677778888 artifact fetched')
    .replace('log-backend-trace-correlation staging artifact trace_id', 'log-backend-trace-correlation staging artifact scriptureforge-api scriptureforge-rust-engine trace_id');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /OBS-OTEL-001 strict release evidence must include API\/Rust trace markers on trace-backend-search/,
  );
});

test('validateManifest strict release rejects OTEL log proof borrowed from trace segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'OBS-OTEL-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('trace-backend-search staging artifact trace_id=11112222333344445555666677778888 scriptureforge-api scriptureforge-rust-engine', 'trace-backend-search staging artifact trace_id=11112222333344445555666677778888 trace_id scriptureforge-api scriptureforge-rust-engine service_version deployment_environment tenant_id=org-staging user_id=user-staging role=admin')
    .replace('log-backend-trace-correlation staging artifact trace_id=11112222333344445555666677778888 trace_id scriptureforge-api scriptureforge-rust-engine route=/api/v1/ai/generate/study method=POST service_version deployment_environment tenant_id=org-staging user_id=user-staging role=admin', 'log-backend-trace-correlation staging artifact trace_id=11112222333344445555666677778888 artifact fetched');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /OBS-OTEL-001 strict release evidence must include tenant-aware log markers on log-backend-trace-correlation/,
  );
});

test('validateManifest strict release rejects OTEL trace and log evidence with different trace IDs', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'OBS-OTEL-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'log-backend-trace-correlation staging artifact trace_id=11112222333344445555666677778888',
      'log-backend-trace-correlation staging artifact trace_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /OBS-OTEL-001 strict release trace\/log segments must reference the same concrete trace ID/,
  );
});

test('validateManifest strict release rejects OTEL trace without route and method markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'OBS-OTEL-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replaceAll(' route=/api/v1/ai/generate/study', '')
    .replaceAll(' method=POST', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /OBS-OTEL-001 strict release evidence must include API\/Rust trace markers on trace-backend-search/,
  );
});

test('validateManifest strict release rejects OTEL evidence without distinct artifact marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'OBS-OTEL-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' distinct_otel_artifacts=true', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /OBS-OTEL-001 strict release evidence must include a tools\/observabilityprobe JSON report/,
  );
});

test('validateManifest strict release rejects OTEL evidence without staging artifact provenance', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'OBS-OTEL-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('api-prometheus-metrics staging artifact scriptureforge_http_requests_total', 'api-prometheus-metrics scriptureforge_http_requests_total');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /OBS-OTEL-001 strict release evidence must include API metric markers on api-prometheus-metrics/,
  );
});

test('validateManifest strict release rejects OTEL evidence for a different release candidate', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'OBS-OTEL-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replaceAll('release_candidate=0123456789abcdef0123456789abcdef01234567', 'release_candidate=oldsha')
    .replaceAll('service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123', 'service_version=scriptureforge-api:oldsha');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /OBS-OTEL-001 strict release evidence must include a tools\/observabilityprobe JSON report/,
  );
});

test('validateManifest strict release rejects OTEL evidence without segment load run marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'OBS-OTEL-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('collector-otlp-config staging artifact receivers otlp 4317 4318 exporters service release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123', 'collector-otlp-config staging artifact receivers otlp 4317 4318 exporters service release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /OBS-OTEL-001 strict release evidence must include staging OTLP markers on collector-otlp-config/,
  );
});

test('validateManifest strict release rejects alert evidence without dashboard alert and retention markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'OBS-ALERT-001');
  item.evidence[0].result_summary = 'OBS-ALERT-001 passed with observabilityprobe report';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /OBS-ALERT-001 strict release evidence must include a tools\/observabilityprobe JSON report/,
  );
});

test('validateManifest strict release rejects alert dashboard proof borrowed from alert segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'OBS-ALERT-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'dashboard-import staging artifact ScriptureForge scriptureforge_http_requests_total scriptureforge_http_request_duration_seconds_sum websocket_active_connections_count room_broadcast ai_inference_duration_seconds scriptureforge_rust_engine_ trace_id release_candidate=',
      'dashboard-import staging artifact release_candidate=',
    )
    .replace(
      'alert-rules-loaded staging artifact ScriptureForgeHighErrorRate',
      'alert-rules-loaded staging artifact ScriptureForge scriptureforge_http_requests_total scriptureforge_http_request_duration_seconds_sum websocket_active_connections_count room_broadcast ai_inference_duration_seconds scriptureforge_rust_engine_ trace_id ScriptureForgeHighErrorRate',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /OBS-ALERT-001 strict release evidence must include dashboard metric markers on dashboard-import/,
  );
});

test('validateManifest strict release rejects alert rules proof borrowed from dashboard segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'OBS-ALERT-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'dashboard-import staging artifact ScriptureForge',
      'dashboard-import staging artifact ScriptureForge ScriptureForgeHighErrorRate ScriptureForgeTrafficAbsent ScriptureForgeAuthFailureSpike ScriptureForgeAbuseLimitSpike ScriptureForgeRouteLatencyElevated ScriptureForgeDependencyFailures ScriptureForgeAIInferenceLatencyElevated ScriptureForgeJournalWriteFailures ScriptureForgeRoomStreamFailures ScriptureForgeRoomBroadcastDrops ScriptureForgeRustEngineFailures scriptureforge_dependency_operations_total',
    )
    .replace(
      'alert-rules-loaded staging artifact ScriptureForgeHighErrorRate ScriptureForgeTrafficAbsent ScriptureForgeAuthFailureSpike ScriptureForgeAbuseLimitSpike ScriptureForgeRouteLatencyElevated ScriptureForgeDependencyFailures ScriptureForgeAIInferenceLatencyElevated ScriptureForgeJournalWriteFailures ScriptureForgeRoomStreamFailures ScriptureForgeRoomBroadcastDrops ScriptureForgeRustEngineFailures scriptureforge_http_requests_total scriptureforge_dependency_operations_total ai_inference_duration_seconds release_candidate=',
      'alert-rules-loaded staging artifact release_candidate=',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /OBS-ALERT-001 strict release evidence must include rule and metric markers on alert-rules-loaded/,
  );
});

test('validateManifest strict release rejects alert delivery proof borrowed from alert rules segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'OBS-ALERT-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'alert-rules-loaded staging artifact ScriptureForgeHighErrorRate',
      'alert-rules-loaded staging artifact success alertname=ScriptureForgeHighErrorRate receiver=staging-release delivery_id=am-delivery-123 delivered test alert alertmanager ScriptureForgeHighErrorRate',
    )
    .replace(
      'alert-delivery-status staging artifact success alertname=ScriptureForgeHighErrorRate receiver=staging-release delivery_id=am-delivery-123 delivered test alert alertmanager release_candidate=',
      'alert-delivery-status staging artifact release_candidate=',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /OBS-ALERT-001 strict release evidence must include delivery markers on alert-delivery-status/,
  );
});

test('validateManifest strict release rejects alert delivery contradiction markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'OBS-ALERT-001');
  item.evidence[0].result_summary = `${item.evidence[0].result_summary}; alert-delivery-status alert silenced; not delivered`;

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /OBS-ALERT-001 evidence contains forbidden non-production marker/,
  );
});

test('validateManifest strict release rejects alert retention proof borrowed from dashboard segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'OBS-ALERT-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'dashboard-import staging artifact ScriptureForge',
      'dashboard-import staging artifact retention 30 days trace logs metrics distinct_alert_artifacts=true ScriptureForge',
    )
    .replace(
      'telemetry-retention-policy staging artifact retention 30 days trace logs metrics distinct_alert_artifacts=true release_candidate=',
      'telemetry-retention-policy staging artifact release_candidate=',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /OBS-ALERT-001 strict release evidence must include retention markers on telemetry-retention-policy/,
  );
});

test('validateManifest strict release rejects alert evidence without distinct artifact marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'OBS-ALERT-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' distinct_alert_artifacts=true', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /OBS-ALERT-001 strict release evidence must include a tools\/observabilityprobe JSON report/,
  );
});

test('validateManifest strict release rejects alert evidence for a different release candidate', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'OBS-ALERT-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replaceAll('release_candidate=0123456789abcdef0123456789abcdef01234567', 'release_candidate=oldsha')
    .replaceAll('service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123', 'service_version=scriptureforge-api:oldsha');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /OBS-ALERT-001 strict release evidence must include a tools\/observabilityprobe JSON report/,
  );
});

test('validateManifest strict release rejects alert evidence without segment load run marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'OBS-ALERT-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('dashboard-import staging artifact ScriptureForge scriptureforge_http_requests_total scriptureforge_http_request_duration_seconds_sum websocket_active_connections_count room_broadcast ai_inference_duration_seconds scriptureforge_rust_engine_ trace_id release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123', 'dashboard-import staging artifact ScriptureForge scriptureforge_http_requests_total scriptureforge_http_request_duration_seconds_sum websocket_active_connections_count room_broadcast ai_inference_duration_seconds scriptureforge_rust_engine_ trace_id release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /OBS-ALERT-001 strict release evidence must include dashboard metric markers on dashboard-import/,
  );
});

test('validateManifest strict release rejects Rust evidence without gRPC and metrics markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'RUST-GRPC-001');
  item.evidence[0].result_summary = 'RUST-GRPC-001 passed with rustprobe report';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /RUST-GRPC-001 strict release evidence must include a tools\/rustprobe JSON report/,
  );
});

test('validateManifest strict release rejects Rust health proof borrowed from metrics segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'RUST-GRPC-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'rust-grpc-health staging artifact grpc health scriptureforge.engine.ScriptureEngine SERVING release_candidate=',
      'rust-grpc-health staging artifact release_candidate=',
    )
    .replace(
      'rust-metrics staging artifact scriptureforge_rust_engine_embedding_requests_total',
      'rust-metrics staging artifact grpc health scriptureforge.engine.ScriptureEngine SERVING scriptureforge_rust_engine_embedding_requests_total',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /RUST-GRPC-001 strict release evidence must include Rust markers on rust-grpc-health/,
  );
});

test('validateManifest strict release rejects Rust evidence without staging artifact provenance', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'RUST-GRPC-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary.replace(
    'rust-metrics staging artifact scriptureforge_rust_engine_embedding_requests_total',
    'rust-metrics scriptureforge_rust_engine_embedding_requests_total',
  );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /RUST-GRPC-001 strict release evidence must include Rust markers on rust-metrics/,
  );
});

test('validateManifest strict release rejects Rust metrics proof borrowed from API integration segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'RUST-GRPC-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'rust-metrics staging artifact scriptureforge_rust_engine_embedding_requests_total scriptureforge_rust_engine_embedding_failures_total scriptureforge_rust_engine_vector_search_requests_total scriptureforge_rust_engine_vector_search_failures_total Prometheus metrics rust_metrics_samples_verified=true rust_embedding_requests_positive=true rust_vector_search_requests_positive=true release_candidate=',
      'rust-metrics staging artifact release_candidate=',
    )
    .replace(
      'api-rust-integration-metrics staging artifact Go API',
      'api-rust-integration-metrics staging artifact scriptureforge_rust_engine_embedding_requests_total scriptureforge_rust_engine_embedding_failures_total scriptureforge_rust_engine_vector_search_requests_total scriptureforge_rust_engine_vector_search_failures_total Prometheus metrics rust_metrics_samples_verified=true rust_embedding_requests_positive=true rust_vector_search_requests_positive=true Go API',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /RUST-GRPC-001 strict release evidence must include Rust markers on rust-metrics/,
  );
});

test('validateManifest strict release rejects Rust API integration proof borrowed from health segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'RUST-GRPC-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'rust-grpc-health staging artifact grpc health',
      'rust-grpc-health staging artifact Go API rust_engine vector_search success scriptureforge_dependency_operations_total scriptureforge_dependency_operation_duration_seconds_sum api_rust_metrics_samples_verified=true distinct_metrics_targets=true grpc health',
    )
    .replace(
      'api-rust-integration-metrics staging artifact Go API rust_engine vector_search success scriptureforge_dependency_operations_total scriptureforge_dependency_operation_duration_seconds_sum api_rust_metrics_samples_verified=true distinct_metrics_targets=true release_candidate=',
      'api-rust-integration-metrics staging artifact release_candidate=',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /RUST-GRPC-001 strict release evidence must include Rust markers on api-rust-integration-metrics/,
  );
});

test('validateManifest strict release rejects Rust metrics evidence without positive request proof', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'RUST-GRPC-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' rust_embedding_requests_positive=true', '')
    .replace(' rust_vector_search_requests_positive=true', '')
    + '; api-rust-integration-metrics rust_embedding_requests_positive=true rust_vector_search_requests_positive=true';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /RUST-GRPC-001 strict release evidence must include Rust markers on rust-metrics/,
  );
});

test('validateManifest strict release rejects Rust API integration evidence without distinct metrics target proof', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'RUST-GRPC-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' distinct_metrics_targets=true', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /RUST-GRPC-001 strict release evidence must include a tools\/rustprobe JSON report/,
  );
});

test('validateManifest strict release rejects Rust evidence for a different release candidate', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'RUST-GRPC-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replaceAll('release_candidate=0123456789abcdef0123456789abcdef01234567', 'release_candidate=oldsha')
    .replaceAll('service_version=scriptureforge-rust-engine:0123456789abcdef0123456789abcdef01234567', 'service_version=scriptureforge-rust-engine:oldsha');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /RUST-GRPC-001 strict release evidence must include a tools\/rustprobe JSON report/,
  );
});

test('validateManifest strict release rejects Rust evidence without deployment environment markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'RUST-GRPC-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replaceAll(' deployment_environment=staging', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /RUST-GRPC-001 strict release evidence must include Rust markers on rust-grpc-health/,
  );
});

test('validateManifest strict release rejects mobile evidence without native crypto and staging config markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-MOBILE-001');
  item.evidence[0].result_summary = 'CLIENT-MOBILE-001 passed with mobileprobe report';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-MOBILE-001 strict release evidence must include a tools\/mobileprobe JSON report/,
  );
});

test('validateManifest strict release rejects mobile evidence without staging artifact provenance', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-MOBILE-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('mobile-eas-or-device-run staging artifact eas', 'mobile-eas-or-device-run eas');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-MOBILE-001 strict release evidence must include mobile markers on mobile-eas-or-device-run/,
  );
});

test('validateManifest strict release rejects mobile EAS proof borrowed from crypto segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-MOBILE-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'mobile-native-crypto-smoke staging artifact runJournalCryptoSelfTest react-native-quick-crypto',
      'mobile-native-crypto-smoke staging artifact eas build finished android ios native device installed app release channel staging expo profile staging react-native-quick-crypto',
    )
    .replace(
      'mobile-eas-or-device-run staging artifact eas build finished android ios native device installed app release channel staging expo profile staging',
      'mobile-eas-or-device-run',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-MOBILE-001 strict release evidence must include mobile markers on mobile-eas-or-device-run/,
  );
});

test('validateManifest strict release rejects mobile native crypto proof borrowed from config segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-MOBILE-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'mobile-staging-config staging artifact EXPO_PUBLIC_API_BASE_URL',
      'mobile-staging-config staging artifact runJournalCryptoSelfTest react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true mobile_build_id=mobile-build-123 AES-GCM round-trip unique_iv=true unique IV tamper rejected associated data wrong associated data rejected associated_data_salt_id=journal:self-test:server-derived-salt associated_data_salt_version=1 non-extractable provider-bound key fallback-derived key rejected key disposed disposed handle rejected revoked_key_rejected=true stale raw key rejected passphrase wiped passphrase buffer zeroized salt wiped salt buffer zeroized plaintext cleared plaintext buffer zeroized EXPO_PUBLIC_API_BASE_URL',
    )
    .replace(
      'mobile-native-crypto-smoke staging artifact runJournalCryptoSelfTest react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true mobile_build_id=mobile-build-123 AES-GCM round-trip unique_iv=true unique IV tamper rejected associated data wrong associated data rejected associated_data_salt_id=journal:self-test:server-derived-salt associated_data_salt_version=1 non-extractable provider-bound key fallback-derived key rejected key disposed disposed handle rejected revoked_key_rejected=true stale raw key rejected passphrase wiped passphrase buffer zeroized salt wiped salt buffer zeroized plaintext cleared plaintext buffer zeroized',
      'mobile-native-crypto-smoke',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-MOBILE-001 strict release evidence must include mobile markers on mobile-native-crypto-smoke/,
  );
});

test('validateManifest strict release rejects mobile crypto proof without zeroized buffer markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-MOBILE-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' passphrase buffer zeroized', '')
    .replace(' salt buffer zeroized', '')
    .replace(' plaintext buffer zeroized', '')
    .replace(
      'mobile-staging-config staging artifact EXPO_PUBLIC_API_BASE_URL',
      'mobile-staging-config staging artifact passphrase buffer zeroized salt buffer zeroized plaintext buffer zeroized EXPO_PUBLIC_API_BASE_URL',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-MOBILE-001 strict release evidence must include mobile markers on mobile-native-crypto-smoke/,
  );
});

test('validateManifest strict release rejects mobile crypto proof without associated-data markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-MOBILE-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' associated data', '')
    .replace(' wrong associated data rejected', '')
    .replace(
      'mobile-staging-config staging artifact EXPO_PUBLIC_API_BASE_URL',
      'mobile-staging-config staging artifact associated data wrong associated data rejected EXPO_PUBLIC_API_BASE_URL',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-MOBILE-001 strict release evidence must include mobile markers on mobile-native-crypto-smoke/,
  );
});

test('validateManifest strict release rejects mobile crypto proof without exact provider markers', () => {
  for (const marker of ['provider=react-native-quick-crypto', 'native_required=true']) {
    const manifest = baseManifest({
      releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
      statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
    });
    const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-MOBILE-001');
    item.evidence[0].result_summary = item.evidence[0].result_summary
      .replace(` ${marker}`, '')
      .replace(
        'mobile-staging-config staging artifact EXPO_PUBLIC_API_BASE_URL',
        `mobile-staging-config staging artifact ${marker} EXPO_PUBLIC_API_BASE_URL`,
      );

    assert.throws(
      () => validateManifest(manifest, { strictRelease: true }),
      /CLIENT-MOBILE-001 strict release evidence must include mobile markers on mobile-native-crypto-smoke/,
    );
  }
});

test('validateManifest strict release rejects mobile crypto proof with mismatched first provider binding', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-MOBILE-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary.replace(
    'mobile-native-crypto-smoke staging artifact runJournalCryptoSelfTest react-native-quick-crypto',
    'mobile-native-crypto-smoke staging artifact runJournalCryptoSelfTest provider=expo-secure-store native_required=true react-native-quick-crypto',
  );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-MOBILE-001 mobile-native-crypto-smoke must bind first provider marker to react-native-quick-crypto/,
  );
});

test('validateManifest strict release rejects mobile staging config proof borrowed from EAS segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-MOBILE-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'mobile-eas-or-device-run staging artifact eas build finished android ios native device installed app release channel staging expo profile staging',
      'mobile-eas-or-device-run staging artifact EXPO_PUBLIC_API_BASE_URL EXPO_PUBLIC_WS_BASE_URL EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging mobile_build_id=mobile-build-123 https:// wss:// staging eas build finished android ios native device installed app release channel staging expo profile staging',
    )
    .replace(
      'mobile-staging-config staging artifact EXPO_PUBLIC_API_BASE_URL EXPO_PUBLIC_WS_BASE_URL EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging mobile_build_id=mobile-build-123 https:// wss:// staging',
      'mobile-staging-config',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-MOBILE-001 strict release evidence must include mobile markers on mobile-staging-config/,
  );
});

test('validateManifest strict release rejects mobile crypto proof without associated-data salt markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-MOBILE-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' associated_data_salt_id=journal:self-test:server-derived-salt', '')
    .replace(' associated_data_salt_version=1', '')
    .replace(
      'mobile-staging-config staging artifact EXPO_PUBLIC_API_BASE_URL',
      'mobile-staging-config staging artifact associated_data_salt_id=journal:self-test:server-derived-salt associated_data_salt_version=1 EXPO_PUBLIC_API_BASE_URL',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-MOBILE-001 strict release evidence must include mobile markers on mobile-native-crypto-smoke/,
  );
});

test('validateManifest strict release rejects mobile crypto proof without concrete associated-data salt values', () => {
  for (const { find, replacement, expected } of [
    {
      find: 'associated_data_salt_id=journal:self-test:server-derived-salt',
      replacement: 'associated_data_salt_id=',
      expected: /CLIENT-MOBILE-001 mobile-native-crypto-smoke must include concrete associated_data_salt_id/,
    },
    {
      find: 'associated_data_salt_version=1',
      replacement: 'associated_data_salt_version=0',
      expected: /CLIENT-MOBILE-001 mobile-native-crypto-smoke must include positive associated_data_salt_version/,
    },
  ]) {
    const manifest = baseManifest({
      releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
      statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
    });
    const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-MOBILE-001');
    item.evidence[0].result_summary = item.evidence[0].result_summary
      .replace(find, replacement);

    assert.throws(
      () => validateManifest(manifest, { strictRelease: true }),
      expected,
    );
  }
});

test('validateManifest strict release rejects mobile evidence with mixed build IDs', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-MOBILE-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'mobile-native-crypto-smoke staging artifact runJournalCryptoSelfTest react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true mobile_build_id=mobile-build-123',
      'mobile-native-crypto-smoke staging artifact runJournalCryptoSelfTest react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true mobile_build_id=mobile-build-other',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-MOBILE-001 strict release evidence mobile_build_id values must all match/,
  );
});

test('validateManifest strict release rejects contradictory mobile staging config markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-MOBILE-001');
  item.evidence[0].result_summary += '; mobile-staging-config EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO = false';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-MOBILE-001 strict release evidence must include a tools\/mobileprobe JSON report/,
  );
});

test('validateManifest strict release rejects mobile crypto fallback provider markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-MOBILE-001');
  item.evidence[0].result_summary += '; mobile-native-crypto-smoke provider=webcrypto-fallback native_required=false';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-MOBILE-001 strict release evidence must include a tools\/mobileprobe JSON report/,
  );
});

test('validateManifest strict release rejects mobile staging config with hardcoded production API URL', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-MOBILE-001');
  item.evidence[0].result_summary += '; mobile-staging-config EXPO_PUBLIC_API_BASE_URL=https://api.scriptureforge.com';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-MOBILE-001 strict release evidence must include a tools\/mobileprobe JSON report/,
  );
});

test('validateManifest strict release rejects mobile evidence without distinct artifact marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-MOBILE-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' distinct_mobile_artifacts=true', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-MOBILE-001 strict release evidence must include mobile markers on mobile-eas-or-device-run/,
  );
});

test('validateManifest strict release rejects mobile distinct artifact proof borrowed from one segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-MOBILE-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('mobile-eas-or-device-run staging artifact eas', 'mobile-eas-or-device-run staging artifact distinct_mobile_artifacts=true eas')
    .replace('mobile-native-crypto-smoke staging artifact runJournalCryptoSelfTest react-native-quick-crypto', 'mobile-native-crypto-smoke staging artifact runJournalCryptoSelfTest react-native-quick-crypto')
    .replace('mobile-staging-config staging artifact EXPO_PUBLIC_API_BASE_URL', 'mobile-staging-config staging artifact EXPO_PUBLIC_API_BASE_URL')
    .replaceAll(' distinct_mobile_artifacts=true', '')
    .replace('mobile-eas-or-device-run staging artifact eas', 'mobile-eas-or-device-run staging artifact distinct_mobile_artifacts=true eas');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-MOBILE-001 strict release evidence must include mobile markers on mobile-native-crypto-smoke/,
  );
});

test('validateManifest strict release rejects mobile evidence for a different release candidate', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'CLIENT-MOBILE-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replaceAll('release_candidate=0123456789abcdef0123456789abcdef01234567', 'release_candidate=oldsha')
    .replaceAll('service_version=scriptureforge-mobile:0123456789abcdef0123456789abcdef01234567', 'service_version=scriptureforge-mobile:oldsha');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /CLIENT-MOBILE-001 strict release evidence must include a tools\/mobileprobe JSON report/,
  );
});

test('validateManifest strict release rejects secret evidence without IRSA CSI and IAM markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'SEC-SECRETS-001');
  item.evidence[0].result_summary = 'SEC-SECRETS-001 passed with securityprobe report';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-SECRETS-001 strict release evidence must include a tools\/securityprobe JSON report/,
  );
});

test('validateManifest strict release rejects secret evidence without staging artifact provenance', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'SEC-SECRETS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('irsa-service-account staging artifact namespace=staging', 'irsa-service-account namespace=staging');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-SECRETS-001 strict release evidence must include security markers on irsa-service-account/,
  );
});

test('validateManifest strict release rejects secret evidence without concrete IAM role ARN', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'SEC-SECRETS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'irsa-service-account staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets',
      'irsa-service-account staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-SECRETS-001 strict release evidence must include concrete IAM role ARN on irsa-service-account/,
  );
});

test('validateManifest strict release rejects secret evidence with mismatched role ARN segments', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'SEC-SECRETS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'iam-secrets-policy staging artifact role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets',
      'iam-secrets-policy staging artifact role_arn=arn:aws:iam::123456789012:role/scriptureforge-other-secrets',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-SECRETS-001 strict release evidence role_arn values must match/,
  );
});

test('validateManifest strict release rejects synced-secret proof borrowed from SecretProviderClass segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'SEC-SECRETS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'secret-provider-class staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets SecretProviderClass',
      'secret-provider-class staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets scriptureforge-runtime-secrets redacted stringData absent managed by secrets-store.csi.k8s.io SecretProviderClass',
    )
    .replace(
      'synced-secret-metadata-redacted staging artifact namespace=staging scriptureforge-runtime-secrets type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN redacted stringData absent managed by secrets-store.csi.k8s.io',
      'synced-secret-metadata-redacted staging artifact namespace=staging',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-SECRETS-001 strict release evidence must include security markers on synced-secret-metadata-redacted/,
  );
});

test('validateManifest strict release rejects synced-secret proof without ownership markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'SEC-SECRETS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'secret-provider-class staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets SecretProviderClass',
      'secret-provider-class staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets ownerReferences secrets-store.csi.k8s.io/managed=true SecretProviderClass',
    )
    .replace(
      'synced-secret-metadata-redacted staging artifact namespace=staging scriptureforge-runtime-secrets type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN redacted stringData absent managed by secrets-store.csi.k8s.io ownerReferences secrets-store.csi.k8s.io/managed=true',
      'synced-secret-metadata-redacted staging artifact namespace=staging scriptureforge-runtime-secrets type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN redacted stringData absent managed by secrets-store.csi.k8s.io',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-SECRETS-001 strict release evidence must include security markers on synced-secret-metadata-redacted/,
  );
});

test('validateManifest strict release rejects IAM policy proof borrowed from access-test segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'SEC-SECRETS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'iam-secrets-policy staging artifact role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets secretsmanager:GetSecretValue secretsmanager:DescribeSecret arn:aws:secretsmanager: scoped resource no wildcard resources',
      'iam-secrets-policy staging artifact role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets',
    )
    .replace(
      'scoped-secrets-access-test staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets allowed configured secret denied unscoped secret AccessDenied distinct_secret_artifacts=true',
      'scoped-secrets-access-test staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets secretsmanager:GetSecretValue secretsmanager:DescribeSecret arn:aws:secretsmanager: scoped resource no wildcard resources allowed configured secret denied unscoped secret AccessDenied distinct_secret_artifacts=true',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-SECRETS-001 strict release evidence must include security markers on iam-secrets-policy/,
  );
});

test('validateManifest strict release rejects scoped access proof borrowed from IAM segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'SEC-SECRETS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'iam-secrets-policy staging artifact role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets secretsmanager:GetSecretValue',
      'iam-secrets-policy staging artifact role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets allowed configured secret denied unscoped secret AccessDenied secretsmanager:GetSecretValue',
    )
    .replace(
      'scoped-secrets-access-test staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets allowed configured secret denied unscoped secret AccessDenied distinct_secret_artifacts=true',
      'scoped-secrets-access-test staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-SECRETS-001 strict release evidence must include a tools\/securityprobe JSON report/,
  );
});

test('validateManifest strict release rejects secret evidence without distinct artifact marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'SEC-SECRETS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary.replace(' distinct_secret_artifacts=true', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-SECRETS-001 strict release evidence must include a tools\/securityprobe JSON report/,
  );
});

test('validateManifest strict release rejects secret evidence with leaked secret-shaped values', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'SEC-SECRETS-001');
  item.evidence[0].result_summary = `${item.evidence[0].result_summary}; synced-secret-metadata-redacted leaked value postgres://scriptureforge_app:secret@db/scriptureforge`;

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-SECRETS-001 strict release evidence must not include secret value marker postgres:\/\//,
  );
});

test('validateManifest strict release rejects secret evidence with Kubernetes stringData field', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'SEC-SECRETS-001');
  item.evidence[0].result_summary = `${item.evidence[0].result_summary}; synced-secret-metadata-redacted stringData: DATABASE_URL redacted`;

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-SECRETS-001 strict release evidence must not include secret value marker stringdata:/,
  );
});

test('validateManifest strict release rejects secret evidence for a different release candidate', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'SEC-SECRETS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replaceAll('release_candidate=0123456789abcdef0123456789abcdef01234567', 'release_candidate=oldsha')
    .replaceAll('service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123', 'service_version=scriptureforge-api:oldsha');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-SECRETS-001 strict release evidence must include a tools\/securityprobe JSON report/,
  );
});

test('validateManifest strict release rejects DB user evidence without scoped role markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'SEC-DBUSER-001');
  item.evidence[0].result_summary = 'SEC-DBUSER-001 passed with securityprobe report';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-DBUSER-001 strict release evidence must include a tools\/securityprobe JSON report/,
  );
});

test('validateManifest strict release rejects DB user evidence without staging artifact provenance', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'SEC-DBUSER-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('database-scoped-user staging artifact connected as', 'database-scoped-user connected as');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-DBUSER-001 strict release evidence must include database user markers on database-scoped-user/,
  );
});

test('validateManifest strict release rejects DB user privilege proof borrowed outside scoped segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'SEC-DBUSER-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'database-scoped-user staging artifact connected as scriptureforge_app current_user=scriptureforge_app superuser=false bypassrls=false createrole=false createdb=false privileged_operation_denied=true app_grants_verified=true app_grant_tables=9 app_grant_table_names=organizations,users,scripture_texts,refresh_tokens,journal_entries,live_rooms,room_participants,ai_request_logs,citation_trails app_grants=SELECT,INSERT,UPDATE,DELETE',
      'database-scoped-user staging artifact connected as scriptureforge_app; scoped-role-summary current_user=scriptureforge_app superuser=false bypassrls=false createrole=false createdb=false privileged_operation_denied=true app_grants_verified=true app_grant_tables=9 app_grant_table_names=organizations,users,scripture_texts,refresh_tokens,journal_entries,live_rooms,room_participants,ai_request_logs,citation_trails app_grants=SELECT,INSERT,UPDATE,DELETE',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-DBUSER-001 strict release evidence must include database user markers on database-scoped-user/,
  );
});

test('validateManifest strict release rejects DB user evidence without scriptureforge_app principal', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'SEC-DBUSER-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('connected as scriptureforge_app', 'connected as tenant_app');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-DBUSER-001 database-scoped-user must bind connected user and current_user to scriptureforge_app/,
  );
});

test('validateManifest strict release rejects DB user evidence without bypass RLS denial', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'SEC-DBUSER-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' superuser=false bypassrls=false createrole=false', ' superuser=false createrole=false')
    + '; database-user-bypass-summary bypassrls=false';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-DBUSER-001 strict release evidence must include database user markers on database-scoped-user/,
  );
});

test('validateManifest strict release rejects DB user evidence without privileged operation denial', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'SEC-DBUSER-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' privileged_operation_denied=true', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-DBUSER-001 strict release evidence must include a tools\/securityprobe JSON report/,
  );
});

test('validateManifest strict release rejects DB user evidence without application grant proof', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'SEC-DBUSER-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' app_grants_verified=true app_grant_tables=9 app_grant_table_names=organizations,users,scripture_texts,refresh_tokens,journal_entries,live_rooms,room_participants,ai_request_logs,citation_trails app_grants=SELECT,INSERT,UPDATE,DELETE', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-DBUSER-001 strict release evidence must include a tools\/securityprobe JSON report/,
  );
});

test('validateManifest strict release rejects DB user evidence without application grant table names', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'SEC-DBUSER-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' app_grant_table_names=organizations,users,scripture_texts,refresh_tokens,journal_entries,live_rooms,room_participants,ai_request_logs,citation_trails', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-DBUSER-001 strict release evidence must include a tools\/securityprobe JSON report/,
  );
});

test('validateManifest strict release rejects DB user evidence for a different release candidate', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'SEC-DBUSER-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replaceAll('release_candidate=0123456789abcdef0123456789abcdef01234567', 'release_candidate=oldsha')
    .replaceAll('service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123', 'service_version=scriptureforge-api:oldsha');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-DBUSER-001 strict release evidence must include a tools\/securityprobe JSON report/,
  );
});

test('validateManifest strict release rejects rollback evidence without version and degradation markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DR-ROLLBACK-001');
  item.evidence[0].result_summary = 'DR-ROLLBACK-001 passed with resilienceprobe report';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DR-ROLLBACK-001 strict release evidence must include a tools\/resilienceprobe JSON report/,
  );
});

test('validateManifest strict release rejects rollback rollout proof borrowed from readiness segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DR-ROLLBACK-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'api-ready-before-rollback staging artifact ready service_version deployment_environment pre_rollback_version pre_rollback_version=release-1 release_candidate=',
      'api-ready-before-rollback rollout undo revision previous_revision target_revision scriptureforge-api successfully rolled out staging artifact ready service_version deployment_environment pre_rollback_version pre_rollback_version=release-1 release_candidate=',
    )
    .replace(
      'rollback-rollout-artifact staging artifact rollout undo revision previous_revision target_revision scriptureforge-api successfully rolled out release_candidate=',
      'rollback-rollout-artifact release_candidate=',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DR-ROLLBACK-001 strict release evidence must include resilience markers on rollback-rollout-artifact/,
  );
});

test('validateManifest strict release rejects degradation proof borrowed from rollout segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DR-ROLLBACK-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'rollback-rollout-artifact staging artifact rollout',
      'rollback-rollout-artifact AI Zoom degradation fallback AI_ORCHESTRATION_ENGINE_FAULT offline://in-person non-AI routes healthy zoom circuit open ai_fault=true zoom_offline_fallback=true non_ai_routes_healthy=true zoom_circuit_open=true distinct_rollback_artifacts=true staging artifact rollout',
    )
    .replace(
      'degradation-drill-artifact staging artifact AI Zoom degradation fallback AI_ORCHESTRATION_ENGINE_FAULT offline://in-person non-AI routes healthy zoom circuit open ai_fault=true zoom_offline_fallback=true non_ai_routes_healthy=true zoom_circuit_open=true distinct_rollback_artifacts=true release_candidate=',
      'degradation-drill-artifact release_candidate=',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DR-ROLLBACK-001 strict release evidence must include resilience markers on degradation-drill-artifact/,
  );
});

test('validateManifest strict release rejects rollback evidence without distinct artifact marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DR-ROLLBACK-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' distinct_rollback_artifacts=true', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DR-ROLLBACK-001 strict release evidence must include a tools\/resilienceprobe JSON report/,
  );
});

test('validateManifest strict release rejects rollback degradation evidence without structured fallback marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DR-ROLLBACK-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' ai_fault=true', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DR-ROLLBACK-001 strict release evidence must include a tools\/resilienceprobe JSON report/,
  );
});

test('validateManifest strict release rejects resilience evidence without segment load run marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DR-ROLLBACK-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('api-ready-before-rollback staging artifact ready service_version deployment_environment pre_rollback_version pre_rollback_version=release-1 release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123', 'api-ready-before-rollback staging artifact ready service_version deployment_environment pre_rollback_version pre_rollback_version=release-1 release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DR-ROLLBACK-001 strict release evidence must include resilience markers on api-ready-before-rollback/,
  );
});

test('validateManifest strict release rejects rollback evidence with inconsistent version linkage', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DR-ROLLBACK-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('rolled_back_from=release-1', 'rolled_back_from=release-other');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DR-ROLLBACK-001 strict release rolled_back_from must match pre_rollback_version/,
  );
});

test('validateManifest strict release rejects rollback evidence with admitted failed drill marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DR-ROLLBACK-001');
  item.evidence[0].result_summary += '; rollback failed';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DR-ROLLBACK-001 strict release evidence must include a tools\/resilienceprobe JSON report/,
  );
});

test('validateManifest strict release rejects backup evidence without restore and smoke markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DR-BACKUP-001');
  item.evidence[0].result_summary = 'DR-BACKUP-001 passed with resilienceprobe report';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DR-BACKUP-001 strict release evidence must include a tools\/resilienceprobe JSON report/,
  );
});

test('validateManifest strict release rejects backup evidence with admitted failed restore marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DR-BACKUP-001');
  item.evidence[0].result_summary += '; restore failed';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DR-BACKUP-001 strict release evidence must include a tools\/resilienceprobe JSON report/,
  );
});

test('validateManifest strict release rejects backup restore proof borrowed from snapshot segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DR-BACKUP-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'backup-snapshot-artifact staging artifact snapshot',
      'backup-snapshot-artifact restore restore_job_id available staging restored endpoint source snapshot_id checksum isolated restore rto_minutes restore_duration_minutes staging artifact snapshot',
    )
    .replace(
      'restore-drill-artifact staging artifact restore restore_job_id=restore-456 available staging restored endpoint source snapshot_id=snap-123 checksum isolated restore rto_minutes=30 restore_duration_minutes=18 release_candidate=',
      'restore-drill-artifact release_candidate=',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DR-BACKUP-001 strict release evidence must include resilience markers on restore-drill-artifact/,
  );
});

test('validateManifest strict release rejects restored database smoke proof borrowed from restore segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DR-BACKUP-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'restore-drill-artifact staging artifact restore',
      'restore-drill-artifact smoke passed restored database tenant journal auth RLS migration version no plaintext journal distinct_backup_artifacts=true staging artifact restore',
    )
    .replace(
      'restored-database-smoke staging artifact smoke passed restored database tenant journal auth RLS migration version no plaintext journal distinct_backup_artifacts=true release_candidate=',
      'restored-database-smoke release_candidate=',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DR-BACKUP-001 strict release evidence must include resilience markers on restored-database-smoke/,
  );
});

test('validateManifest strict release rejects backup restore source snapshot mismatch', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DR-BACKUP-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('source snapshot_id=snap-123', 'source snapshot_id=snap-other');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DR-BACKUP-001 strict release restore source snapshot_id must match backup snapshot_id/,
  );
});

test('validateManifest strict release rejects backup restore duration above RTO', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DR-BACKUP-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('restore_duration_minutes=18', 'restore_duration_minutes=45');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DR-BACKUP-001 strict release restore_duration_minutes 45 must be <= rto_minutes 30/,
  );
});

test('validateManifest strict release rejects backup evidence without distinct artifact marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DR-BACKUP-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' distinct_backup_artifacts=true', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DR-BACKUP-001 strict release evidence must include a tools\/resilienceprobe JSON report/,
  );
});

test('validateManifest strict release rejects resilience evidence without exact manifest release candidate', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const rollback = manifest.items.find((candidate) => candidate.id === 'DR-ROLLBACK-001');
  rollback.evidence[0].result_summary = rollback.evidence[0].result_summary
    .replaceAll('release_candidate=0123456789abcdef0123456789abcdef01234567', 'release_candidate=oldsha');
  const backup = manifest.items.find((candidate) => candidate.id === 'DR-BACKUP-001');
  backup.evidence[0].result_summary = backup.evidence[0].result_summary
    .replaceAll('release_candidate=0123456789abcdef0123456789abcdef01234567', 'release_candidate=oldsha');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DR-ROLLBACK-001 strict release evidence must include a tools\/resilienceprobe JSON report/,
  );
});

test('validateManifest strict release rejects abuse evidence without account-scoped login proof', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const abuseItem = manifest.items.find((item) => item.id === 'ABUSE-LIMIT-001');
  abuseItem.evidence[0].result_summary = 'ABUSE-LIMIT-001 passed with auth, AI, journal, rooms, and websocket upgrade probes';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /ABUSE-LIMIT-001 strict release evidence must include a tools\/abuseprobe JSON report/,
  );
});

test('validateManifest strict release rejects abuse evidence without config proof', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const abuseItem = manifest.items.find((item) => item.id === 'ABUSE-LIMIT-001');
  abuseItem.evidence[0].result_summary = 'ABUSE-LIMIT-001 passed with auth, account-scoped login, refresh token, AI, journal, rooms, and websocket upgrade probes';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /ABUSE-LIMIT-001 strict release evidence must include a tools\/abuseprobe JSON report/,
  );
});

test('validateManifest strict release rejects abuse evidence without refresh-token proof', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const abuseItem = manifest.items.find((item) => item.id === 'ABUSE-LIMIT-001');
  abuseItem.evidence[0].result_summary = 'ABUSE-LIMIT-001 abuseprobe passed with auth, account-scoped login, AI, journal, rooms, and websocket upgrade probes after repeated attempts; config_artifact_verified=true; config_artifact_summary markers include ABUSE_LIMIT_AUTH_REQUESTS=2, ABUSE_LIMIT_AUTH_WINDOW_SECONDS=60, ABUSE_LIMIT_AUTH_ACCOUNT_REQUESTS=2, ABUSE_LIMIT_AUTH_ACCOUNT_WINDOW_SECONDS=60, ABUSE_LIMIT_AI_REQUESTS=2, ABUSE_LIMIT_JOURNAL_REQUESTS=2, ABUSE_LIMIT_ROOMS_REQUESTS=2, ABUSE_LIMIT_WEBSOCKET_REQUESTS=2, ABUSE_LIMIT_MAX_BUCKETS=1000, TRUST_PROXY_HEADERS=true, X-Forwarded-For, X-Real-IP, redacted, distinct_abuse_artifacts=true';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /ABUSE-LIMIT-001 strict release evidence must include a tools\/abuseprobe JSON report/,
  );
});

test('validateManifest strict release rejects abuse evidence with first-attempt denial proof', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'ABUSE-LIMIT-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('auth-rate-limit staging artifact 429 after 2 attempts', 'auth-rate-limit staging artifact 429 after 1 attempts');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /ABUSE-LIMIT-001 strict release auth-rate-limit attempts 1 must be >= 2/,
  );
});

test('validateManifest strict release rejects abuse profile evidence without staging artifact provenance', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'ABUSE-LIMIT-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('journal-rate-limit staging artifact 429 after 2 attempts', 'journal-rate-limit 429 after 2 attempts');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /ABUSE-LIMIT-001 strict release evidence must include abuse markers on journal-rate-limit/,
  );
});

test('validateManifest strict release rejects decorative abuse rate-limit headers without values', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'ABUSE-LIMIT-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'auth-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200',
      'auth-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After X-RateLimit-Limit X-RateLimit-Remaining X-RateLimit-Reset',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /ABUSE-LIMIT-001 strict release auth-rate-limit must include concrete Retry-After=<integer>/,
  );
});

test('validateManifest strict release rejects abuse evidence for a different release candidate', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const abuseItem = manifest.items.find((item) => item.id === 'ABUSE-LIMIT-001');
  abuseItem.evidence[0].result_summary = abuseItem.evidence[0].result_summary
    .replaceAll('release_candidate=0123456789abcdef0123456789abcdef01234567', 'release_candidate=oldsha')
    .replaceAll('service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123', 'service_version=scriptureforge-api:oldsha');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /ABUSE-LIMIT-001 strict release evidence must include a tools\/abuseprobe JSON report/,
  );
});

test('validateManifest strict release rejects abuse account proof borrowed from auth segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const abuseItem = manifest.items.find((item) => item.id === 'ABUSE-LIMIT-001');
  abuseItem.evidence[0].result_summary = abuseItem.evidence[0].result_summary
    .replace(
      'auth-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200',
      'auth-rate-limit staging artifact account-scoped login rotating forwarded client IP 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200',
    )
    .replace(
      'auth-account-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200 account-scoped login account_scoped=true rotating forwarded client IP forwarded_client_ip_rotated=true',
      'auth-account-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /ABUSE-LIMIT-001 strict release evidence must include abuse markers on auth-account-rate-limit/,
  );
});

test('validateManifest strict release rejects abuse websocket proof borrowed from rooms segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const abuseItem = manifest.items.find((item) => item.id === 'ABUSE-LIMIT-001');
  abuseItem.evidence[0].result_summary = abuseItem.evidence[0].result_summary
    .replace(
      'rooms-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200',
      'rooms-rate-limit staging artifact websocket upgrade 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200',
    )
    .replace(
      'websocket-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200 websocket upgrade',
      'websocket-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /ABUSE-LIMIT-001 strict release evidence must include abuse markers on websocket-rate-limit/,
  );
});

test('validateManifest strict release rejects abuse config proof borrowed from rate-limit segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const abuseItem = manifest.items.find((item) => item.id === 'ABUSE-LIMIT-001');
  abuseItem.evidence[0].result_summary = abuseItem.evidence[0].result_summary
    .replace(
      'auth-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200',
      'auth-rate-limit staging artifact ABUSE_LIMIT_AUTH_REQUESTS=2 ABUSE_LIMIT_AUTH_WINDOW_SECONDS=60 ABUSE_LIMIT_AUTH_ACCOUNT_REQUESTS=2 ABUSE_LIMIT_AUTH_ACCOUNT_WINDOW_SECONDS=60 ABUSE_LIMIT_AI_REQUESTS=2 ABUSE_LIMIT_JOURNAL_REQUESTS=2 ABUSE_LIMIT_ROOMS_REQUESTS=2 ABUSE_LIMIT_WEBSOCKET_REQUESTS=2 ABUSE_LIMIT_MAX_BUCKETS=1000 TRUST_PROXY_HEADERS=true X-Forwarded-For X-Real-IP redacted distinct_abuse_artifacts=true 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200',
    )
    .replace(
      'config_artifact_summary ABUSE_LIMIT_AUTH_REQUESTS=2 ABUSE_LIMIT_AUTH_WINDOW_SECONDS=60 ABUSE_LIMIT_AUTH_ACCOUNT_REQUESTS=2 ABUSE_LIMIT_AUTH_ACCOUNT_WINDOW_SECONDS=60 ABUSE_LIMIT_AI_REQUESTS=2 ABUSE_LIMIT_JOURNAL_REQUESTS=2 ABUSE_LIMIT_ROOMS_REQUESTS=2 ABUSE_LIMIT_WEBSOCKET_REQUESTS=2 ABUSE_LIMIT_MAX_BUCKETS=1000 TRUST_PROXY_HEADERS=true X-Forwarded-For X-Real-IP redacted distinct_abuse_artifacts=true',
      'config_artifact_summary',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /ABUSE-LIMIT-001 strict release evidence must include abuse markers on config_artifact_summary/,
  );
});

test('validateManifest strict release rejects abuse config without assignment markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const abuseItem = manifest.items.find((item) => item.id === 'ABUSE-LIMIT-001');
  abuseItem.evidence[0].result_summary = abuseItem.evidence[0].result_summary
    .replace('ABUSE_LIMIT_AI_REQUESTS=2', 'ABUSE_LIMIT_AI_REQUESTS');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /ABUSE-LIMIT-001 strict release evidence must include abuse markers on config_artifact_summary/,
  );
});

test('validateManifest strict release rejects abuse config with zero assignment values', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const abuseItem = manifest.items.find((item) => item.id === 'ABUSE-LIMIT-001');
  abuseItem.evidence[0].result_summary = abuseItem.evidence[0].result_summary
    .replace('ABUSE_LIMIT_AI_REQUESTS=2', 'ABUSE_LIMIT_AI_REQUESTS=0');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /ABUSE-LIMIT-001 strict release config_artifact_summary ABUSE_LIMIT_AI_REQUESTS must be a positive integer/,
  );
});

test('validateManifest strict release rejects HTTP load evidence without threshold and artifact markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-HTTP-001');
  item.evidence[0].result_summary = 'PERF-HTTP-001 passed with loadtest report';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-HTTP-001 strict release evidence must include a tools\/loadtest JSON report/,
  );
});

test('validateManifest strict release rejects HTTP load threshold proof borrowed from artifact segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-HTTP-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'verified markers: http_replica_artifact_verified',
      'verified markers: min_rps=5000 http_replica_artifact_verified',
    )
    .replace(
      'min_rps=5000',
      'min_rps',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-HTTP-001 strict release evidence must include HTTP load markers on PERF-HTTP-001/,
  );
});

test('validateManifest strict release rejects HTTP artifact proof borrowed from measurement segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-HTTP-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'PERF-HTTP-001 profile=staging_http',
      'PERF-HTTP-001 http_replica_artifact_verified profile=staging_http',
    )
    .replace(
      'verified markers: http_replica_artifact_verified, http_replica_count=2, dependency_telemetry_artifact_verified, dependency_latency_artifact_verified=true, dependency_postgres_p99_ms=32, dependency_redis_p99_ms=18, http_distinct_artifacts=true',
      'verified markers: dependency_telemetry_artifact_verified, dependency_latency_artifact_verified=true, dependency_postgres_p99_ms=32, dependency_redis_p99_ms=18, http_distinct_artifacts=true',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-HTTP-001 strict release evidence must include HTTP load markers on verified markers/,
  );
});

test('validateManifest strict release rejects HTTP load evidence without distinct artifact marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-HTTP-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(', http_distinct_artifacts=true', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-HTTP-001 strict release evidence must include HTTP load markers on verified markers/,
  );
});

test('validateManifest strict release rejects HTTP load evidence without load run identity', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-HTTP-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replaceAll(' load_run_id=load-run-123', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-HTTP-001 strict release evidence must include a tools\/loadtest JSON report/,
  );
});

test('validateManifest strict release rejects HTTP load evidence below observed RPS target', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-HTTP-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('observed_rps=5200', 'observed_rps=4999');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-HTTP-001 strict release observed_rps 4999 is below required 5000/,
  );
});

test('validateManifest strict release rejects HTTP load evidence above observed P99 target', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-HTTP-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('observed_p99_ms=180', 'observed_p99_ms=201');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-HTTP-001 strict release observed_p99_ms 201 must be <= 200/,
  );
});

test('validateManifest strict release rejects HTTP load evidence with weak side artifact values', () => {
  for (const [summaryPatch, expected] of [
    [
      (summary) => summary.replace('http_replica_count=2', 'http_replica_count=1'),
      /PERF-HTTP-001 strict release http_replica_count 1 must prove at least 2 replicas/,
    ],
    [
      (summary) => summary.replace('dependency_postgres_p99_ms=32', 'dependency_postgres_p99_ms=250'),
      /PERF-HTTP-001 strict release dependency_postgres_p99_ms 250 must be <= 200/,
    ],
    [
      (summary) => summary.replace('dependency_redis_p99_ms=18', 'dependency_redis_p99_ms=250'),
      /PERF-HTTP-001 strict release dependency_redis_p99_ms 250 must be <= 200/,
    ],
  ]) {
    const manifest = baseManifest({
      releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
      statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
    });
    const item = manifest.items.find((candidate) => candidate.id === 'PERF-HTTP-001');
    item.evidence[0].result_summary = summaryPatch(item.evidence[0].result_summary);

    assert.throws(
      () => validateManifest(manifest, { strictRelease: true }),
      expected,
    );
  }
});

test('validateManifest strict release rejects HTTP load evidence without production target markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-HTTP-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' production_target_rps=5000 production_target_p99_ms=200', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-HTTP-001 strict release evidence must include HTTP load markers on PERF-HTTP-001/,
  );
});

test('validateManifest strict release rejects HTTP load evidence without dependency latency marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-HTTP-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(', dependency_latency_artifact_verified=true', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-HTTP-001 strict release evidence must include a tools\/loadtest JSON report/,
  );
});

test('validateManifest strict release rejects HTTP load evidence below minimum measurement duration', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-HTTP-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' observed_p99_ms=180 duration_ms=60000 ', ' observed_p99_ms=180 duration_ms=1000 ');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-HTTP-001 strict release duration_ms 1000 is below required 60000/,
  );
});

test('validateManifest strict release rejects HTTP load evidence when threshold pass marker is false', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-HTTP-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('threshold_pass=true', 'threshold_pass=false')
    .replace('verified markers:', 'verified markers: threshold_pass=true,');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-HTTP-001 strict release evidence must include HTTP load markers on PERF-HTTP-001/,
  );
});

test('validateManifest strict release rejects HTTP load evidence with admitted threshold failure marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-HTTP-001');
  item.evidence[0].result_summary = `${item.evidence[0].result_summary}; threshold failed`;

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-HTTP-001 strict release evidence must include a tools\/loadtest JSON report/,
  );
});

test('validateManifest strict release rejects WebSocket load evidence without sequence and Redis markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const perfItem = manifest.items.find((candidate) => candidate.id === 'PERF-WS-001');
  perfItem.evidence[0].result_summary = 'PERF-WS-001 passed with loadtest report';
  const redisItem = manifest.items.find((candidate) => candidate.id === 'DATA-REDIS-001');
  redisItem.evidence[0].result_summary = 'DATA-REDIS-001 passed with loadtest report';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-REDIS-001 strict release evidence must include a tools\/loadtest JSON report/,
  );
});

test('validateManifest strict release rejects WebSocket sequence proof borrowed from artifact segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-WS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'verified markers: staging artifact,',
      'verified markers: staging artifact, ws_sequence_contiguous=true,',
    )
    .replace(
      'ws_sequence_contiguous=true;',
      'ws_sequence_contiguous;',
    )
    .replace(
      'ws_replica_count=2 room_broadcast_drops=0;',
      'room_broadcast_drops=0;',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-WS-001 strict release evidence must include WebSocket load markers on PERF-WS-001/,
  );
});

test('validateManifest strict release rejects WebSocket load evidence without a measurement segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-WS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('PERF-WS-001 staging artifact profile=staging_websocket', 'staging artifact profile=staging_websocket');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-WS-001 strict release evidence must include WebSocket load markers on PERF-WS-001/,
  );
});

test('validateManifest strict release rejects WebSocket load evidence without staging artifact provenance', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-WS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary.replace(
    'PERF-WS-001 staging artifact profile=staging_websocket',
    'PERF-WS-001 profile=staging_websocket',
  );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-WS-001 strict release evidence must include WebSocket load markers on PERF-WS-001/,
  );
});

test('validateManifest strict release rejects WebSocket load evidence without production target markers', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-WS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' production_target_rps=500 production_target_p99_ms=200 production_min_duration_ms=60000 production_min_ws_events=30000', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-WS-001 strict release evidence must include WebSocket load markers on PERF-WS-001/,
  );
});

test('validateManifest strict release rejects WebSocket load evidence below minimum event volume', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-WS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('ws_expected_events=30000', 'ws_expected_events=29999');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-WS-001 strict release ws_expected_events 29999 is below required 30000/,
  );
});

test('validateManifest strict release rejects WebSocket load evidence without room binding', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-WS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' ws_room_id=room-1', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-WS-001 strict release evidence must include WebSocket load markers on PERF-WS-001/,
  );
});

test('validateManifest strict release rejects WebSocket load evidence without polling latest sequence binding', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-WS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' ws_polling_latest_sequence=30000', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-WS-001 strict release evidence must include a tools\/loadtest JSON report/,
  );
});

test('validateManifest strict release rejects WebSocket load evidence without polling artifact sequence validation marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-WS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' ws_polling_artifact_latest_sequence_validated=true,', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-WS-001 strict release evidence must include a tools\/loadtest JSON report/,
  );
});

test('validateManifest strict release rejects WebSocket reconnect proof borrowed from measurement segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-WS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'PERF-WS-001 staging artifact profile=staging_websocket',
      'PERF-WS-001 staging artifact ws_reconnect_artifact_verified profile=staging_websocket',
    )
    .replace(
      'ws_reconnect_artifact_url=https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt, ws_reconnect_artifact_verified, ',
      'ws_reconnect_artifact_url=https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt, ',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-WS-001 strict release evidence must include WebSocket load markers on verified markers/,
  );
});

test('validateManifest strict release rejects WebSocket reconnect proof without sequence continuity marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-WS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' ws_reconnect_sequence_continues=true,', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-WS-001 strict release evidence must include a tools\/loadtest JSON report/,
  );
});

test('validateManifest strict release rejects WebSocket load evidence below observed RPS target', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-WS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('observed_rps=620', 'observed_rps=499');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-WS-001 strict release observed_rps 499 is below required 500/,
  );
});

test('validateManifest strict release rejects WebSocket load evidence with weak replica proof', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-WS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('ws_replica_count=2', 'ws_replica_count=1');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-WS-001 strict release ws_replica_count 1 must prove at least 2 replicas/,
  );
});

test('validateManifest strict release rejects WebSocket load evidence when threshold pass marker is false', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-WS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('threshold_pass=true', 'threshold_pass=false')
    .replace('verified markers:', 'verified markers: threshold_pass=true,');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-WS-001 strict release evidence must include WebSocket load markers on PERF-WS-001/,
  );
});

test('validateManifest strict release rejects WebSocket load evidence below minimum measurement duration', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-WS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' duration_ms=60000 ', ' duration_ms=1000 ');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-WS-001 strict release duration_ms 1000 is below required 60000/,
  );
});

test('validateManifest strict release rejects WebSocket load evidence without distinct artifact marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-WS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' ws_distinct_artifacts=true,', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-WS-001 strict release evidence must include a tools\/loadtest JSON report/,
  );
});

test('validateManifest strict release rejects Redis sequence proof borrowed from artifact segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-REDIS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'verified markers: staging artifact, redis_telemetry_artifact_verified',
      'verified markers: staging artifact, ws_sequence_contiguous=true, redis_telemetry_artifact_verified',
    )
    .replace(
      'ws_sequence_contiguous=true',
      'ws_sequence_contiguous',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-REDIS-001 strict release evidence must include a tools\/loadtest JSON report/,
  );
});

test('validateManifest strict release rejects Redis evidence with broadcast drops', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-REDIS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('room_broadcast_drops=0', 'room_broadcast_drops=1');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-REDIS-001 strict release evidence must include a tools\/loadtest JSON report/,
  );
});

test('validateManifest strict release rejects Redis sequence evidence when polling state lags max sequence', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-REDIS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('ws_polling_latest_sequence=30000', 'ws_polling_latest_sequence=29999');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-REDIS-001 strict release polling latest sequence must match maximum sequence/,
  );
});

test('validateManifest strict release rejects Redis sequence evidence below minimum event volume', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-REDIS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('ws_expected_events=30000', 'ws_expected_events=29999');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-REDIS-001 strict release ws_expected_events 29999 is below required 30000/,
  );
});

test('validateManifest strict release rejects Redis evidence without a Redis measurement segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-REDIS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace('DATA-REDIS-001 staging artifact profile=staging_websocket', 'staging artifact profile=staging_websocket');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-REDIS-001 strict release evidence must include Redis load markers on DATA-REDIS-001/,
  );
});

test('validateManifest strict release rejects Redis evidence without room binding', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-REDIS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' ws_room_id=room-1', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-REDIS-001 strict release evidence must include Redis load markers on DATA-REDIS-001/,
  );
});

test('validateManifest strict release rejects Redis evidence without polling latest sequence binding', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-REDIS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' ws_polling_latest_sequence=30000', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-REDIS-001 strict release evidence must include a tools\/loadtest JSON report/,
  );
});

test('validateManifest strict release rejects Redis telemetry proof borrowed from sequence segment', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-REDIS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(
      'DATA-REDIS-001 staging artifact profile=staging_websocket',
      'DATA-REDIS-001 staging artifact redis_telemetry_artifact_verified profile=staging_websocket',
    )
    .replace(
      'verified markers: staging artifact, ws_polling_artifact_url=https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt, redis_telemetry_artifact_verified, ws_polling_artifact_latest_sequence_validated=true, ws_polling_artifact_latest_sequence_matches_run=true, ws_distinct_artifacts=true, room_broadcast_drops=0',
      'verified markers: staging artifact, ws_polling_artifact_url=https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt, ws_polling_artifact_latest_sequence_validated=true, ws_polling_artifact_latest_sequence_matches_run=true, ws_distinct_artifacts=true, room_broadcast_drops=0',
    );

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-REDIS-001 strict release evidence must include Redis load markers on verified markers/,
  );
});

test('validateManifest strict release rejects Redis evidence without distinct artifact marker', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-REDIS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replace(' ws_distinct_artifacts=true,', '');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /DATA-REDIS-001 strict release evidence must include a tools\/loadtest JSON report/,
  );
});

test('validateManifest strict release rejects load evidence without exact manifest release candidate', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'PERF-HTTP-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replaceAll('release_candidate=0123456789abcdef0123456789abcdef01234567', 'release_candidate');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /PERF-HTTP-001 strict release evidence must include a tools\/loadtest JSON report/,
  );
});

test('validateManifest strict release rejects mixed performance load run identities', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'DATA-REDIS-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replaceAll('load_run_id=load-run-123', 'load_run_id=load-run-456');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /strict release performance evidence load_run_id values must match across PERF-HTTP-001, PERF-WS-001, and DATA-REDIS-001/,
  );
});

test('validateManifest strict release rejects mixed release load run identities across evidence families', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: (id) => id === 'SEC-SIGNOFF-001' ? 'accepted_risk' : 'passed',
  });
  const item = manifest.items.find((candidate) => candidate.id === 'EXT-AI-001');
  item.evidence[0].result_summary = item.evidence[0].result_summary
    .replaceAll('load_run_id=load-run-123', 'load_run_id=load-run-456');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /strict release evidence load_run_id values must match across all staging evidence items/,
  );
});

test('validateManifest strict release rejects generic passed security signoff evidence', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: () => 'passed',
  });
  const signoffItem = manifest.items.find((item) => item.id === 'SEC-SIGNOFF-001');
  signoffItem.evidence[0].result_summary = 'security owner approved release';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-SIGNOFF-001 strict release evidence must include threat-model, dependency-risk, residual-risk, owner\/security approval, release signoff, and exact release_candidate markers/,
  );
});

test('validateManifest strict release rejects signoff evidence for a different release candidate', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: () => 'passed',
  });
  const signoffItem = manifest.items.find((item) => item.id === 'SEC-SIGNOFF-001');
  signoffItem.evidence[0].result_summary = signoffItem.evidence[0].result_summary
    .replaceAll('release_candidate=0123456789abcdef0123456789abcdef01234567', 'release_candidate=oldsha');

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-SIGNOFF-001 strict release evidence must include threat-model, dependency-risk, residual-risk, owner\/security approval, release signoff, and exact release_candidate markers/,
  );
});

test('validateManifest strict release rejects placeholder security signoff evidence', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: () => 'passed',
  });
  const signoffItem = manifest.items.find((item) => item.id === 'SEC-SIGNOFF-001');
  signoffItem.evidence[0].result_summary = `${signoffItem.evidence[0].result_summary}; placeholder approval package`;

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /SEC-SIGNOFF-001 strict release evidence must include threat-model, dependency-risk, residual-risk, owner\/security approval, release signoff, and exact release_candidate markers/,
  );
});

test('validateManifest strict release rejects placeholder release candidate', () => {
  const manifest = baseManifest({
    releaseCandidate: 'replace-with-git-sha-or-tag',
    statusFor: () => 'passed',
  });

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /real release_candidate/,
  );
});

test('validateManifest strict release rejects non-SHA release candidate values', () => {
  const manifest = baseManifest({
    releaseCandidate: 'v2026.06.27',
    statusFor: () => 'passed',
  });

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /release_candidate must be a 40-character git commit SHA/,
  );
});

test('validateManifest strict release rejects local environment manifests', () => {
  const manifest = baseManifest({
    releaseCandidate: '0123456789abcdef0123456789abcdef01234567',
    statusFor: () => 'passed',
  });
  manifest.environment = 'local';

  assert.throws(
    () => validateManifest(manifest, { strictRelease: true }),
    /strict release manifest environment must be staging, production, or prod/,
  );
});

function baseManifest({ releaseCandidate = 'replace-with-git-sha-or-tag', statusFor }) {
  return {
    schema_version: 1,
    environment: 'staging',
    release_candidate: releaseCandidate,
    generated_at: '2026-06-25T23:59:00Z',
    items: requiredIds.map((id) => buildItem(id, statusFor(id))),
  };
}
function buildItem(id, status) {
  const item = {
    id,
    category: 'test',
    status,
    description: `${id} proof`,
  };

  if (status === 'pending_external') {
    item.required_evidence = ['artifact'];
  } else if (status === 'passed') {
    item.evidence = [passedEvidenceFor(id)];
  } else if (status === 'blocked' || status === 'failed') {
    item.owner = 'platform';
    item.blocker = `${status} in test`;
  } else if (status === 'accepted_risk') {
    item.decision_ref = 'security/dependency_risk_register.md#DRR-001';
    item.owner = 'security';
    item.accepted_by = 'release-owner';
    item.review_due_at = '2026-07-25';
    item.expires_at = '2026-08-25';
  }

  return item;
}
function passedEvidenceFor(id) {
  const probeById = {
    'SRC-CI-001': 'ciprobe',
    'DEPLOY-TF-001': 'deploymentprobe',
    'DEPLOY-TLS-001': 'stagingprobe',
    'DEPLOY-K8S-001': 'deploymentprobe',
    'SEC-SECRETS-001': 'securityprobe',
    'SEC-DBUSER-001': 'securityprobe',
    'ABUSE-LIMIT-001': 'abuseprobe',
    'DATA-RLS-001': 'tenantprobe',
    'DATA-REDIS-001': 'loadtest',
    'RUST-GRPC-001': 'rustprobe',
    'OBS-OTEL-001': 'observabilityprobe',
    'OBS-ALERT-001': 'observabilityprobe',
    'CLIENT-WEB-001': 'stagingprobe',
    'CLIENT-MOBILE-001': 'mobileprobe',
    'EXT-ZOOM-001': 'zoomprobe',
    'EXT-AI-001': 'aiprobe',
    'PERF-HTTP-001': 'loadtest',
    'PERF-WS-001': 'loadtest',
    'DR-ROLLBACK-001': 'resilienceprobe',
    'DR-BACKUP-001': 'resilienceprobe',
  };
  const probe = probeById[id] ?? 'probe';
  return {
    observed_at: '2026-06-25T12:00:00Z',
    command_or_probe: id === 'SRC-CI-001'
      ? 'go run ./tools/ciprobe -run-artifact-url https://artifacts.staging.scriptureforge.ai/ci/ci-release-evidence.txt'
      : id === 'SEC-SIGNOFF-001'
        ? 'security owner signoff'
      : `go run ./tools/${probe}`,
    artifact: id === 'SEC-SIGNOFF-001'
      ? 'security/release-signoff.md'
      : `https://artifacts.staging.scriptureforge.ai/${probe}.json`,
    result_summary: id === 'SRC-CI-001'
      ? ciReleaseEvidenceSummary('0123456789abcdef0123456789abcdef01234567')
      : id === 'DEPLOY-TF-001'
        ? 'DEPLOY-TF-001 deploymentprobe passed: terraform-remote-backend-init staging artifact terraform s3 backend bucket key encrypt=true dynamodb_table successfully initialized release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; terraform-staging-plan staging artifact Terraform Plan: aws_eks_cluster aws_eks_node_group aws_rds_cluster aws_elasticache_replication_group aws_ecr_repository kubernetes_deployment kubernetes_ingress_v1 kubernetes_horizontal_pod_autoscaler_v2 kubernetes_pod_disruption_budget_v1 kubernetes_manifest aws_iam_role release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; terraform-staging-apply-or-approval staging artifact deployment approval approved DEPLOY-TF-001 change_ticket=PLATFORM-123 release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123 distinct_terraform_artifacts=true'
      : id === 'DEPLOY-TLS-001'
        ? tlsSummary('0123456789abcdef0123456789abcdef01234567')
      : id === 'DEPLOY-K8S-001'
        ? 'DEPLOY-K8S-001 deploymentprobe passed: kubernetes-rollout-status staging artifact namespace staging deployment scriptureforge-api scriptureforge-web scriptureforge-rust-engine successfully rolled out ready available release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; kubernetes-workload-resources staging artifact namespace staging deployment service ingress hpa pdb ready available targets minavailable readinessProbe livenessProbe rollingUpdate maxUnavailable=0 minReplicas maxReplicas tls SecretProviderClass image scriptureforge-api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa scriptureforge-web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb scriptureforge-rust-engine@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123 scriptureforge-api scriptureforge-web scriptureforge-rust-engine distinct_kubernetes_artifacts=true'
      : id === 'EXT-ZOOM-001'
        ? 'EXT-ZOOM-001 zoomprobe passed: zoom-oauth-readiness staging artifact oauth account_credentials status ok release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; zoom-meeting-create-or-fallback staging artifact meeting join_url zoom.us release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; zoom-timeout-circuit-fallback staging artifact timeout provider timeout circuit open circuit_open_fallback fallback offline://in-person provider_timeout=true circuit_open=true offline_fallback=true release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; zoom-webhook-signature-delivery staging artifact webhook signature x-zm-signature=v0=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa x-zm-request-timestamp=1710000000 stale replay 401 invalid signed 200 release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; zoom-webhook-url-validation staging artifact endpoint.url_validation plain_token=zoom-plain-123 encrypted_token=zoom-encrypted-456 validation_response=200 release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; zoom-duplicate-webhook-idempotency staging artifact duplicate x-zm-trackingid=zm-track-123 delivery_id=zm-delivery-123 delivery id same Zoom event idempotent 200 single state mutation no duplicate side effects single_state_mutation=true no_duplicate_side_effects=true release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; zoom-meeting-room-mapping staging artifact meeting_external_id=zoom-123 live_rooms internal_room_id=room-abc redis room state mapped unknown meeting ignored no external meeting id fallback distinct_zoom_artifacts=true release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123'
      : id === 'EXT-AI-001'
        ? 'EXT-AI-001 aiprobe passed: ai-provider-config staging artifact AI_PROVIDER AI_CHAT_MODEL AI_CHAT_ENDPOINT AI_HTTP_TIMEOUT_MS AI_MAX_RETRIES OPENAI_API_KEY redacted configured AI_PROVIDER=openai AI_CHAT_MODEL=gpt-staging AI_CHAT_ENDPOINT=https://api.openai.com/v1/chat/completions AI_HTTP_TIMEOUT_MS=3500 AI_MAX_RETRIES=1 release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; ai-generation-route staging artifact /api/v1/ai/generate/study authenticated JWT claims organization_id=org-staging user_id=user-staging request_id=req-123 200 generated_curriculum [Genesis 1:1] release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; ai-timeout-degradation staging artifact provider timeout degradation retry exhausted 503 fail closed AI_ORCHESTRATION_ENGINE_FAULT provider_timeout=true retry_exhausted=true fail_closed=true release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; ai-citation-verification staging artifact no-citation rejected hallucinated citation rejected verified citation accepted citation_trails citation_id=cite-123 release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; ai-audit-persistence staging artifact ai_request_logs citation_trails organization_id=org-staging user_id=user-staging request_id=req-123 citation_id=cite-123 succeeded failed verified tenant rls cross-tenant hidden distinct_ai_artifacts=true release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123'
      : id === 'OBS-OTEL-001'
        ? 'OBS-OTEL-001 observabilityprobe passed: collector-otlp-config staging artifact receivers otlp 4317 4318 exporters service release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; api-prometheus-metrics staging artifact scriptureforge_http_requests_total scriptureforge_http_request_duration_seconds_sum scriptureforge_http_requests_total{ status= websocket_active_connections_count scriptureforge_dependency_operations_total{dependency="websocket",operation="room_broadcast",status="dropped" ai_inference_duration_seconds_sum ai_inference_duration_seconds_count scriptureforge_dependency_operations_total{dependency="rust_engine",operation="vector_search",status="success" scriptureforge_dependency_operation_duration_seconds_sum{dependency="rust_engine",operation="vector_search",status="success" release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; rust-prometheus-metrics staging artifact scriptureforge_rust_engine_embedding_requests_total scriptureforge_rust_engine_embedding_failures_total scriptureforge_rust_engine_vector_search_requests_total scriptureforge_rust_engine_vector_search_failures_total release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; trace-backend-search staging artifact trace_id=11112222333344445555666677778888 scriptureforge-api scriptureforge-rust-engine route=/api/v1/ai/generate/study method=POST release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; log-backend-trace-correlation staging artifact trace_id=11112222333344445555666677778888 trace_id scriptureforge-api scriptureforge-rust-engine route=/api/v1/ai/generate/study method=POST service_version deployment_environment tenant_id=org-staging user_id=user-staging role=admin distinct_otel_artifacts=true release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123'
      : id === 'OBS-ALERT-001'
        ? 'OBS-ALERT-001 observabilityprobe passed: dashboard-import staging artifact ScriptureForge scriptureforge_http_requests_total scriptureforge_http_request_duration_seconds_sum websocket_active_connections_count room_broadcast ai_inference_duration_seconds scriptureforge_rust_engine_ trace_id release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; alert-rules-loaded staging artifact ScriptureForgeHighErrorRate ScriptureForgeTrafficAbsent ScriptureForgeAuthFailureSpike ScriptureForgeAbuseLimitSpike ScriptureForgeRouteLatencyElevated ScriptureForgeDependencyFailures ScriptureForgeAIInferenceLatencyElevated ScriptureForgeJournalWriteFailures ScriptureForgeRoomStreamFailures ScriptureForgeRoomBroadcastDrops ScriptureForgeRustEngineFailures scriptureforge_http_requests_total scriptureforge_dependency_operations_total ai_inference_duration_seconds release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; alert-delivery-status staging artifact success alertname=ScriptureForgeHighErrorRate receiver=staging-release delivery_id=am-delivery-123 delivered test alert alertmanager release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; telemetry-retention-policy staging artifact retention 30 days trace logs metrics distinct_alert_artifacts=true release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123'
      : id === 'RUST-GRPC-001'
        ? 'RUST-GRPC-001 rustprobe passed: rust-grpc-health staging artifact grpc health scriptureforge.engine.ScriptureEngine SERVING release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-rust-engine:0123456789abcdef0123456789abcdef01234567 deployment_environment=staging load_run_id=load-run-123; rust-metrics staging artifact scriptureforge_rust_engine_embedding_requests_total scriptureforge_rust_engine_embedding_failures_total scriptureforge_rust_engine_vector_search_requests_total scriptureforge_rust_engine_vector_search_failures_total Prometheus metrics rust_metrics_samples_verified=true rust_embedding_requests_positive=true rust_vector_search_requests_positive=true release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-rust-engine:0123456789abcdef0123456789abcdef01234567 deployment_environment=staging load_run_id=load-run-123 embedding_requests=1 vector_search_requests=1; api-rust-integration-metrics staging artifact Go API rust_engine vector_search success scriptureforge_dependency_operations_total scriptureforge_dependency_operation_duration_seconds_sum api_rust_metrics_samples_verified=true distinct_metrics_targets=true release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-rust-engine:0123456789abcdef0123456789abcdef01234567 deployment_environment=staging load_run_id=load-run-123 api_rust_vector_search_ops=1 api_rust_vector_search_seconds=0.042'
      : id === 'CLIENT-MOBILE-001'
        ? 'CLIENT-MOBILE-001 mobileprobe passed: mobile-eas-or-device-run staging artifact eas build finished android ios native device installed app release channel staging expo profile staging mobile_build_id=mobile-build-123 platforms=android,ios release_channel=staging expo_profile=staging distinct_mobile_artifacts=true release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-mobile:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; mobile-native-crypto-smoke staging artifact runJournalCryptoSelfTest react-native-quick-crypto native provider native module loaded provider status react-native-quick-crypto provider=react-native-quick-crypto native-required true native_required=true mobile_build_id=mobile-build-123 AES-GCM round-trip unique_iv=true unique IV tamper rejected associated data wrong associated data rejected associated_data_salt_id=journal:self-test:server-derived-salt associated_data_salt_version=1 non-extractable provider-bound key fallback-derived key rejected key disposed disposed handle rejected revoked_key_rejected=true stale raw key rejected passphrase wiped passphrase buffer zeroized salt wiped salt buffer zeroized plaintext cleared plaintext buffer zeroized distinct_mobile_artifacts=true release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-mobile:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; mobile-staging-config staging artifact EXPO_PUBLIC_API_BASE_URL EXPO_PUBLIC_WS_BASE_URL EXPO_PUBLIC_REQUIRE_NATIVE_CRYPTO=true EXPO_PUBLIC_DEPLOYMENT_ENVIRONMENT=staging mobile_build_id=mobile-build-123 https:// wss:// staging EXPO_PUBLIC_API_BASE_URL=https://api.staging.scriptureforge.ai EXPO_PUBLIC_WS_BASE_URL=wss://api.staging.scriptureforge.ai distinct_mobile_artifacts=true release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-mobile:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123'
      : id === 'CLIENT-WEB-001'
        ? webClientSummary('0123456789abcdef0123456789abcdef01234567')
      : id === 'DATA-RLS-001'
        ? tenantRLSSummary('0123456789abcdef0123456789abcdef01234567')
      : id === 'SEC-SECRETS-001'
        ? 'SEC-SECRETS-001 securityprobe passed: irsa-service-account staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets eks.amazonaws.com/role-arn scriptureforge trust policy sts:AssumeRoleWithWebIdentity release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; secret-provider-class staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets SecretProviderClass secrets-store.csi.k8s.io provider aws objects objectName objectType secretsmanager objectAlias jmesPath secretObjects type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; synced-secret-metadata-redacted staging artifact namespace=staging scriptureforge-runtime-secrets type Opaque DATABASE_URL JWT_SECRET_KEY OPENAI_API_KEY ZOOM_WEBHOOK_SECRET_TOKEN redacted stringData absent managed by secrets-store.csi.k8s.io ownerReferences secrets-store.csi.k8s.io/managed=true release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; iam-secrets-policy staging artifact role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets secretsmanager:GetSecretValue secretsmanager:DescribeSecret arn:aws:secretsmanager: scoped resource no wildcard resources release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; scoped-secrets-access-test staging artifact namespace=staging service_account=scriptureforge-api role_arn=arn:aws:iam::123456789012:role/scriptureforge-app-secrets allowed configured secret denied unscoped secret AccessDenied distinct_secret_artifacts=true release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123'
      : id === 'SEC-DBUSER-001'
        ? 'SEC-DBUSER-001 securityprobe passed: database-scoped-user staging artifact connected as scriptureforge_app current_user=scriptureforge_app superuser=false bypassrls=false createrole=false createdb=false privileged_operation_denied=true app_grants_verified=true app_grant_tables=9 app_grant_table_names=organizations,users,scripture_texts,refresh_tokens,journal_entries,live_rooms,room_participants,ai_request_logs,citation_trails app_grants=SELECT,INSERT,UPDATE,DELETE release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123'
      : id === 'DR-ROLLBACK-001'
        ? 'DR-ROLLBACK-001 resilienceprobe passed: api-ready-before-rollback staging artifact ready service_version deployment_environment pre_rollback_version pre_rollback_version=release-1 release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; rollback-rollout-artifact staging artifact rollout undo revision previous_revision target_revision scriptureforge-api successfully rolled out release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; api-ready-after-rollback staging artifact ready service_version deployment_environment post_rollback_version post_rollback_version=release-0 rolled_back_from rolled_back_from=release-1 rolled_back_to rolled_back_to=release-0 release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; degradation-drill-artifact staging artifact AI Zoom degradation fallback AI_ORCHESTRATION_ENGINE_FAULT offline://in-person non-AI routes healthy zoom circuit open ai_fault=true zoom_offline_fallback=true non_ai_routes_healthy=true zoom_circuit_open=true distinct_rollback_artifacts=true release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123'
      : id === 'DR-BACKUP-001'
        ? 'DR-BACKUP-001 resilienceprobe passed: backup-snapshot-artifact staging artifact snapshot snapshot_id=snap-123 available encrypted kms retention automated backup source cluster rpo_minutes=15 release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; restore-drill-artifact staging artifact restore restore_job_id=restore-456 available staging restored endpoint source snapshot_id=snap-123 checksum isolated restore rto_minutes=30 restore_duration_minutes=18 release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; restored-database-smoke staging artifact smoke passed restored database tenant journal auth RLS migration version no plaintext journal distinct_backup_artifacts=true release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123'
      : id === 'ABUSE-LIMIT-001'
        ? abuseLimitSummary('0123456789abcdef0123456789abcdef01234567')
      : id === 'PERF-HTTP-001'
        ? 'PERF-HTTP-001 profile=staging_http min_rps=5000 max_p99_ms=200 production_target_rps=5000 production_target_p99_ms=200 production_min_duration_ms=60000 observed_rps=5200 observed_p99_ms=180 duration_ms=60000 duration_ms>=60000 threshold_pass=true http_replica_count=2 dependency_postgres_p99_ms=32 dependency_redis_p99_ms=18 release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123; verified markers: http_replica_artifact_verified, http_replica_count=2, dependency_telemetry_artifact_verified, dependency_latency_artifact_verified=true, dependency_postgres_p99_ms=32, dependency_redis_p99_ms=18, http_distinct_artifacts=true'
      : id === 'PERF-WS-001'
        ? 'PERF-WS-001 staging artifact profile=staging_websocket min_rps=500 max_p99_ms=200 production_target_rps=500 production_target_p99_ms=200 production_min_duration_ms=60000 production_min_ws_events=30000 duration_ms=60000 duration_ms>=60000 observed_rps=620 observed_p99_ms=140 ws_expected_events=30000 threshold_pass=true release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123 ws_origin=https://web.staging.scriptureforge.ai ws_room_id=room-1 ws_authenticated=true ws_polling_latest_sequence=30000 ws_sequence_contiguous=true ws_replica_count=2 room_broadcast_drops=0; verified markers: staging artifact, ws_replica_artifact_url=https://artifacts.staging.scriptureforge.ai/load/ws-replicas.txt, ws_replica_artifact_verified, ws_replica_count=2, ws_reconnect_artifact_url=https://artifacts.staging.scriptureforge.ai/load/ws-reconnect.txt, ws_reconnect_artifact_verified, ws_reconnect_sequence_continues=true, ws_polling_artifact_url=https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt, ws_polling_artifact_verified, ws_polling_artifact_latest_sequence_validated=true, ws_polling_artifact_latest_sequence_matches_run=true, redis_telemetry_artifact_url=https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt, redis_telemetry_artifact_verified, ws_distinct_artifacts=true, room_broadcast_drops=0'
      : id === 'DATA-REDIS-001'
        ? 'DATA-REDIS-001 staging artifact profile=staging_websocket release_candidate=0123456789abcdef0123456789abcdef01234567 service_version=scriptureforge-api:0123456789abcdef0123456789abcdef01234567 load_run_id=load-run-123 ws_room_id=room-1 production_min_ws_events=30000 ws_sequence_contiguous=true ws_expected_events=30000 ws_unique_sequences=30000 ws_min_sequence=1 ws_max_sequence=30000 ws_polling_latest_sequence=30000 ws_polling_artifact_url=https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt redis_telemetry_artifact_url=https://artifacts.staging.scriptureforge.ai/load/redis-telemetry.txt; verified markers: staging artifact, ws_polling_artifact_url=https://artifacts.staging.scriptureforge.ai/load/ws-polling.txt, redis_telemetry_artifact_verified, ws_polling_artifact_latest_sequence_validated=true, ws_polling_artifact_latest_sequence_matches_run=true, ws_distinct_artifacts=true, room_broadcast_drops=0'
      : id === 'SEC-SIGNOFF-001'
        ? 'threat model approval complete; security/dependency_risk_register.md#DRR-001 dependency risk decision reviewed; residual risk review complete; owner/security approval recorded; release risk signoff approved; release_candidate=0123456789abcdef0123456789abcdef01234567'
      : `${id} passed`,
  };
}

function ciReleaseEvidenceSummary(releaseCandidate) {
  return [
    'github-actions-release-run passed with uploaded ci-release-evidence artifact',
    `release_candidate=${releaseCandidate}`,
    `proof markers: ${ciReleaseEvidenceProofMarkers.join(', ')}`,
  ].join(' ');
}

function tlsSummary(releaseCandidate) {
  const release = `release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123`;
  return [
    'DEPLOY-TLS-001 stagingprobe passed: api-live /live HTTP 200',
    'api-ready /ready HTTP 200',
    'api-tls TLS certificate cert_not_after cert_hostname=api.staging.scriptureforge.ai cert_issuer=Amazon_RSA_2048_M02',
    'api-http-redirect HTTP HTTPS redirect',
    'web-root web root HTTP 200',
    'web-tls TLS certificate cert_not_after cert_hostname=app.staging.scriptureforge.ai cert_issuer=Amazon_RSA_2048_M02',
    'web-http-redirect HTTP HTTPS redirect',
  ].map((segment) => `${segment} ${release}`).join('; ');
}

function abuseLimitSummary(releaseCandidate) {
  const release = `release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123`;
  return [
    'ABUSE-LIMIT-001 abuseprobe passed: auth-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200',
    'auth-account-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200 account-scoped login account_scoped=true rotating forwarded client IP forwarded_client_ip_rotated=true',
    'auth-refresh-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200 refresh token refresh_token_scoped=true',
    'ai-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200',
    'journal-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200',
    'rooms-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200',
    'websocket-rate-limit staging artifact 429 after 2 attempts repeated_attempts_verified=true Retry-After=60 X-RateLimit-Limit=1 X-RateLimit-Remaining=0 X-RateLimit-Reset=1782403200 websocket upgrade websocket_upgrade=true',
    'config_artifact_verified=true',
    'config_artifact_summary ABUSE_LIMIT_AUTH_REQUESTS=2 ABUSE_LIMIT_AUTH_WINDOW_SECONDS=60 ABUSE_LIMIT_AUTH_ACCOUNT_REQUESTS=2 ABUSE_LIMIT_AUTH_ACCOUNT_WINDOW_SECONDS=60 ABUSE_LIMIT_AI_REQUESTS=2 ABUSE_LIMIT_JOURNAL_REQUESTS=2 ABUSE_LIMIT_ROOMS_REQUESTS=2 ABUSE_LIMIT_WEBSOCKET_REQUESTS=2 ABUSE_LIMIT_MAX_BUCKETS=1000 TRUST_PROXY_HEADERS=true X-Forwarded-For X-Real-IP redacted distinct_abuse_artifacts=true',
  ].map((segment) => `${segment} ${release}`).join('; ');
}

function tenantRLSSummary(releaseCandidate) {
  const release = `release_candidate=${releaseCandidate} service_version=scriptureforge-api:${releaseCandidate} load_run_id=load-run-123`;
  return [
    'DATA-RLS-001 tenantprobe passed: owner-create-encrypted-journal same-tenant journal write accepted encrypted journal created plaintext not returned plaintext-shaped journal payload denied malformed encrypted envelope rejected, journal_id=entry-1',
    'blocked-journal-tenant-override-write-denied cross-tenant journal write denied tenant override rejected',
    'owner-read-created-journal same-tenant journal read visible created journal returned, journal_id=entry-1',
    'owner-list-contains-created-journal same-tenant journal list visible created journal present, journal_id=entry-1',
    'blocked-read-created-journal cross-tenant journal read denied created journal hidden, journal_id=entry-1',
    'blocked-list-excludes-created-journal cross-tenant journal list hidden created journal absent, journal_id=entry-1',
    'owner-create-room same-tenant room write accepted room created, room_id=room-1',
    'blocked-room-tenant-override-write-denied cross-tenant room write denied tenant override rejected',
    'owner-active-rooms-contains-created-room same-tenant room list visible created room present, room_id=room-1',
    'blocked-active-rooms-excludes-created-room cross-tenant room list hidden created room absent, room_id=room-1',
    'owner-room-state same-tenant room state visible created room state returned, room_id=room-1',
    'blocked-room-state-denied cross-tenant room state denied created room state hidden, room_id=room-1',
    "database-rls-context-proof staging artifact current_user=scriptureforge_app non-superuser superuser=false bypassrls=false app.current_org_id app.current_org_id=11111111-1111-4111-8111-111111111111 current_setting('app.current_org_id') blocked_org_id=22222222-2222-4222-8222-222222222222 row_security=on FORCE ROW LEVEL SECURITY rls_tables_verified=9 rls_forced_tables=9 rls_policy_scope=app.current_org_id organizations users scripture_texts refresh_tokens journal_entries live_rooms room_participants ai_request_logs citation_trails same-tenant read visible cross-tenant read hidden cross-tenant write denied auth_refresh_session_rls=true auth_mfa_rls=true workspace_switch_tenant_match=true privileged_mfa_enrollment_rls=true ai_audit_rls=true generated_curriculum_audit_rls=true distinct_db_rls_artifact=true",
  ].map((segment) => `${segment} ${release}`).join('; ');
}

function webClientSummary(releaseCandidate) {
  const release = `release_candidate=${releaseCandidate} service_version=scriptureforge-web:${releaseCandidate} load_run_id=load-run-123`;
  return [
    'CLIENT-WEB-001 stagingprobe passed: web-root web root HTTP 200',
    'web-tls TLS certificate cert_not_after cert_hostname=app.staging.scriptureforge.ai cert_issuer=Amazon_RSA_2048_M02',
    'web-http-redirect HTTP HTTPS redirect',
    'web-auth-browser-smoke staging artifact login register authenticated https:// user_id=user-staging organization_id=org-staging distinct_web_artifacts=true',
    'web-journal-browser-smoke staging artifact journal encrypted save load plaintext absent associated data wrong associated data rejected user_id=user-staging organization_id=org-staging journal_id=journal-staging distinct_web_artifacts=true',
    'web-room-browser-smoke staging artifact room create select WebSocket connected user_id=user-staging organization_id=org-staging room_id=room-staging distinct_web_artifacts=true',
  ].map((segment) => `${segment} ${release}`).join('; ');
}
