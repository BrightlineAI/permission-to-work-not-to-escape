"""Combined Node import gate. Native effects require the manager's Linux host.

Reuse accepted fixture builders, not inherited test counts. Each case performs
new controller operations against both pinned native tools in separate projects.
Synthetic registry evidence is explicit; no model or external account is used.
"""
from fnmatch import fnmatchcase
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ptw import pnpm, pnpm_tool, yarn, yarn_tool
from ptw.policy import Invalid, digest, save
from ptw.supervisor import Supervisor
from ptw.workspace import Workspace, request
import test_product_pnpm as pnpm_fixtures
import test_product_yarn as yarn_fixtures


@unittest.skipUnless(os.environ.get('PTW_LINUX_TESTS') == '1',
                     'manager native Node import checks required')
class NodeImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = Path(tempfile.mkdtemp(prefix='ptw-node-import-'))
        print('NODE_IMPORT_EVIDENCE ' + str(cls.evidence), flush=True)
        source = Path(__file__).resolve().parents[1]
        paths = sorted((source / 'ptw').glob('*.py')) + [
            source / 'requirements.lock', Path(__file__),
            Path(pnpm_fixtures.__file__), Path(yarn_fixtures.__file__),
            source / 'tests/test_ecosystems.py', source / 'tests/test_packages.py',
            source / 'tests/test_product_ecosystems.py',
            source / 'scripts/product_ecosystems_acceptance.py'] + sorted(
                p for p in (source / 'examples/product-ecosystems/typescript').rglob('*')
                if p.is_file())
        save(cls.evidence / 'source.json', {
            str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in paths})
        cls.tools = {}
        for name, tool in (('pnpm', pnpm_tool), ('yarn', yarn_tool)):
            directory = cls.evidence / name
            directory.mkdir()
            cls.tools[name] = tool.provision(directory / 'tool')

    def fixture(self, manager, **options):
        fixture_type = (pnpm_fixtures.PnpmNativeTests if manager == 'pnpm'
                        else yarn_fixtures.YarnNativeTests)
        fixture = fixture_type('runTest')
        fixture._testMethodName = self._testMethodName
        fixture.evidence = self.evidence / manager
        fixture.tool = self.tools[manager]
        # Attach cleanup to the running case, so service/fixture cleanup errors
        # are reported by its real unittest result, including setup failures.
        fixture.addCleanup = self.addCleanup
        fixture.setUp()
        fixture.controller(**options)
        fixture.project_id = manager + '-fixture'
        fixture.project_root = fixture.repo if manager == 'pnpm' else fixture.stage
        fixture.read_inputs = pnpm.read_inputs if manager == 'pnpm' else yarn.read_inputs
        fixture.original = fixture.read_inputs(fixture.project_root)[0]
        with fixture.store.locked() as db:
            _, bundle = fixture.store.project(db, fixture.project_id)
            fixture.policy_hash = digest(bundle['policy'])
        save(fixture.root / 'reviewed-inputs.json', {
            n: hashlib.sha256(t.encode()).hexdigest() for n, t in fixture.original.items()})
        return fixture

    def install(self, fixture):
        result = fixture.controller_install()
        self.assertTrue(result['allowed'], result)
        return result['package_set']

    def command(self, fixture, identity, *, name='use', actor=None, event='use'):
        result = Workspace(fixture.store).request(
            (actor or fixture.actor)['token'], event,
            request('run', name, content=json.dumps({'package_sets': [identity]})))
        save(fixture.root / (event + '.json'), result)
        return result

    def assert_unchanged(self, fixture):
        self.assertEqual(fixture.read_inputs(fixture.project_root)[0], fixture.original)
        with fixture.store.locked() as db:
            _, bundle = fixture.store.project(db, fixture.project_id)
            self.assertEqual(digest(bundle['policy']), fixture.policy_hash)
        self.assertFalse((fixture.project_root / 'package-lock.json').exists())

    def assert_use(self, fixture, identity, *, event='use'):
        result = self.command(fixture, identity, event=event)
        self.assertTrue(result['allowed'], result)
        self.assertEqual(result['exit_code'], 0, result)
        self.assertEqual((fixture.project_root / 'dist/result.txt').read_text(),
                         'PROTECTED_' + fixture.specs['manager'].upper() + '_OK')
        self.assert_unchanged(fixture)

    def test_both_native_imports_preserve_authority_and_unrelated_work(self):
        pnpm_case, yarn_case = self.fixture('pnpm'), self.fixture('yarn')
        identities = [(f, self.install(f)) for f in (pnpm_case, yarn_case)]
        for fixture, identity in identities:
            self.assert_use(fixture, identity)
            self.assertEqual(fixture.store.status(fixture.project_id)['violations'], 0)
            self.assertFalse((fixture.project_root / 'root-build').exists())
            self.assertFalse((fixture.project_root / 'root-hook').exists())
        pnpm_case.store.stop(pnpm_case.project_id)
        Supervisor(pnpm_case.store).reconcile()
        self.assertFalse(self.command(pnpm_case, identities[0][1], event='after-stop')['allowed'])
        (yarn_case.project_root / 'dist/result.txt').unlink()
        self.assert_use(yarn_case, identities[1][1], event='unrelated-after-stop')
        self.assertFalse(yarn_case.store.status(yarn_case.project_id)['stopped'])

    def test_narrow_delegates_cannot_recover_cached_workspace_sources(self):
        for manager in ('pnpm', 'yarn'):
            with self.subTest(manager=manager):
                fixture = self.fixture(manager)
                identity = self.install(fixture)
                child = fixture.store.register(fixture.project_id, 'work',
                    parent_token=fixture.actor['token'], grants=fixture.narrow['grants'],
                    packages=fixture.narrow['packages'], commands=['narrow'])
                result = self.command(fixture, identity, name='narrow', actor=child)
                self.assertTrue(result['allowed'], result)
                self.assertEqual(result['exit_code'], 0, result)
                # The native command probes direct paths, lookup links and every
                # recorded cached copy, while still importing registry packages.
                self.assertEqual((fixture.project_root / 'dist/narrow.txt').read_text(),
                                 'SOURCE_DENIED_REGISTRY_OK')
                denied = fixture.controller_install(child, 'delegate-install')
                self.assertFalse(denied['allowed'], denied)
                self.assertFalse(self.command(fixture, identity, name='partial', event='partial')['allowed'])
                self.assertFalse((fixture.project_root / 'dist/leak.txt').exists())
                self.assertEqual(fixture.store.status(fixture.project_id)['violations'], 2)
                self.assert_unchanged(fixture)

    def test_manager_authority_and_package_sets_cannot_be_substituted(self):
        from ptw.packages import PackageControl
        left, right = self.fixture('pnpm'), self.fixture('yarn')
        left_set, right_set = self.install(left), self.install(right)
        for fixture, other, foreign_set, own_set in (
                (left, right, right_set, left_set), (right, left, left_set, right_set)):
            with self.subTest(manager=fixture.specs['manager']):
                published = set((fixture.store.directory / 'package-sets').iterdir())
                with self.assertRaises(Invalid):
                    PackageControl(fixture.store).install(fixture.actor['token'],
                        'foreign-authority', other.specs, ecosystem='npm')
                denied = self.command(fixture, foreign_set, event='foreign-set')
                self.assertFalse(denied['allowed'], denied)
                self.assertFalse((fixture.project_root / 'dist/result.txt').exists())
                self.assertEqual(set((fixture.store.directory / 'package-sets').iterdir()), published)
                self.assert_use(fixture, own_set, event='own-set')

    def test_unapproved_hooks_and_changed_inputs_never_publish(self):
        for manager in ('pnpm', 'yarn'):
            with self.subTest(manager=manager):
                options = ({'lifecycle': True} if manager == 'pnpm' else
                    {'script': 'node -e "require(\'fs\').writeFileSync(\'unapproved-build\',\'ran\')"'})
                fixture = self.fixture(manager, **options)
                denied = fixture.controller_install()
                self.assertFalse(denied['allowed'], denied)
                self.assertIn('explicit controller approval', denied['reason'])
                self.assertFalse(denied['violation_counted'])
                self.assertFalse(list(fixture.root.rglob('unapproved-build')))
                self.assert_unchanged(fixture)
                lock = fixture.project_root / ('pnpm-lock.yaml' if manager == 'pnpm' else 'yarn.lock')
                lock.write_bytes(lock.read_bytes() + b'\n')
                changed = lock.read_bytes()
                with self.assertRaisesRegex(Invalid, 'input changed'):
                    fixture.controller_install(event='changed-inputs')
                self.assertEqual(lock.read_bytes(), changed)
                self.assertFalse((fixture.store.directory / 'package-sets').exists())
                self.assertEqual(fixture.store.status(fixture.project_id)['violations'], 0)

    def test_explicit_dependency_builds_produce_protected_usable_output(self):
        for manager in ('pnpm', 'yarn'):
            with self.subTest(manager=manager):
                index = 'module.exports = require("./built.cjs")' + (' + 1;' if manager == 'pnpm' else ';')
                script = ('const fs=require("fs");'
                          'fs.writeFileSync("built.cjs","module.exports = 7;");'
                          'fs.writeFileSync("index.js",' + json.dumps(index) + ');')
                options = {'build_script': script} if manager == 'pnpm' else {'script': 'node -e ' + "'" + script + "'"}
                fixture = self.fixture(manager, approve_build=True, **options)
                identity = self.install(fixture)
                name = 'ptw-peer' if manager == 'pnpm' else 'ptw-value'
                built = fixture.store.directory / 'package-sets' / identity / 'node_modules' / name / 'built.cjs'
                self.assertEqual(built.read_text(), 'module.exports = 7;')
                self.assert_use(fixture, identity)
                self.assertFalse((fixture.project_root / 'root-build').exists())
                self.assertFalse((fixture.project_root / 'root-hook').exists())
                self.assertFalse((fixture.project_root / 'pnpmfile-ran').exists())

    def test_real_typescript_compiles_and_executes_under_npm_policy(self):
        # Reuse the existing example and real public compiler, including ordinary
        # setup, broker installation, protected editing and reviewed commands.
        # The driver's approval stub applies only to this synthetic project.
        source = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location('node_import_journey',
            source / 'scripts/product_ecosystems_acceptance.py')
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        attempt = self.evidence / self._testMethodName
        from ptw.npm import NpmEvidence
        packument = NpmEvidence.packument
        requested = []

        def observed_packument(provider, name):
            requested.append(name)
            return packument(provider, name)

        try:
            # Observe actual public metadata requests without replacing evidence.
            # A fresh resolver must not request npm for its update notification.
            with patch.object(NpmEvidence, 'packument', observed_packument):
                result = driver.journey(attempt, 'existing-typescript')
            self.assertEqual(set(requested), {'typescript'})
            self.assertTrue(result['passed'], result)
            self.assertTrue(result['unrelated_process_alive_after_stop'])
            self.assertEqual(len(result['installs']), 1)
            self.assertTrue(result['installs'][0]['allowed'])
            self.assertTrue(all(c['result']['allowed'] and c['result']['exit_code'] == 0
                                for c in result['commands']))
            self.assertTrue(any('TYPESCRIPT_BUILD_OK 42' in c['result']['output']
                                for c in result['commands']))
            self.assertFalse(result['denial']['allowed'])
            repo = attempt / 'repo'
            manifest = json.loads((repo / 'package.json').read_text())
            self.assertEqual(manifest, json.loads(
                (source / 'examples/product-ecosystems/typescript/package.json').read_text()))
            lock = json.loads((repo / 'package-lock.json').read_text())
            compiler = lock['packages']['node_modules/typescript']
            self.assertEqual(compiler['version'], manifest['devDependencies']['typescript'])
            self.assertTrue(compiler['integrity'].startswith('sha512-'))
            self.assertEqual(compiler['resolved'],
                'https://registry.npmjs.org/typescript/-/typescript-5.8.3.tgz')
            self.assertIn('TYPESCRIPT_BUILD_OK 42', (repo / 'dist/app.js').read_text())
        except Exception as exc:
            # Also retain setup failures, which precede the driver's journey.json.
            save(attempt / 'failure.json', {'error_type': type(exc).__name__, 'error': str(exc)})
            raise
        finally:
            save(attempt / 'metadata-requests.json', requested)
            repo = attempt / 'repo'
            save(attempt / 'artifact-hashes.json', {
                str(p.relative_to(repo)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in (repo / 'package.json', repo / 'package-lock.json',
                          repo / 'src/app.ts', repo / 'dist/app.js') if p.is_file()})


# Retain the accepted adapters' security oracles verbatim. Explicit selections
# keep this integration gate bounded and make every regression independently
# selectable by the manager; no inherited test counts or fake native results.
REGRESSIONS = {
    'test_product_ecosystems.NpmResolutionTests': (
        'test_npm_critical_newest_uses_original_ranges_and_exclusions',
        'test_npm_exact_pin_conflict_and_frozen_lock',
        'test_npm_evidence_failure_and_budget_do_not_become_safe',
        'test_npm_metadata_error_rejects_successful_native_exit',
        'test_npm_binds_inputs_lock_and_artifact_origin',
    ),
    'test_product_pnpm.PnpmAdmissionTests': (
        'test_source_traversal_symlink_and_competing_authority_are_rejected',
        'test_frozen_ranges_origin_and_integrity_remain_bound',
        'test_critical_young_and_unavailable_evidence_fail_without_install',
        'test_file_directory_copies_reject_extra_bytes_and_wrong_locked_source',
    ),
    'test_product_pnpm.PnpmNativeTests': (
        'test_native_file_directory_import_and_all_cached_source_copies_are_confined',
        'test_native_stale_lock_fails_without_repair',
        'test_native_missing_store_cannot_download_or_run_hooks',
        'test_native_corrupt_store_cannot_supply_frozen_install',
        'test_native_malformed_lock_is_not_ignored',
        'test_native_exact_locked_targets_and_peer_context_substitution',
        'test_native_reviewed_resolution_excludes_critical_young_and_preserves_ranges',
        'test_native_reviewed_resolution_exact_pin_outage_and_budget_fail_closed',
        'test_native_setup_requires_explicit_dependency_build_review',
        'test_native_revision_terminal_retains_grants_history_and_revokes_sessions',
        'test_native_revision_concurrent_edit_preserves_current_policy_and_session',
        'test_native_revision_failed_publication_recovers_without_reopening_sessions',
        'test_native_authenticated_registry_build_and_credential_confinement',
        'test_controller_failed_approved_build_has_no_publication',
        'test_controller_approved_build_cannot_export_escape',
        'test_controller_approved_build_cannot_shadow_nested_dependency',
    ),
    'test_product_yarn.YarnToolTests': (
        'test_original_metadata_and_sources_reject_escapes_and_competing_authorities',
        'test_public_origin_binding_preserves_urls_and_authenticated_routes_stay_exact',
    ),
    'test_product_yarn.YarnNativeTests': (
        'test_controller_protected_directory_copy_and_narrow_cached_denial',
        'test_missing_artifact_fails_without_network_or_install',
        'test_corrupted_artifact_fails_without_cache_repair',
        'test_stale_lock_fails_without_rewriting_original_range',
        'test_malformed_lock_is_rejected_without_install',
        'test_default_public_origin_frozen_import_and_protected_install',
        'test_default_public_origin_reviewed_update_and_protected_use',
        'test_controller_approved_builds_follow_dependency_order',
        'test_controller_policy_rejects_critical_young_and_missing_evidence',
        'test_native_reviewed_resolution_excludes_critical_young_and_preserves_ranges',
        'test_native_reviewed_resolution_exact_pin_outage_and_budget_fail_closed',
        'test_native_terminal_setup_review_rejection_eof_and_protected_build',
        'test_native_revision_terminal_retains_grants_history_and_revokes_sessions',
        'test_native_revision_concurrent_edit_preserves_current_policy_and_session',
        'test_native_revision_failed_publication_recovers_without_reopening_sessions',
        'test_native_authenticated_registry_build_and_credential_confinement',
        'test_controller_failed_approved_build_has_no_publication',
        'test_controller_build_export_escape_rejected',
        'test_controller_build_shadowing_rejected',
    ),
    'test_product_ecosystems.WorkspaceSourceTests': (
        'test_native_npm_workspace_lock_is_local_not_registry',
        'test_workspace_path_link_and_manifest_mutation_rejected',
        'test_sibling_file_dependency_and_origin_confusion',
        'test_file_source_parent_symlink_cannot_read_external_metadata',
        'test_native_narrower_workspace_import_and_excluded_source',
    ),
}


def load_tests(loader, tests, pattern):
    for case, methods in REGRESSIONS.items():
        # These owners are sibling modules with ordinary discovery. Let them
        # supply their cases when selected by the enclosing filename pattern.
        # Named loading (pattern=None) and the standalone gate retain all cases.
        if pattern is not None and fnmatchcase(case.split('.')[0] + '.py', pattern):
            continue
        tests.addTests(loader.loadTestsFromNames([case + '.' + name for name in methods]))
    return tests


if __name__ == '__main__':
    unittest.main()
