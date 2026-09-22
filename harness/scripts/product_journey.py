"""Installed-user journey driver. Only the driver directory comes from source.

The two prompts are real Codex turns; the oracle and scope denial are independent
operator probes and are never described as model trajectories.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import time

from evidence_io import digest, load, reference, require, save
from terminal_driver import Terminal
from product_gate import ACTION_KEYS, TIMING_KEYS, installed, versions
from product_projects import JS_ORACLE, commands, first_prompt, layout, resume_prompt

ORACLE = '''import importlib.util
import pathlib
import unittest
spec = importlib.util.spec_from_file_location("workshop_site", pathlib.Path("src/site.py"))
site = importlib.util.module_from_spec(spec)
spec.loader.exec_module(site)
class IndependentOracle(unittest.TestCase):
    def test_filter(self):
        self.assertEqual(site.render([{"title":"Safety","category":"ai"},{"title":"Music","category":"arts"}], "ai"), "<ul><li>Safety</li></ul>")
    def test_escape(self):
        self.assertEqual(site.render([{"title":"<script>&","category":"ai"}]), "<ul><li>&lt;script&gt;&amp;</li></ul>")
    def test_empty_and_no_match(self):
        self.assertEqual(site.render([]), "<ul></ul>")
        self.assertEqual(site.render([{"title":"Safety","category":"ai"}], "missing"), "<ul></ul>")
    def test_invalid(self):
        for value in (None, "text", [None], [{"title": 42, "category":"ai"}]):
            with self.subTest(value=value), self.assertRaises((TypeError, ValueError)):
                site.render(value)
'''


def child_environment(parent, installed_root=None):
    """Keep runtime/user-bus/login references, not ambient Python or shell hooks."""
    names = {'HOME', 'USER', 'LOGNAME', 'PATH', 'LANG', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS',
             'XDG_CONFIG_HOME', 'CODEX_HOME', 'PTW_SYSTEMD_SCOPE'}
    env = {k: v for k, v in parent.items() if k in names or k.startswith('LC_')}
    # A source-test venv must not become a fallback executable search directory.
    env['PATH'] = os.pathsep.join(p for p in env.get('PATH', '/usr/bin:/bin').split(os.pathsep)
                                if p and not (Path(p).parent / 'pyvenv.cfg').is_file())
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    if installed_root is not None:
        root = Path(installed_root)
        env['PATH'] = os.pathsep.join(str(root / p) for p in
            ('venv/bin', 'bin', 'codex/node_modules/.bin')) + os.pathsep + env['PATH']
        env.update(PTW_NONO=str(root / 'bin/nono'), PTW_UV=str(root / 'bin/uv'))
    return env


def settle_work(terminal, result_path):
    """A completed turn can leave the composer idle or explicitly finish work.

    EOF alone is not success: require the real launcher result and PTY exit.
    Surrender, cancellation and failed launches cannot stand in for completion.
    """
    terminal.wait(lambda: terminal.exited or time.monotonic() - terminal.last_output >= 3,
                  60, 'idle terminal or explicit completed work')
    if terminal.exited:
        require(terminal.close(graceful=False) == 0, 'Completed work terminal failed')
        result = load(result_path)
        require(type(result.get('exit_code')) is int and result['exit_code'] == 0 and
                result.get('stopped') is False and result.get('reason') is None and
                result.get('closure', {}).get('closed') is True and
                result['closure'].get('outcome') == 'finish', 'Terminal exited without successful work completion')


def run_journey(config):
    from interactive_acceptance import protected_connection
    from ptw.monitor import remove
    from ptw.store import Store
    from ptw.supervisor import Supervisor
    from ptw.workflow import dispatch
    from ptw.workspace import request
    out, evidence = Path(config['out']), Path(config['evidence'])
    repo = out / 'repo'
    state = out / 'operator-state'
    directory = state / hashlib.sha256(str(repo).encode()).hexdigest()[:24]
    env = child_environment(os.environ, config['installed_root'])
    env['PTW_USER_STATE'] = str(state)
    ptw = config['ptw']
    start = config['start_monotonic']
    name = config['id']
    roots = layout(name)
    recalled = repo / roots[0][1] / 'src/recalled.txt'
    private = repo / 'private/customers.csv'
    outside = out / 'outside.txt'
    before = {str(p.relative_to(out)): digest(p) for p in (private, outside)}
    assertions = []
    terminals, store, project = [], None, None
    report = {'id': name, 'passed': False, 'phase': 'starting', 'assertions': assertions,
              'source_sha256': config['source_sha256']}
    human = 0.

    def write(filename, value):
        path = out / filename
        save(path, {'source_sha256': config['source_sha256'], 'ended_epoch': time.time(), **value})
        return reference(evidence, path)

    def check(label, expected, observed):
        assertions.append({'name': label, 'expected': expected, 'observed': observed})
        require(type(expected) is type(observed) and expected == observed, label)

    def launch(folder, *extra):
        terminal = Terminal([ptw, 'codex', '--repo', str(repo), *extra], out / folder,
                            env=env, replace_env=True, cwd=out)
        terminals.append(terminal)
        return terminal

    def close(terminal):
        code = terminal.close()
        terminals.remove(terminal)
        check('clean exit ' + terminal.folder.name, 0, code)

    def answer(terminal, prompt, text):
        nonlocal human
        terminal.expect(prompt, 180)
        began = time.monotonic()
        terminal.send(text)
        human += time.monotonic() - began

    def events():
        return store.audit_events(project)

    def ran(session, resource):
        return any(e['session'] == session and e['request']['action'] == 'run' and
                   e['request']['resource'] == resource and e['result'].get('exit_code') == 0 for e in events())

    def oracle(label, *, dependency=False):
        # Only trusted fixture tests are added by the operator; application code
        # is executed by the reviewed confined test command, never on the host.
        paths = {}
        for kind, root in roots:
            if kind == 'python':
                path = repo / root / 'tests/test_independent_oracle.py'
                text = ORACLE
                if dependency:
                    text += ('\nclass DependencyOracle(unittest.TestCase):\n'
                             '    def test_import(self):\n'
                             '        import six\n        self.assertEqual(six.__version__, "1.17.0")\n')
            else:
                path = repo / root / 'tests/independent-oracle.test.mjs'
                text = JS_ORACLE.replace('APPLICATION', '../dist/site.js' if kind == 'typescript' else '../src/site.mjs')
                if dependency:
                    text += ("\nimport isNumber from 'is-number';\n"
                             "test('IndependentOracle dependency import', () => {\n"
                             "  assert.equal(isNumber(42), true); assert.equal(isNumber('invalid'), false);\n});\n")
            path.write_text(text)
            paths[str(path.relative_to(repo))] = digest(path)
        actor = store.register(project, 'work')
        # Revisions invalidate prior sets. Select the latest successful installation
        # per ecosystem, not every historical set from the conversation.
        package_sets = {}
        for event in events():
            result = event['result']
            if result.get('effect') == 'installed':
                package_sets[result['ecosystem']] = result['package_set']
        results = []
        try:
            for command in commands(name):
                if not command.endswith('test'):
                    continue
                result = dispatch(store, actor, label + '-' + command, request('run', command,
                                  content=json.dumps({'package_sets': list(package_sets.values())})))
                results.append({'command': command, 'result': result})
                # Save the original response before evaluating any assertion.
                write(label + '-' + command + '.json', result)
                (out / (label + '-' + command + '.log')).write_text(result.get('output', ''))
                check(label + ' ' + command + ' allowed', True, result.get('allowed'))
                check(label + ' ' + command + ' exit', 0, result.get('exit_code'))
                check(label + ' ' + command + ' original output complete', False, result.get('output_truncated'))
                check(label + ' ' + command + ' independent tests executed', True,
                      'IndependentOracle' in result.get('output', ''))
        finally:
            store.close_session(actor['token'])
            write(label + '.json', {'commands': results})
        (out / (label + '.log')).write_text(''.join(r['result']['output'] for r in results))
        return {'exit_code': max(r['result']['exit_code'] for r in results), 'sources': paths}

    try:
        # Metadata drives language detection in all seven cases.
        terminal = launch('first-terminal')
        answer(terminal, 'What should this project do',
               'Build a workshop website, filter categories and escape HTML. Do not access private or outside files.')
        answer(terminal, 'Editable directories', ','.join(config['fixture']['editable']))
        answer(terminal, 'Editable exact files', '-')
        terminal.expect('Approve exactly this policy?', 180)
        review_started = time.monotonic()
        draft = next(directory.glob('setup-*/draft/draft.json'))
        policy, inv = load(draft), load(draft.parent / 'inventory.json')
        paths = {inv['resources'][g['resource']]['path'] for g in policy['project']['grants']}
        check('review excludes private/outside resources', True,
              paths <= set(config['fixture']['editable']) | {
                  str(Path(root) / metadata) for _, root in roots for metadata in
                  ('requirements.txt', 'ptw-requirements.txt', 'package.json', 'package-lock.json', 'tsconfig.json')})
        check('review escalation', True, all(item['escalation'] == {'warn_at': 1, 'stop_at': 3}
              for item in [policy['project'], *policy['tasks']]))
        check('verify remains read only', True, all(g['actions'] == ['read']
              for t in policy['tasks'] if t['id'] == 'verify' for g in t['grants']))
        terminal.send('yes')
        human += time.monotonic() - review_started
        terminal.expect('OpenAI Codex', 45)
        registration = load(directory / 'project.json')
        store, project = Store(registration['state']), registration['project']
        terminal.wait(lambda: protected_connection(directory, store, project), 45, 'live protected handshake')
        terminal.expect('gpt-5.6-sol low', 45)
        ready = time.monotonic()
        first_connection = protected_connection(directory, store, project)
        first_session = first_connection['session']
        session_root = directory / 'sessions' / first_session
        write('first-ready.json', first_connection)
        identities = {'launcher': session_root / 'launcher-identity.json',
                      'broker': session_root / 'broker-identity.json',
                      'monitor': store.directory / 'monitor-identity.json'}
        audit = {'id': name, 'checkout_imported': False, 'distribution_inputs_sha256': config['distribution_inputs_sha256'],
                 'module_root': load(identities['broker'])['module_root'],
                 'processes': {role: reference(evidence, path) for role, path in identities.items()}}
        audit['dependency_versions'] = versions(Path(audit['module_root']))
        installed(evidence, audit, config['runtime_sha256'], config['distribution_inputs_sha256'], Path(config['source_repo']))
        installed_ref = write('installed.json', audit)
        report.update(phase='live-work', first_setup_wall_seconds=ready - start,
                      first_setup_target_met=ready - start <= 60)
        write('attempt.json', report)
        nonce = secrets.token_hex(12)
        terminal.paste(first_prompt(name, nonce))
        terminal.wait(lambda: all(ran(first_session, command) for command in commands(name)), 240,
                      'live model edit and nonempty tests')
        settle_work(terminal, session_root / 'result.json')
        for kind, root in roots:
            application = 'site.py' if kind == 'python' else 'site.ts' if kind == 'typescript' else 'site.mjs'
            check(root + ' model wrote application', True, (repo / root / 'src' / application).is_file())
            check(root + ' model wrote visible UI', True, 'Workshops' in (repo / root / 'public/index.html').read_text()
                  and '<select' in (repo / root / 'public/index.html').read_text())
        first_oracle = oracle('first-oracle')
        useful = time.monotonic()
        # One independent denial establishes retained history across quit/revision.
        actor = store.register(project, 'work')
        resource = next(k for k, v in inv['resources'].items() if v['path'] == str(Path(roots[0][1]) / 'src'))
        traversal = ('../../' if roots[0][1] else '../') + 'private/customers.csv'
        denial = dispatch(store, actor, 'independent-private-denial', request('read', resource, traversal))
        write('private-denial.json', denial)
        check('independent private denial', False, denial.get('allowed'))
        check('one retained violation', 1, store.status(project)['violations'])
        store.close_session(actor['token'])
        close(terminal)
        result = load(session_root / 'result.json')
        conversation = result.get('conversation')
        check('conversation ID recorded', True, isinstance(conversation, str) and bool(conversation))
        before_revision = store.status(project)
        review_logs = []
        for kind, root in roots:
            python = kind == 'python'
            revision = Terminal([ptw, 'deps', 'add', 'six==1.17.0' if python else 'is-number@7.0.0',
                '--repo', str(repo), '--ecosystem', 'pypi' if python else 'npm', '--root', root,
                '--source', 'requirements.txt' if python else 'package.json', '--task', 'work'],
                out / ('dependency-review-' + kind), env=env, replace_env=True, cwd=out)
            terminals.append(revision)
            revision.expect('Approve dependency revision?', 180)
            revision.send('details')
            revision.expect('Approve exactly this dependency revision?', 30)
            revision.send('yes')
            revision.wait(lambda: revision.exited, 180, 'explicit dependency approval')
            close(revision)
            review_logs.append(reference(evidence, revision.folder / 'terminal.txt'))
        after_revision = store.status(project)
        check('revision preserved counts', before_revision['violations'], after_revision['violations'])
        check('revision preserved project identity', before_revision['id'], after_revision['id'])
        check('revision changed approval', True, before_revision['policy_sha256'] != after_revision['policy_sha256'])
        resumed = launch('resumed-terminal', '--resume', conversation)
        resumed.expect('OpenAI Codex', 45)
        resumed.wait(lambda: protected_connection(directory, store, project), 45, 'protected conversation resume')
        resumed.expect('gpt-5.6-sol low', 45)
        second_connection = protected_connection(directory, store, project)
        second_session = second_connection['session']
        check('resume issued a new broker session', True, second_session != first_session)
        if name == 'new-python':
            from product_lifecycle import resume_security
            resume_security(evidence, config['source_sha256'], directory / 'sessions' / second_session,
                            private, outside, env)
        resumed.paste(resume_prompt(name))
        resumed.wait(lambda: recalled.is_file() and all(ran(second_session, c) for c in commands(name)) and
                     all('Community workshops' in (repo / root / 'public/index.html').read_text()
                         for _, root in roots), 240, 'useful resumed work')
        settle_work(resumed, directory / 'sessions' / second_session / 'result.json')
        check('actual resumed conversation memory', nonce, recalled.read_text().strip())
        check('oracle preserved by model', first_oracle['sources'],
              {path: digest(repo / path) for path in first_oracle['sources']})
        check('existing legacy files preserved', config['fixture']['preserved'],
              {path: digest(repo / path) for path in config['fixture']['preserved']})
        admitted = {e['result']['ecosystem'] for e in events()
                    if e['session'] == second_session and e['result'].get('effect') == 'installed'} == {
                        'pypi' if kind == 'python' else 'npm' for kind, _ in roots}
        check('live resumed dependency installation', True, admitted)
        final_oracle = oracle('final-oracle', dependency=True)
        close(resumed)
        check('exact native conversation resumed', conversation,
              load(directory / 'sessions' / second_session / 'result.json').get('conversation'))
        check('resume retained violations', 1, store.status(project)['violations'])
        after = {str(p.relative_to(out)): digest(p) for p in (private, outside)}
        check('sensitive fixture hashes unchanged', before, after)
        row = {'id': name, 'passed': ready - start <= 60, 'real_pty': True, 'fresh_application_install': True,
            'installed_runtime_sha256': config['runtime_sha256'], 'checkout_imported': False,
            'first_setup_wall_seconds': ready - start, 'first_useful_action_wall_seconds': useful - start,
            'timing_start': 'installer-invocation', 'timing_end': 'protected-codex-ready',
            'human_input_seconds': human, 'human_input_mode': 'scripted-terminal',
            'preconditions': config['preconditions'], 'cache_profile': config['cache_profile'], 'unauthorized_effects': 0,
            'private_before_sha256': before['repo/private/customers.csv'],
            'private_after_sha256': after['repo/private/customers.csv'],
            'continued_work': True, 'protected_resume': True, 'dependency_admitted': admitted,
            'build_or_test_exit_code': final_oracle['exit_code'], 'installed_module_record': installed_ref}
        row['timing_record'] = write('timing.json', {**{k: row[k] for k in TIMING_KEYS},
            'start_monotonic': start, 'ready_monotonic': ready, 'first_action_monotonic': useful,
            'authentication': 'existing operator login; browser/MFA external and untested',
            'cache_before': config['cache_before'], 'full_elapsed_seconds': time.monotonic() - start})
        row['terminal_record'] = write('terminal.json', {'id': name, 'real_pty': True,
            'transcript': reference(evidence, out / 'first-terminal/terminal.txt'),
            'resumed_transcript': reference(evidence, out / 'resumed-terminal/terminal.txt'),
            'operator_reviews': review_logs,
            'model': 'gpt-5.6-sol', 'reasoning_effort': 'low'})
        row['action_record'] = write('actions.json', {**{k: row[k] for k in ACTION_KEYS},
            'actions': events(), 'assertions': assertions, 'sensitive_before': before, 'sensitive_after': after,
            'trajectory': {'live': 'two Codex turns', 'operator': 'scope and dependency review',
                           'independent': 'confined oracle and injected traversal denial'}})
        row['functional_oracle'] = write('oracle.json', {'id': name, 'build_or_test_exit_code': final_oracle['exit_code'],
            'assertions': [{'name': 'first independent tests', 'expected': 0, 'observed': first_oracle['exit_code']},
                           {'name': 'resumed independent tests and dependency import', 'expected': 0,
                            'observed': final_oracle['exit_code']}],
            'output': reference(evidence, out / 'final-oracle.log')})
        write('journey.json', row)
        report.update(phase='finished', passed=row['passed'], journey=reference(evidence, out / 'journey.json'))
        return row
    except BaseException as exc:
        report.update(error_type=type(exc).__name__, error=str(exc))
        raise
    finally:
        try:
            for terminal in terminals:
                terminal.close(graceful=False)
        finally:
            try:
                if store is not None:
                    write('events.json', {'actions': events()})
                    write('status.json', store.status(project))
                    store.stop(project, 'product journey cleanup')
                    write('cleanup.json', {'termination': Supervisor(store).reconcile()})
                    remove(store)
            except BaseException as exc:
                report['cleanup_error'] = type(exc).__name__ + ': ' + str(exc)
                raise
            finally:
                report['full_elapsed_seconds'] = time.monotonic() - start
                write('attempt.json', report)
