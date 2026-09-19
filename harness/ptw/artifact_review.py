"""Bounded checkpoint packets. Findings are analysis, never authority.

The controller owns these records; repository text and command output cannot
choose requirements, manufacture receipts, or change the publication decision.
"""
import hashlib
import json
from pathlib import PurePosixPath
import re
import sqlite3

from .policy import Invalid, canonical, digest, load, obj, save, validate
from .workspace_policy import relative

HISTORY_LIMIT = 2048
INPUT_VERSION = 3
RESULT_BYTES = 256 * 1024
REVIEWER = {'kind': 'manual', 'configuration': 'local-terminal-v1',
            'provenance': 'operator inspection; no model detection claim'}
CODEX_REVIEWER = {'kind': 'codex', 'configuration': 'read-only-sequence-v1',
    'model': 'gpt-5.6-sol', 'effort': 'low', 'version': 'codex-cli 0.154.0',
    'input_bytes': 4 * 1024 * 1024, 'output_bytes': RESULT_BYTES, 'seconds': 120,
    'provenance': 'untrusted optional analysis; never approval'}
RESULT_SCHEMA = obj({
    'schema': {'type': 'integer', 'const': 1},
    'input_sha256': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'},
    'reviewer': {'enum': [REVIEWER, CODEX_REVIEWER]},
    'state': {'enum': ['no_findings', 'suspected', 'incomplete']},
    'findings': {'type': 'array', 'maxItems': 32, 'items': obj({
        'id': {'type': 'string', 'pattern': '^[a-z0-9-]{1,64}$'},
        'text': {'type': 'string', 'minLength': 1, 'maxLength': 4096},
    })},
})
# A candidate-only finding has no event references. Sequence findings may name
# only retained original operations, never reviewer-invented authority.
RESULT_SCHEMA['properties']['findings']['items']['properties']['events'] = {
    'type': 'array', 'maxItems': 32, 'uniqueItems': True,
    'items': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'}}


def input_files(snapshot):
    return {p: {'sha256': hashlib.sha256(e['data']).hexdigest(),
                'mode': '100755' if e['mode'] & 0o111 else '100644'}
            for p, e in snapshot.items() if e['kind'] == 'file'}


def input_directories(files, directories=()):
    """Directory layout materialize() produces, including implicit parents."""
    result = set(directories)
    for path in (*files, *directories):
        result.update(str(p) for p in PurePosixPath(path).parents if str(p) != '.')
    return sorted(result)


def in_resources(path, resources, inventory):
    return any(path == inventory['resources'][r]['path'] or
               (inventory['resources'][r].get('kind') == 'tree' and
                path.startswith(inventory['resources'][r]['path'] + '/')) for r in resources)


class History(list):
    """Bounded originals with an exact count, not an invented complete history."""
    def __init__(self, rows, total):
        super().__init__(rows)
        self.total = total


def history(store, db, project, session, event):
    # Keep original references and hashes, not a replacement prose summary.
    from .event_evidence import export_row
    store.project(db, project)
    query = (' FROM events e LEFT JOIN sessions s ON s.id=e.session '
             'WHERE (s.project=? OR e.session=?) AND NOT (e.session IS ? AND e.event IS ?)')
    params = (project, 'controller:' + project, session, event)
    total = db.execute('SELECT count(*)' + query, params).fetchone()[0]
    rows = db.execute('SELECT e.*,s.task' + query + ' ORDER BY e.rowid LIMIT ?',
                      (*params, HISTORY_LIMIT + 1))
    return History([export_row(r) for r in rows], total)


def references(rows):
    return [{'session': r['session'], 'event': r['event'], 'sha256': digest(r),
             'operation_id': r['audit']['operation_id'],
             'state': r['state'], 'action': r['request'].get('action'),
             'sequence': r['audit'].get('sequence'), 'task': r['task'],
             'actor_session': r['audit'].get('session'),
             'route': r['audit'].get('route'), 'coverage': r['audit'].get('coverage'),
             'decision': r['audit'].get('decision'), 'outcome': r['audit'].get('outcome'),
             'resource': r['request'].get('resource'), 'path': r['request'].get('path'),
             'content': r['audit'].get('content', 'omitted'),
             'content_sha256': r['request'].get('content_sha256'),
             'parent_session': r['audit'].get('parent_session'),
             'resume_of': r['audit'].get('resume_of'),
             'causes': r['audit'].get('causes', []),
             'policy_sha256': r['audit'].get('policy_sha256'),
             'authorization': r['audit'].get('authorization')}
            for r in rows]


def prior_evidence(store, rows, resources, gaps):
    prior_findings, finding_sources = [], []
    for row in rows[:HISTORY_LIMIT]:
        if row['request'].get('action') != 'checkpoint_findings':
            continue
        fact = row['audit']['details']
        # The immutable result is original evidence, not a worker summary.
        from .local_git import IDENTITY
        if not IDENTITY.fullmatch(fact['checkpoint']) or not re.fullmatch('[0-9a-f]{64}', fact['result_sha256']):
            raise Invalid('Malformed original finding reference')
        finding_sources.append({'checkpoint': fact['checkpoint'], 'sha256': fact['result_sha256']})
        path = store.directory / 'git-requests' / fact['checkpoint'] / ('findings-' + fact['result_sha256'] + '.json')
        try:
            original = load(path)
            if digest(original) != fact['result_sha256']:
                raise Invalid('Original finding evidence changed')
            if not set(original['resources']) <= set(resources):
                gaps.append({'reason': 'original finding context outside current read scope'})
                continue
            for finding in original['findings']:
                prior_findings.append({'id': 'prior-' + digest([fact['result_sha256'], finding['id']])[:40],
                                      'text': finding['text'],
                                      **({'events': finding['events']} if 'events' in finding else {})})
        except (OSError, ValueError):
            gaps.append({'reason': 'required original finding evidence missing or corrupt'})
    # A missing original must hold, never silently drop a previously raised concern.
    prior_findings = list({f['id']: f for f in prior_findings}.values())
    if len(prior_findings) > 32:
        gaps.append({'reason': 'required findings exceed bounded review limit'})
    return prior_findings[:32], finding_sources


def packet(store, db, actor, bundle, definition, result, event):
    candidate = result['candidate']
    config = definition['git'].get('review')
    gaps = list(candidate['gaps'])
    if config is None:
        gaps.append({'reason': 'legacy review configuration; explicit policy revision required'})
    else:
        for path in config['required_paths']:
            relative(path)
            if not in_resources(path, definition['resources'], bundle['inventory']):
                gaps.append({'path': path, 'reason': 'required context outside reviewed scope'})
            elif path not in candidate['files']:
                gaps.append({'path': path, 'reason': 'required context missing'})
    rows = history(store, db, actor['project'], actor['id'], event)
    if rows.total > HISTORY_LIMIT:
        gaps.append({'reason': 'required history exceeds bounded review limit'})
    if any(r['state'] != 'complete' or r['audit'].get('coverage') == 'legacy_unknown' for r in rows):
        gaps.append({'reason': 'required history incomplete or uncertain'})
    prior_findings, finding_sources = prior_evidence(store, rows, definition['resources'], gaps)
    commands = {c['id']: c for c in bundle['policy']['project']['commands']}
    facts = {p: {k: f[k] for k in ('sha256', 'mode')} for p, f in candidate['files'].items()}
    tests = []
    for name in (config or {}).get('tests', []):
        command = commands.get(name)
        if (command is None or 'git' in command or 'preview' in command or
                not set(command['resources']) <= set(definition['resources'])):
            gaps.append({'test': name, 'reason': 'required test inputs outside candidate review scope'})
            continue
        expected = {p: f for p, f in facts.items() if in_resources(p, command['resources'], bundle['inventory'])}
        directories = input_directories(expected)
        matches = [r for r in rows if r['request'].get('action') == 'run' and
                   r['request'].get('resource') == name]
        row = matches[-1] if matches else None
        response = json.loads(db.execute('SELECT response FROM events WHERE session=? AND event=?',
            (row['session'], row['event'])).fetchone()[0] or '{}') if row else {}
        binding = response.get('test_binding', {})
        valid = (row is not None and row['state'] == 'complete' and response.get('allowed') is True
                 and type(response.get('exit_code')) is int and response['exit_code'] == 0
                 and binding.get('schema') == 2 and binding.get('policy_sha256') == bundle['approval']['sha256']
                 and binding.get('definition_sha256') == digest(command) and binding.get('files') == expected
                 and binding.get('directories') == directories)
        if not valid:
            gaps.append({'test': name, 'reason': 'missing, failed or candidate-mismatched test receipt'})
        tests.append({'command': name, 'candidate_tree': candidate['tree'],
                      'candidate_inputs_sha256': digest({'files': expected, 'directories': directories}), 'matches': valid,
                      'receipt': references([row])[0] if row else None,
                      'binding': binding, 'exit_code': response.get('exit_code')})
    selected = references(rows[:HISTORY_LIMIT])
    from .sequence_review import INPUT_BYTES, sequence
    index = sequence(selected, rows.total, excluded=[digest([actor['id'], event])])
    gaps.extend(g for g in index['gaps'] if g not in gaps)
    inputs = {'schema': INPUT_VERSION, 'project': actor['project'], 'session': actor['id'],
            'preparation_event': event, 'policy_sha256': bundle['approval']['sha256'],
            'authority': {'producer': 'controller', 'grants_sha256': digest(json.loads(actor['grants'])),
                          'command_sha256': digest(definition)},
            'base': result['base'], 'candidate': candidate, 'configuration': config,
            'reviewer': REVIEWER, 'tests': tests,
            'prior_findings': prior_findings[:32],
            'finding_sources': finding_sources,
            'history': {'records': selected, 'total': rows.total, 'sha256': digest(selected),
                        'content': 'original scoped candidate; event payloads not reconstructed'},
            'sequence': index,
            'coverage': {'state': 'incomplete' if gaps else 'complete', 'gaps': gaps,
                         'opaque_entries': 'bound by full tree identity; not semantically reviewed',
                         'hidden_reasoning': 'unavailable'}}
    if len(canonical(inputs).encode()) > INPUT_BYTES:
        raise Invalid('Review input exceeds bounded byte limit; acceptance unavailable')
    return inputs


def initial_result(inputs):
    return {'schema': 1, 'input_sha256': digest(inputs), 'reviewer': REVIEWER,
            'state': ('incomplete' if inputs['coverage']['state'] != 'complete' else
                      'suspected' if inputs['prior_findings'] else 'no_findings'),
            'findings': inputs['prior_findings']}


def validate_result(review):
    inputs, result = review.get('review_input'), review.get('review_result')
    if not isinstance(inputs, dict) or inputs.get('schema') != INPUT_VERSION:
        raise Invalid('Missing versioned assembled review; prepare a fresh checkpoint')
    if 'sequence' not in inputs:
        raise Invalid('Missing bounded sequence review; prepare a fresh checkpoint')
    from .sequence_review import validate_sequence
    validate_sequence(inputs)
    validate(RESULT_SCHEMA, result)
    if len(canonical(result).encode()) > RESULT_BYTES:
        raise Invalid('Review result exceeds bounded byte limit')
    if result['input_sha256'] != digest(inputs) or result['reviewer'] != inputs['reviewer']:
        raise Invalid('Review result does not bind these exact inputs')
    if ((result['state'] == 'no_findings' and result['findings']) or
            (result['state'] == 'suspected' and not result['findings']) or
            len({f['id'] for f in result['findings']}) != len(result['findings'])):
        raise Invalid('Inconsistent review findings')
    originals = {r['operation_id'] for r in inputs['history']['records']}
    if any(set(f.get('events', ())) - originals for f in result['findings']):
        raise Invalid('Finding references unavailable original evidence')
    return inputs, result


def eligible(store, db, actor, bundle, definition, review, disposition=None):
    inputs, result = validate_result(review)
    if inputs['coverage']['state'] != 'complete' or inputs['coverage']['gaps'] or result['state'] == 'incomplete':
        raise Invalid('Checkpoint review incomplete; mandatory evidence cannot be waived')
    if (inputs['configuration'] != definition['git'].get('review') or
            inputs['authority']['command_sha256'] != digest(definition) or
            inputs['authority']['grants_sha256'] != digest(json.loads(actor['grants']))):
        raise Invalid('Review configuration, assumptions or authority changed')
    rows = history(store, db, actor['project'], actor['id'], inputs['preparation_event'])
    original = inputs['history']['records']
    if (references(rows[:len(original)]) != original or len(original) != inputs['history']['total']
            or rows.total > len(rows)):
        raise Invalid('Required original history changed or is missing')
    # New mutations/test executions may invalidate even a byte-restored candidate.
    harmless = {'read', 'list', 'git_status', 'git_diff', 'git_checkpoint', 'checkpoint_rejected'}
    def own_finding(row):
        facts = row['audit'].get('details', {})
        return (row['request'].get('action') == 'checkpoint_findings' and
                facts.get('checkpoint') == review['id'] and
                facts.get('result_sha256') in review['finding_records'])
    if any(r['state'] != 'complete' or (r['request'].get('action') not in harmless and not own_finding(r))
           for r in rows[len(original):]):
        raise Invalid('Relevant evidence changed since review; prepare a fresh checkpoint')
    sources = inputs['finding_sources'] + [{'checkpoint': review['id'], 'sha256': h} for h in review['finding_records']]
    for reference in sources:
        checkpoint, identity = reference['checkpoint'], reference['sha256']
        if not re.fullmatch('[0-9a-f]{32}', checkpoint) or not re.fullmatch('[0-9a-f]{64}', identity):
            raise Invalid('Malformed original finding reference')
        try:
            source = load(store.directory / 'git-requests' / checkpoint / ('findings-' + identity + '.json'))
            if digest(source) != identity:
                raise Invalid('Original finding evidence changed')
        except (OSError, ValueError) as exc:
            raise Invalid('Required original finding evidence missing or corrupt') from exc
    if result['findings'] and (not isinstance(disposition, str) or not disposition.strip()
                              or len(disposition) > 4096):
        raise Invalid('Unresolved suspicion requires an explicit operator disposition for this candidate')
    from .reassessment import validate_binding
    from .workspace import scan
    commands = {c['id']: c for c in bundle['policy']['project']['commands']}
    for test in inputs['tests']:
        command = commands[test['command']]
        validate_binding(store, db, actor, {
            'approval': review['policy_sha256'], 'definition': command,
            'snapshot': scan(bundle['inventory'], command['resources']),
            'package_sets': test['binding']['package_sets']})
    for name, expected in review['object_sha256'].items():
        path = store.directory / 'git-requests' / review['id'] / 'target/repository/objects' / name
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise Invalid('Assembled candidate objects changed')


def record_findings(store, identity, expected, findings, *, analysis=None):
    """Trusted operator entry, never exposed as a worker tool or an approval."""
    from .local_git import IDENTITY
    from .setup_transaction import atomic
    if not isinstance(identity, str) or not IDENTITY.fullmatch(identity):
        raise Invalid('Malformed checkpoint ID')
    folder = store.directory / 'git-requests' / identity
    with store.locked() as db:
        review, state = load(folder / 'review.json'), load(folder / 'state.json')
        if state != {'phase': 'review', 'sha256': expected} or digest(review) != expected:
            raise Invalid('Stale or consumed review findings')
        validate_result(review)
        if analysis is not None:
            from .sequence_review import reviewer_request
            selected = reviewer_request(review)
            validate_result({'review_input': selected, 'review_result': analysis})
            if analysis['findings'] != findings:
                raise Invalid('Reviewer findings differ from original analysis')
        state = ('incomplete' if review['review_result']['state'] == 'incomplete' or
                 analysis is not None and analysis['state'] == 'incomplete' else
                 'suspected' if findings or review['review_result']['findings'] else 'no_findings')
        review['review_result'] = {**review['review_result'], 'state': state,
                                  'findings': review['review_result']['findings'] + findings}
        validate_result(review)
        from .evidence_storage import admit, charge
        _, bundle = store.project(db, review['project'])
        definition = next(c for c in bundle['policy']['project']['commands'] if c['id'] == review['command'])
        original = {'schema': 1, 'input_sha256': digest(review['review_input']),
                    'reviewer': REVIEWER, 'resources': definition['resources'], 'findings': findings}
        if analysis is not None:
            original['analysis'] = analysis
        identity_hash = digest(original)
        review['finding_records'].append(identity_hash)
        event = 'checkpoint-findings:' + identity + ':' + identity_hash
        try:
            admit(db, review['project'], charge(review) + charge(original))
            # Persist intent before touching the packet. A crash or failed file
            # write must leave visible uncertainty, never an erasable concern.
            if not store.lifecycle(db, review['project'], 'checkpoint_findings', session=review['session'],
                    event=event, pending=True,
                    facts={'checkpoint': identity, 'result_sha256': identity_hash,
                           'review_sha256': digest(review)}):
                raise Invalid('Required finding evidence unavailable')
            save(folder / ('findings-' + identity_hash + '.json'), original)
            atomic(folder / 'review.json', review)
            atomic(folder / 'state.json', {'phase': 'review', 'sha256': digest(review)})
            store.complete(db, 'controller:' + review['project'], event,
                           {'allowed': True, 'level': 'allow', 'effect': 'checkpoint_findings'})
        except (OSError, sqlite3.Error, Invalid):
            store.capture_fault(db, review['project'])
            raise
        return digest(review)
