"""On-use advisory refresh. The existing package evaluator is the sole policy."""
import concurrent.futures
import json
import os
import re
import secrets
import sqlite3
import time

from .package_evidence import EvidenceError, evaluate
from .policy import Invalid, canonical, digest
from .evidence_storage import QuotaError, admit, charge

PUBLIC = {'pypi': 'https://pypi.org', 'npm': 'https://registry.npmjs.org'}
BUDGET_SECONDS = 30


def identity(record, ecosystem):
    return (ecosystem, record.get('origin', PUBLIC[ecosystem]), record['name'], record['version'])


def records(row):
    try:
        values = json.loads(row['evidence'])
        if not isinstance(values, list) or len(values) > 4096:
            raise ValueError()
        for value in values:
            if (not isinstance(value, dict) or
                    any(not isinstance(value.get(k), str) or not value[k] for k in ('name', 'version', 'url')) or
                    not re.fullmatch('[0-9a-f]{64}', value.get('sha256', ''))):
                raise ValueError()
        names = {r['name'] for r in values}
        expected = {n.removeprefix(row['ecosystem'] + ':') for n in json.loads(row['names'])}
        if not expected <= names:
            raise ValueError()
        return values
    except (ValueError, TypeError, KeyError):
        raise EvidenceError('Installed set lacks trustworthy assessment provenance; review and install again') from None


def seed(db, package_set, evidence, *, actor=None, cause=None):
    # Full install records retain artifact, registry and build provenance. Local
    # sources have separate reviewed receipts and are never queried as PyPI names.
    db.execute("UPDATE package_sets SET evidence=?,assessment_state='current',assessment_reason=NULL,"
               'assessment_generation=assessment_generation+1 WHERE id=?', (canonical(evidence), package_set))
    attempt(db, package_set, 'current', {'source': 'installation', 'evidence': evidence},
            actor=actor, cause=cause)


def validate_publication(db, project, ecosystem, evidence):
    """Caller holds the publication lock; old clean evidence cannot undo a finding."""
    collected = {}
    for record in evidence:
        key = identity(record, ecosystem)
        collected[key] = min(collected.get(key, record['checked_at']), record['checked_at'])
    for receipt in db.execute(
            'SELECT a.at,a.detail FROM package_assessments a JOIN package_sets p ON p.id=a.package_set '
            "WHERE p.project=? AND a.outcome='quarantined'", (project,)):
        for key, _ in json.loads(receipt['detail'])['forbidden']:
            key = tuple(key)
            if key in collected and collected[key] <= receipt['at']:
                raise EvidenceError('Dependency was quarantined during installation; collect new evidence and retry')


def attempt(db, package_set, outcome, detail, *, actor=None, cause=None):
    from .store import _operation
    active = _operation.get()
    row = db.execute('SELECT project FROM package_sets WHERE id=?', (package_set,)).fetchone()
    bundle = json.loads(db.execute('SELECT bundle FROM projects WHERE id=?', (row['project'],)).fetchone()[0])
    observed = time.time()
    detail = {**detail, '_audit': {'schema': 1, 'source_at': None, 'observed_at': observed,
              'recorded_at': time.time(), 'policy_sha256': bundle['approval']['sha256'],
              'resource': package_set, 'action': 'package_assessment',
              'requester': {'kind': 'authenticated_session', 'id': actor['id']} if actor else
                           {'kind': 'local_controller', 'uid': os.getuid()},
              'enforcer': {'kind': 'local_controller', 'uid': os.getuid()},
              'authorization': {'method': 'standing_policy', 'rule_sha256': digest(bundle['policy']['project']['packages']),
                                'human_review_required': False, 'human_review_performed': False},
              'cause': cause if cause is not None else digest([active['session'], active['event']]) if active else None,
              'outcome': outcome}}
    detail['_seal'] = digest(detail)
    receipt = {'attempt': secrets.token_hex(16), 'package_set': package_set, 'at': observed,
               'outcome': outcome, 'detail': canonical(detail)}
    # Charge exactly the stored representation, including escaped detail and
    # identity/time fields. usage() also sees any uncommitted package-row growth.
    admit(db, row['project'], charge(receipt))
    db.execute('INSERT INTO package_assessments VALUES(?,?,?,?,?)',
               tuple(receipt.values()))


def cached(row, rules):
    if row['assessment_state'] == 'quarantined':
        raise EvidenceError('Package set quarantined: ' + (row['assessment_reason'] or 'forbidden dependency'))
    if row['assessment_state'] != 'current':
        raise EvidenceError(row['assessment_reason'] or 'Package assessment required before reuse')
    for record in records(row):
        if evaluate(record, rules):
            raise EvidenceError('Installed dependency no longer permitted; reassessment required')


def refresh(store, token, package_set, *, definition=None, snapshot=None, provider=None):
    """No network under the admission lock; stale concurrent clean results lose."""
    from .packages import mounted_set
    from .registry import provider_for
    from .supervisor import Supervisor
    try:
        with store.locked() as db:
            actor = store.session(db, token)
            project, bundle = store.project(db, actor['project'])
            if project['stopped']:
                raise Invalid('Project stopped')
            mounted_set(store, db, actor, package_set, definition=definition, snapshot=snapshot, assessment=False)
            row = db.execute('SELECT * FROM package_sets WHERE id=?', (package_set,)).fetchone()
            rules = bundle['policy']['project']['packages']
            if row['assessment_state'] == 'quarantined':
                cached(row, rules)
            try:
                cached(row, rules)
                return
            except EvidenceError:
                pass
            try:
                previous = records(row)
            except EvidenceError as exc:
                db.execute('BEGIN IMMEDIATE')
                db.execute("UPDATE package_sets SET assessment_state='blocked',assessment_reason=?,"
                           'assessment_generation=assessment_generation+1 WHERE id=?', (str(exc), package_set))
                attempt(db, package_set, 'blocked', {'reason': str(exc)}, actor=actor)
                db.commit()
                raise
            generation = row['assessment_generation']
            approval = bundle['approval']['sha256']
        updated, forbidden, errors = [], [], []
        try:
            provider = provider or provider_for(store, bundle, row['ecosystem'])
            provider.deadline = time.monotonic() + BUDGET_SECONDS

            def collect(record):
                if time.monotonic() >= provider.deadline:
                    raise EvidenceError('Advisory refresh deadline reached')
                route = getattr(provider, 'routes', {}).get(record['name'])
                origin = route['registry'] if route else PUBLIC[row['ecosystem']]
                if origin != identity(record, row['ecosystem'])[1]:
                    raise EvidenceError('Installed advisory origin differs from reviewed route')
                checked = time.time()
                vulnerabilities = provider.advisories('PyPI' if row['ecosystem'] == 'pypi' else 'npm',
                                                     record['name'], record['version'])
                if time.monotonic() >= provider.deadline:
                    raise EvidenceError('Advisory refresh deadline reached')
                return {**record, 'checked_at': checked, 'vulnerabilities': vulnerabilities}

            # Each client already bounds requests, response bytes and pagination.
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                futures = [pool.submit(collect, record) for record in previous]
                for future in futures:
                    try:
                        record = future.result()
                        reasons = evaluate(record, rules)
                        updated.append(record)
                        if reasons:
                            forbidden.append((identity(record, row['ecosystem']), reasons))
                    except (Invalid, OSError, ValueError, TypeError) as exc:
                        errors.append(str(exc))
        except (Invalid, OSError, ValueError, TypeError) as exc:
            errors.append(str(exc))
        with store.locked() as db:
            try:
                actor = store.session(db, token)
                project, current = store.project(db, actor['project'])
                if project['stopped'] or current['approval']['sha256'] != approval:
                    raise Invalid('Project or policy changed during reassessment')
                mounted_set(store, db, actor, package_set, definition=definition, snapshot=snapshot, assessment=False)
            except Invalid as exc:
                attempt(db, package_set, 'discarded', {'reason': str(exc), 'evidence': updated, 'errors': errors}, actor=actor)
                raise
            latest = db.execute('SELECT * FROM package_sets WHERE id=?', (package_set,)).fetchone()
            if forbidden:
                # Quarantine all installations of the exact origin/name/version
                # in this project, even those with a still-fresh cached assessment.
                matches = {tuple(key) for key, _ in forbidden}
                reason = '; '.join(sorted({r for _, reasons in forbidden for r in reasons}))
                db.execute('BEGIN IMMEDIATE')
                quarantined = []
                for other in db.execute('SELECT * FROM package_sets WHERE project=?', (actor['project'],)).fetchall():
                    try:
                        affected = any(identity(r, other['ecosystem']) in matches for r in records(other))
                    except EvidenceError:
                        affected = other['id'] == package_set
                    if affected:
                        db.execute("UPDATE package_sets SET assessment_state='quarantined',assessment_reason=?,"
                                   'assessment_generation=assessment_generation+1 WHERE id=?', (reason, other['id']))
                        quarantined.append(other['id'])
                # Capture the entire batch or none. On capture failure preserve
                # the restrictive state if storage permits, then stop the project
                # through the existing fault handler; never claim a receipt exists.
                db.execute('SAVEPOINT assessment_receipts')
                try:
                    for identity_ in quarantined:
                        attempt(db, identity_, 'quarantined', {'source_set': package_set,
                                'forbidden': forbidden, 'evidence': updated, 'errors': errors}, actor=actor)
                except (QuotaError, sqlite3.Error):
                    db.execute('ROLLBACK TO assessment_receipts')
                    db.commit()
                    raise
                db.commit()
                raise EvidenceError('Package set quarantined: ' + reason)
            if latest['assessment_generation'] != generation or latest['assessment_state'] == 'quarantined':
                attempt(db, package_set, 'discarded', {'reason': 'Concurrent assessment changed', 'evidence': updated, 'errors': errors}, actor=actor)
                cached(latest, rules)
                return
            if len(updated) != len(previous):
                errors.append('Incomplete advisory refresh')
            # Recheck time after the complete batch, without extending collection times.
            for record in updated:
                try:
                    if evaluate(record, rules):
                        errors.append('Evidence changed during reassessment')
                except EvidenceError as exc:
                    errors.append(str(exc))
            state = 'blocked' if errors else 'current'
            reason = '; '.join(sorted(set(errors))) if errors else None
            # A direct Supervisor.launch has no enclosing operation intent yet.
            # Eligibility and its required receipt must therefore commit together.
            db.execute('BEGIN IMMEDIATE')
            db.execute('UPDATE package_sets SET assessment_state=?,assessment_reason=?,evidence=?, '
                       'assessment_generation=assessment_generation+1 WHERE id=?',
                       (state, reason, row['evidence'] if errors else canonical(updated), package_set))
            attempt(db, package_set, state, {'evidence': updated, 'errors': errors}, actor=actor)
            db.commit()
            if errors:
                raise EvidenceError('Package reassessment unavailable: ' + reason)
    except (QuotaError, sqlite3.Error):
        if 'actor' in locals():
            with store.locked() as db:
                store.capture_fault(db, actor['project'])
        raise
    finally:
        Supervisor(store).reconcile()


def validate_binding(store, db, actor, binding):
    """Trusted adapter binding checked at admission and workspace publication."""
    if binding is None:
        return
    from .packages import mounted_set
    from .dependency_binding import verify_inputs
    project, bundle = store.project(db, actor['project'])
    if project['stopped'] or bundle['approval']['sha256'] != binding['approval']:
        raise Invalid('Command policy changed before admission/publication')
    verify_inputs(bundle)
    definition = binding['definition']
    if definition is not None:
        if (definition['id'] not in json.loads(actor['commands']) or definition not in
                bundle['policy']['project']['commands']):
            from .policy import OutsideScope
            raise OutsideScope('Command authority changed before admission/publication')
    for package_set in binding['package_sets']:
        mounted_set(store, db, actor, package_set, definition=definition, snapshot=binding['snapshot'])


def bind_workload(db, unit, binding):
    if binding:
        db.executemany('INSERT INTO workload_packages VALUES(?,?)',
                       [(unit, p) for p in binding['package_sets']])
