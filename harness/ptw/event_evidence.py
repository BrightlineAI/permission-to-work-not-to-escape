"""Versioned views of the controller's existing events, not another journal.

Hashes detect inconsistent records/exports against retained references. They do
not attest an honest host, reconstruct omitted content, or supply authority.
"""
from .policy import Invalid, digest

VERSION = 1
LEVELS = {'allow', 'deny', 'warn', 'stop', 'blocked', 'conflict'}
STATES = {'pending', 'complete', 'uncertain'}
# Never export arbitrary diagnostic strings, tool output, worker narratives or
# nested response objects. The private original response remains replay data.
RESULT_FIELDS = {
    'allowed', 'effect', 'level', 'bytes', 'sha256', 'exit_code',
    'output_truncated', 'violation_counted', 'project_violations',
    'task_violations', 'confirmed_stopped', 'ready', 'checkpoint',
    'review_sha256', 'package_set', 'manifest_sha256', 'policy_sha256',
    'published', 'commit', 'ref', 'unit', 'ecosystem', 'replayed',
}


def result_metadata(response):
    result = {k: v for k, v in response.items() if k in RESULT_FIELDS
              and (v is None or type(v) in (str, bool, int, float))}
    child = response.get('child')
    if isinstance(child, dict):
        result['child'] = {k: child[k] for k in ('session', 'project', 'task', 'parent')
                           if k in child and (child[k] is None or isinstance(child[k], str))}
    changed = response.get('changed')
    if isinstance(changed, list) and all(isinstance(p, str) for p in changed):
        result['changed'] = changed
    return result


def validate_response(response):
    if (not isinstance(response, dict) or response.get('level') not in LEVELS
            or type(response.get('allowed')) is not bool
            or response['allowed'] != (response['level'] == 'allow')):
        raise Invalid('Unsupported event decision')


def outcome(response, state):
    if state != 'complete' or response.get('effect') == 'unknown':
        return 'unknown'
    if response.get('exit_code') not in (None, 0):
        return 'failed'
    if response.get('confirmed_stopped') is False:
        return 'unconfirmed'
    if response.get('effect') == 'service_start_failed':
        return 'failed'
    if response.get('allowed'):
        return 'observed'
    return 'not_performed'


def seal(meta, response, state):
    value = dict(meta)
    value.pop('_seal', None)
    return digest({'metadata': value, 'response': response, 'state': state})


def export_row(row):
    import json
    meta = json.loads(row['request_meta'])
    response = json.loads(row['response'] or '{}')
    envelope = meta.pop('_audit', None)
    stored_seal = meta.pop('_seal', None)
    if row['state'] not in STATES:
        raise Invalid('Unsupported event state')
    if envelope is not None:
        if not isinstance(envelope, dict) or envelope.get('schema') != VERSION:
            raise Invalid('Unsupported event schema')
        original = {**meta, '_audit': envelope}
        if stored_seal != seal(original, response, row['state']):
            raise Invalid('Event evidence changed; original record required')
        if (envelope['operation_id'] != digest([row['session'], row['event']])
                or envelope['request_sha256'] != row['request_hash']
                or envelope['observed_at'] != row['at']):
            raise Invalid('Event identity changed')
        if response:
            validate_response(response)
    else:
        # Do not backfill historical provenance using today's policy or grants.
        envelope = {'schema': VERSION, 'operation_id': digest([row['session'], row['event']]),
                    'sequence': None, 'policy_sha256': None, 'authorization': None,
                    'source_at': None, 'observed_at': None, 'recorded_at': None,
                    'coverage': 'legacy_unknown', 'decision': 'unknown',
                    'outcome': 'unknown', 'integrity': 'unverified_legacy'}
    return {'session': row['session'], 'task': row['task'] or envelope.get('task'), 'event': row['event'],
            'request': meta, 'state': row['state'], 'result': result_metadata(response),
            'result_sha256': digest(response), 'at': row['at'], 'audit': envelope}


def export_document(project, events):
    return {'schema': VERSION, 'project': project, 'events': events,
            'manifest': {'count': len(events), 'events_sha256': digest(events)},
            'limits': {'hidden_reasoning': 'unavailable', 'native_transcript': 'not_captured',
                       'content': 'omitted', 'integrity': 'local_consistency_only'}}


def assessment_row(row):
    import json
    detail = json.loads(row['detail'])
    audit = detail.get('_audit')
    if audit is not None:
        saved = detail.pop('_seal', None)
        if (digest(detail) != saved or audit.get('resource') != row['package_set'] or
                audit.get('outcome') != row['outcome'] or audit.get('observed_at') != row['at']):
            raise Invalid('Package assessment evidence changed')
    return {'attempt': row['attempt'], 'package_set': row['package_set'], 'observed_at': row['at'],
            'source_at': None, 'outcome': row['outcome'], 'detail_sha256': digest(json.loads(row['detail'])),
            'audit': audit or {'policy_sha256': None, 'authority': 'legacy_unknown'},
            'ordering': 'assessment_table_rowid'}


def verify_export(document, expected_sha256):
    """The expected digest must come from an independently retained export receipt."""
    if (not isinstance(document, dict) or type(document.get('schema')) is not int
            or document['schema'] != VERSION):
        raise Invalid('Unsupported audit export')
    events = document.get('events')
    manifest = document.get('manifest', {})
    if (not isinstance(events, list) or not isinstance(manifest, dict)
            or type(manifest.get('count')) is not int or manifest.get('count') != len(events)
            or manifest.get('events_sha256') != digest(events)):
        raise Invalid('Missing or altered audit events')
    if 'supporting_sha256' in manifest and manifest['supporting_sha256'] != digest(
            {k: document.get(k) for k in ('profile', 'payloads', 'assessments')}):
        raise Invalid('Missing or altered supporting evidence')
    seen, previous = set(), 0
    for row in events:
        try:
            audit = row['audit']
            identity, sequence = audit['operation_id'], audit['sequence']
            if (type(audit.get('schema')) is not int or audit['schema'] != VERSION or
                    row['state'] not in STATES or identity in seen or
                    audit['decision'] not in LEVELS | {'unknown'} or
                    audit['outcome'] not in {'unknown', 'observed', 'failed', 'unconfirmed', 'not_performed'}):
                raise Invalid('Invalid or duplicate audit event')
            if sequence is not None:
                if type(sequence) is not int or sequence <= previous:
                    raise Invalid('Reordered audit events')
                previous = sequence
            seen.add(identity)
        except (KeyError, TypeError) as exc:
            raise Invalid('Malformed audit event') from exc
    if digest(document) != expected_sha256:
        raise Invalid('Export does not match retained receipt')
    return {'verified': True, 'events': len(events), 'integrity': 'local_consistency_only'}
