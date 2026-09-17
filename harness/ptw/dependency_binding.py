"""Bind preparation and reuse to reviewed declarations and artifact identities."""
import hashlib
import os

from .policy import Invalid, open_resource
from .workspace_policy import relative


def verify_inputs(bundle):
    descriptor = bundle['policy']['project'].get('python_dependencies')
    if not descriptor:
        return
    for name, expected in descriptor['inputs'].items():
        relative(name)
        try:
            fd = open_resource(bundle['inventory'], name, os.O_RDONLY)
            with os.fdopen(fd, 'rb') as stream:
                content = stream.read(8 * 1024 * 1024 + 1)
        except OSError as exc:
            raise Invalid('Reviewed dependency input is missing or replaced; review a dependency revision') from exc
        if len(content) > 8 * 1024 * 1024 or hashlib.sha256(content).hexdigest() != expected:
            raise Invalid('Reviewed dependency input changed; review a dependency revision')


def verify_selection(bundle, selected, extras):
    descriptor = bundle['policy']['project'].get('python_dependencies')
    if descriptor:
        from .package_evidence import pins
        approved_extras = {}
        approved = pins(descriptor['pins'], extras=approved_extras) if descriptor['pins'] else {}
        if approved != selected or approved_extras != (extras or {}):
            raise Invalid('Install differs from the reviewed dependency resolution')


def verify_artifacts(bundle, evidence):
    descriptor = bundle['policy']['project'].get('python_dependencies')
    if descriptor:
        expected = descriptor['artifacts']
        actual = [{k: record[k] for k in ('name', 'version', 'url', 'sha256')} for record in evidence]
        if sorted(actual, key=lambda e: e['name']) != sorted(expected, key=lambda e: e['name']):
            raise Invalid('Registry artifact identity or digest changed after dependency review')
