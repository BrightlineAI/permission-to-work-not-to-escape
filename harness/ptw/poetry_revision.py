"""Staged Poetry declaration edits, using the pinned native parser and TOML writer."""
import copy
import hashlib
from pathlib import Path
import secrets
import subprocess
import tomllib

from packaging.utils import canonicalize_name

from .dependency_resolution import ResolutionError, checked_requirement, metadata
from .policy import Invalid, save
from .python_lock import static_lock_project
from .python_runtime import select


EDIT = r'''
import json, sys
from pathlib import Path
import tomlkit
from poetry.factory import Factory
from poetry.core.constraints.version import Version

config = json.loads(sys.argv[1])
path = Path('pyproject.toml')
original = path.read_text()
poetry = Factory().create_poetry(Path.cwd(), disable_plugins=True)
if not poetry.locker.is_locked() or not poetry.locker.is_fresh():
    raise ValueError('stale Poetry lock')
if not poetry.package.python_constraint.allows(Version.parse(config['runtime']['version'])):
    raise ValueError('project Python constraint excludes reviewed runtime')
for dependency in poetry.package.all_requires:
    if dependency.is_direct_origin() or dependency.source_name:
        raise ValueError('nonregistry Poetry dependency')
document = tomlkit.parse(original)
for change in config['changes']:
    table = document
    for key in change['path'][:-1]:
        if key not in table:
            table[key] = tomlkit.table()
        table = table[key]
    key = change['path'][-1]
    if change['delete']:
        del table[key]
    else:
        table[key] = change['value']
# Parsing the proposed file invokes no installer or project plugin. On any
# failure leave this staging input unchanged, retaining only the host receipt.
try:
    path.write_text(tomlkit.dumps(document))
    proposed = Factory().create_poetry(Path.cwd(), disable_plugins=True)
    if proposed.package.python_constraint != poetry.package.python_constraint:
        raise ValueError('Python constraint changed')
    for dependency in proposed.package.all_requires:
        if dependency.is_direct_origin() or dependency.source_name:
            raise ValueError('nonregistry Poetry dependency')
except BaseException:
    path.write_text(original)
    raise
'''


def planned_edit(document, operation, specs, group=None):
    """Limit mutation to the selected direct declaration, preserving its qualifiers.

    Poetry's parser remains authoritative for Poetry constraint syntax. CLI
    edits use the same explicit PEP 508 ranges as the other Python adapters.
    """
    if not isinstance(document, dict):
        raise Invalid('Malformed Poetry project')
    static_lock_project(document)
    if (operation not in ('add', 'remove', 'update') or not isinstance(specs, (list, tuple))
            or not specs or any(not isinstance(s, str) for s in specs)):
        raise Invalid('Select add, remove or update with explicit dependencies')
    poetry = document.get('tool', {}).get('poetry', {})
    if poetry.get('source'):
        raise Invalid('Poetry sources need separate reviewed routing')
    wanted = {}
    for value in specs:
        req = checked_requirement(value)
        name = canonicalize_name(req.name)
        if (name == 'python' or name in wanted or req.marker or req.extras or
                (operation == 'remove' and req.specifier) or
                (operation != 'remove' and not req.specifier)):
            raise Invalid('Use distinct plain names and explicit add/update ranges or pins')
        wanted[name] = req
    if group is not None and (not isinstance(group, str) or not group or
            (group.startswith('extra:') and not group[6:])):
        raise Invalid('Select a named dependency group or extra')
    expected, changes = copy.deepcopy(document), []

    def change(path, value=None, delete=False):
        table = expected
        for key in path[:-1]:
            table = table.setdefault(key, {})
            if not isinstance(table, dict):
                raise Invalid('Malformed dependency table')
        if delete:
            del table[path[-1]]
        else:
            table[path[-1]] = value
        changes.append(dict(path=path, value=value, delete=delete))

    extra = group[6:] if group and group.startswith('extra:') else None
    group_path, group_entries = None, None
    if group and not extra:
        # Each direct dependency can have a different owning declaration.
        # Preserve include-group entries and never edit an included group by
        # accident. Split batch edits so each name keeps its original owner.
        if len(specs) > 1:
            for spec in specs:
                expected, edits = planned_edit(expected, operation, [spec], group)
                changes.extend(edits)
            return expected, changes
        sources = []
        for name, entries in document.get('dependency-groups', {}).items():
            if canonicalize_name(name) == canonicalize_name(group):
                sources.append((['dependency-groups', name], entries))
        for name, table in poetry.get('group', {}).items():
            if canonicalize_name(name) == canonicalize_name(group) and 'dependencies' in table:
                sources.append((['tool', 'poetry', 'group', name, 'dependencies'], table['dependencies']))
        if canonicalize_name(group) == 'dev' and 'dev-dependencies' in poetry:
            sources.append((['tool', 'poetry', 'dev-dependencies'], poetry['dev-dependencies']))
        owners = []
        for path, entries in sources:
            if isinstance(entries, list):
                names = {canonicalize_name(checked_requirement(e).name) for e in entries if isinstance(e, str)}
            elif isinstance(entries, dict):
                names = {canonicalize_name(n) for n in entries}
            else:
                raise Invalid('Malformed dependency group')
            if names.intersection(wanted):
                owners.append((path, entries))
        if len(owners) > 1:
            raise Invalid('Dependency has multiple group declarations; review the manifest together')
        group_path, group_entries = (owners or sources or [
            (['tool', 'poetry', 'group', group, 'dependencies'], {})])[0]
    project = document.get('project', {})
    # Poetry 2 also accepts static PEP 621 identity with legacy dependency
    # tables. Preserve whichever declaration table already owns the selection.
    modern = bool(project) and (('optional-dependencies' in project or not poetry.get('extras'))
        if extra else ('dependencies' in project or not poetry.get('dependencies')))
    if (modern and (not group or extra)) or (group_path and group_path[0] == 'dependency-groups'):
        if group_path:
            path, entries = group_path, group_entries
        else:
            path = ['project', 'optional-dependencies', extra] if extra else ['project', 'dependencies']
            table = document['project'].get('optional-dependencies', {}) if extra else document['project']
            entries = table.get(path[-1], [])
        if not isinstance(entries, list):
            raise Invalid('Selected PEP 621 dependencies must be an array')
        output, found = [], set()
        for entry in entries:
            if (group_path and isinstance(entry, dict) and set(entry) == {'include-group'}
                    and isinstance(entry['include-group'], str)):
                output.append(entry)
                continue
            if not isinstance(entry, str):
                raise Invalid('Selected PEP 621 dependency must be a string')
            req = checked_requirement(entry)
            name = canonicalize_name(req.name)
            if name not in wanted:
                output.append(entry)
                continue
            if name in found or operation == 'add':
                raise Invalid('Duplicate dependency or existing add; select update')
            # Poetry may enrich the PEP 621 declaration in its own table. Do not
            # publish contradictory declarations by editing only one authority.
            if not group_path and any(canonicalize_name(n) == name for n in poetry.get('dependencies', {}) if n != 'python'):
                raise Invalid('Dependency has both PEP 621 and Poetry constraints; review the manifest together')
            found.add(name)
            if operation == 'update':
                req.specifier = wanted[name].specifier
                output.append(str(req))
        if operation != 'add' and found != set(wanted):
            raise Invalid('Dependency is absent from the selected direct group')
        if operation == 'add':
            if not group_path and any(canonicalize_name(n) in wanted for n in poetry.get('dependencies', {}) if n != 'python'):
                raise Invalid('Dependency already has a Poetry constraint')
            output.extend(str(req) for req in wanted.values())
        change(path, output)
    else:
        path = group_path or ['tool', 'poetry', 'dependencies']
        entries = group_entries if group_path else poetry.get('dependencies', {})
        if not isinstance(entries, dict):
            raise Invalid('Selected Poetry dependencies must be a table')
        names = {}
        for name in entries:
            normalized = canonicalize_name(name)
            if normalized in names:
                raise Invalid('Duplicate canonical Poetry dependency')
            names[normalized] = name
        extras = copy.deepcopy(poetry.get('extras', {}))
        if not isinstance(extras, dict) or any(not isinstance(values, list) or
                any(not isinstance(n, str) for n in values) for values in extras.values()):
            raise Invalid('Malformed Poetry extras')
        members = extras.get(extra, []) if extra else []
        membership = {canonicalize_name(n) for n in members}
        for name, req in wanted.items():
            present = name in names and (not extra or name in membership)
            if (operation == 'add') == present:
                raise Invalid('Use add for new dependencies and update/remove for existing dependencies')
            key = names.get(name, req.name)
            old = entries.get(key)
            if operation == 'remove':
                if extra:
                    members = [n for n in members if canonicalize_name(n) != name]
                    # A shared optional dependency retains its other extra grants.
                    retained = any(name in {canonicalize_name(n) for n in values}
                                   for e, values in extras.items() if e != extra)
                    if retained:
                        continue
                elif any(name in {canonicalize_name(n) for n in values} for values in extras.values()) and not group:
                    raise Invalid('Remove the dependency from its named extras first')
                change([*path, key], delete=True)
                continue
            if extra and name in names and not present:
                raise Invalid('Adding an existing dependency to an extra needs a separate declaration review')
            if isinstance(old, dict):
                if set(old) - {'version', 'optional', 'markers', 'python', 'platform', 'extras', 'allow-prereleases'}:
                    raise Invalid('Poetry source dependency cannot be edited as a registry package')
                value = {**old, 'version': str(req.specifier)}
            elif old is None or isinstance(old, str):
                value = str(req.specifier)
            else:
                raise Invalid('Multiple Poetry constraints require an explicit manifest review')
            if extra:
                value = {**(value if isinstance(value, dict) else {'version': value}), 'optional': True}
                if operation == 'add':
                    members.append(key)
            change([*path, key], value)
        if extra:
            change(['tool', 'poetry', 'extras', extra], members)
    return expected, changes


def edit_project(root, operation, specs, *, group=None, python):
    """Edit only a metadata staging directory; resolution/publication are separate."""
    from .poetry_tool import run
    root = Path(root)
    original = metadata(root, 'pyproject.toml', {})
    document = tomllib.loads(original)
    expected, changes = planned_edit(document, operation, specs, group)
    locked = metadata(root, 'poetry.lock', {})
    if any(p.get('source') for p in tomllib.loads(locked).get('package', [])):
        raise Invalid('Poetry lock sources need separate reviewed routing')
    if (root / 'uv.lock').exists():
        raise Invalid('Select one authoritative Python lock')
    version = metadata(root, '.python-version', {}).strip() if (root / '.python-version').exists() else None
    runtime = select(document.get('project', {}).get('requires-python', ''), python, version)
    receipt = {'outcome': 'invalid', 'manifest_sha256': hashlib.sha256(original.encode()).hexdigest(),
               'lock_sha256': hashlib.sha256(locked.encode()).hexdigest(), 'runtime': runtime,
               'runner_sha256': hashlib.sha256(EDIT.encode()).hexdigest()}
    try:
        result = run(EDIT, dict(changes=changes, runtime=runtime), cwd=root, timeout=30)
        receipt.update(returncode=result.returncode, stderr_sha256=hashlib.sha256(result.stderr.encode()).hexdigest())
        if result.returncode:
            raise ResolutionError('unavailable', 'Native Poetry declaration edit failed; inspect its retained receipt')
        if (tomllib.loads(metadata(root, 'pyproject.toml', {})) != expected or
                metadata(root, 'poetry.lock', {}) != locked):
            raise Invalid('Native Poetry edit changed unrelated metadata or lock authority')
        receipt['outcome'] = 'edited'
    except subprocess.TimeoutExpired as exc:
        receipt['outcome'] = 'budget_exhausted'
        raise ResolutionError('budget_exhausted', 'Native Poetry declaration edit timed out') from exc
    finally:
        save(root / ('edit-receipt-' + secrets.token_hex(8) + '.json'), receipt)
