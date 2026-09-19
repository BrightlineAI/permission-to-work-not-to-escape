"""Version 4: reviewed directory capabilities and named, confined commands."""
import copy
import os
from pathlib import Path, PurePosixPath
import stat

from .policy import ECOSYSTEM_SCHEMA, ID, Invalid, obj, scope, validate

FILE_ACTIONS = ["read", "write", "append", "create", "delete"]
WORKSPACE_SCHEMA = copy.deepcopy(ECOSYSTEM_SCHEMA)
WORKSPACE_SCHEMA["properties"]["version"]["const"] = 4
WORKSPACE_SCHEMA['properties']['project']['properties']['audit'] = obj({
    'version': {'type': 'integer', 'const': 1},
    'project_bytes': {'type': 'integer', 'minimum': 65536},
    'content_resources': {'type': 'array', 'maxItems': 128, 'uniqueItems': True, 'items': ID},
})
COMMAND = obj({
    "id": ID,
    "argv": {"type": "array", "minItems": 1, "maxItems": 64,
             "items": {"type": "string", "minLength": 1, "maxLength": 4096}},
    "resources": {"type": "array", "minItems": 1, "maxItems": 128, "uniqueItems": True, "items": ID},
    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 120},
})
COMMAND['properties']['cwd'] = {'type': 'string', 'maxLength': 1024}
COMMAND['properties']['preview'] = obj({
    'port': {'type': 'integer', 'minimum': 1024, 'maximum': 65535},
    'lifetime_seconds': {'type': 'integer', 'minimum': 1, 'maximum': 3600},
})
COMMAND['properties']['git'] = obj({
    'operation': {'enum': ['status', 'diff', 'checkpoint']},
    'device': {'type': 'integer', 'minimum': 0},
    'inode': {'type': 'integer', 'minimum': 1},
})
WORKSPACE_SCHEMA['properties']['project']['properties']['python_runtime'] = obj({
    'executable': {'type': 'string', 'minLength': 1},
    'sha256': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'},
    'version': {'type': 'string'}, 'implementation': {'type': 'string'},
    'abi': {'type': 'string'}, 'prefix': {'type': 'string'},
    'requires_python': {'type': 'string'},
})
WORKSPACE_SCHEMA['properties']['project']['properties']['python_runtime']['properties']['version_request'] = {'type': 'string'}
WORKSPACE_SCHEMA['properties']['project']['properties']['python_dependencies'] = obj({
    'inputs': {'type': 'object', 'maxProperties': 64,
               'additionalProperties': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'}},
    'pins': {'type': 'array', 'maxItems': 64, 'items': {'type': 'string'}},
    'artifacts': {'type': 'array', 'maxItems': 64, 'items': obj({
        'name': {'type': 'string'}, 'version': {'type': 'string'},
        'url': {'type': 'string'}, 'sha256': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'},
    })},
})
WORKSPACE_SCHEMA['properties']['project']['properties']['npm_dependencies'] = obj({
    'inputs': {'type': 'object', 'maxProperties': 64,
              'additionalProperties': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'}},
    'lock_sha256': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'},
    'artifacts': {'type': 'array', 'maxItems': 1024, 'items': obj({
        'name': {'type': 'string'}, 'version': {'type': 'string'},
        'url': {'type': 'string'}, 'integrity': {'type': 'string'},
    })},
})
WORKSPACE_SCHEMA['properties']['project']['properties']['python_dependencies']['properties'].update({
    'sources': {'type': 'array', 'maxItems': 64, 'items': obj({
        'id': ID,
        'path': {'type': 'string', 'maxLength': 1024},
        'name': {'type': 'string', 'minLength': 1},
        'version': {'type': 'string', 'minLength': 1},
        'mode': {'enum': ['wheel', 'editable', 'discovery']},
        'allow_build': {'type': 'boolean'},
        'resources': {'type': 'array', 'minItems': 1, 'maxItems': 128,
                      'uniqueItems': True, 'items': ID},
        'snapshot_sha256': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'},
    })},
    'registry_config_sha256': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'},
    'groups': {'type': 'array', 'maxItems': 64, 'uniqueItems': True, 'items': {'type': 'string'}},
    'extras': {'type': 'array', 'maxItems': 64, 'uniqueItems': True, 'items': {'type': 'string'}},
    'authority': {'enum': ['requirements', 'pyproject.toml', 'uv.lock', 'poetry.lock']},
})
LOCAL_SOURCE = WORKSPACE_SCHEMA['properties']['project']['properties']['python_dependencies']['properties']['sources']['items']
LOCAL_SOURCE['required'].remove('version')
LOCAL_SOURCE['properties'].update({
    'build_dependencies': obj({key: WORKSPACE_SCHEMA['properties']['project']['properties']
        ['python_dependencies']['properties'][key] for key in ('pins', 'artifacts')}),
    'extras': {'type': 'array', 'maxItems': 64, 'uniqueItems': True,
               'items': {'type': 'string', 'pattern': '^[a-z0-9]+(-[a-z0-9]+)*$'}},
    'dynamic_metadata': {'type': 'object', 'minProperties': 1, 'additionalProperties': False,
                         'properties': {
                             'version': {'type': 'string', 'minLength': 1, 'maxLength': 128},
                             'requires-python': {'type': 'string', 'maxLength': 1024},
                             'dependencies': {'type': 'array', 'maxItems': 64,
                                              'items': {'type': 'string', 'maxLength': 4096}},
                             'optional-dependencies': {'type': 'object', 'maxProperties': 64,
                                 'propertyNames': {'pattern': '^[a-z0-9]+(-[a-z0-9]+)*$'},
                                 'additionalProperties': {'type': 'array', 'maxItems': 64,
                                     'items': {'type': 'string', 'maxLength': 4096}}},
                         }},
    'editable_resources': {'type': 'array', 'minItems': 1, 'maxItems': 128,
                           'uniqueItems': True, 'items': ID},
    'build_sha256': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'},
    'native_build_view': {'enum': ['full', 'setuptools-src-v1']},
})
WORKSPACE_SCHEMA['properties']['project']['properties']['npm_dependencies']['properties']['registry_config_sha256'] = {
    'type': 'string', 'pattern': '^[0-9a-f]{64}$'}
WORKSPACE_SCHEMA['properties']['project']['properties']['npm_dependencies']['properties'].update({
    'root': {'type': 'string', 'maxLength': 1024},
    'sources': {'type': 'array', 'maxItems': 64, 'items': obj({
        'path': {'type': 'string', 'minLength': 1, 'maxLength': 1024},
        'resources': {'type': 'array', 'minItems': 1, 'maxItems': 128, 'uniqueItems': True, 'items': ID},
        'snapshot_sha256': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'},
    })},
})
for node in [WORKSPACE_SCHEMA["properties"]["project"], WORKSPACE_SCHEMA["properties"]["tasks"]["items"]]:
    node["properties"]["grants"]["items"]["properties"]["actions"]["items"]["enum"] = FILE_ACTIONS
    node["required"].append("commands")
WORKSPACE_SCHEMA["properties"]["project"]["properties"]["commands"] = {
    "type": "array", "maxItems": 64, "items": COMMAND}
WORKSPACE_SCHEMA["properties"]["tasks"]["items"]["properties"]["commands"] = {
    "type": "array", "maxItems": 64, "uniqueItems": True, "items": ID}


def relative(value, *, empty=False):
    if empty and value == "":
        return ""
    if (not isinstance(value, str) or not value or len(value) > 1024 or
            PurePosixPath(value).is_absolute() or "\\" in value or
            any(ord(c) < 32 for c in value) or
            any(p in ("", ".", "..") for p in value.split("/"))):
        raise Invalid("Use a normalized relative path without traversal")
    return value


def directory_fd(path):
    """Open a canonical directory without following any link."""
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in Path(path).parts[1:]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def resource_info(inv, resource):
    item = inv["resources"][resource]
    path = Path(inv["root"]) / item["path"]
    if item.get("kind", "file") == "tree":
        fd = directory_fd(path)
        try:
            return os.fstat(fd)
        finally:
            os.close(fd)
    from .policy import open_resource
    try:
        fd = open_resource(inv, item["path"], os.O_RDONLY)
    except FileNotFoundError:
        fd = directory_fd(path.parent)
        os.close(fd)
        return None
    try:
        return os.fstat(fd)
    finally:
        os.close(fd)


def validate_workspace(policy, inv):
    validate(WORKSPACE_SCHEMA, policy)
    if 'python_runtime' in policy['project']:
        from .python_runtime import verify
        verify(policy['project']['python_runtime'])
    descriptor = policy['project'].get('python_dependencies')
    if descriptor:
        if 'python_runtime' not in policy['project']:
            raise Invalid('Dependency resolution requires a reviewed Python runtime')
        for name in descriptor['inputs']:
            relative(name)
        from .package_evidence import pins
        chosen = pins(descriptor['pins'], extras={}) if descriptor['pins'] else {}
        if not {'pypi:' + n for n in chosen} <= set(policy['project']['packages']['allowed_names']):
            raise Invalid('Dependency resolution expands package scope')
        if (len(descriptor['artifacts']) != len(chosen) or
                {e['name']: e['version'] for e in descriptor['artifacts']} != chosen):
            raise Invalid('Dependency artifact identities do not match pins')
        from .python_local import validate_sources
        validate_sources(policy, inv)
    paths = [r["path"] for r in inv["resources"].values()]
    npm = policy['project'].get('npm_dependencies')
    if npm:
        for name in npm['inputs']:
            relative(name)
        identities = [(e['name'], e['version']) for e in npm['artifacts']]
        if len(identities) != len(set(identities)) or not {'npm:' + n for n, _ in identities} <= set(
                policy['project']['packages']['allowed_names']):
            raise Invalid('npm dependency resolution duplicates identities or expands package scope')
        root = relative(npm.get('root', ''), empty=True)
        seen = set()
        for source in npm.get('sources', []):
            path = relative(source['path'])
            if path in seen:
                raise Invalid('Duplicate npm local source')
            seen.add(path)
            location = str(PurePosixPath(root) / path)
            for key in source['resources']:
                if key not in inv['resources'] or not inv['resources'][key]['path'].startswith(location + '/'):
                    raise Invalid('Local npm source resources must stay in their approved source directory')
                if 'read' not in scope(policy['project']['grants']).get(key, set()):
                    raise Invalid('Local npm source requires explicit project read authority')
    for i, path in enumerate(paths):
        for other in paths[i + 1:]:
            if path == other or path.startswith(other + "/") or other.startswith(path + "/"):
                raise Invalid("Workspace resources must not overlap")
    grants = scope(policy["project"]["grants"])
    commands = {}
    for command in policy["project"]["commands"]:
        if 'git' in command:
            if ('preview' in command or command.get('cwd') or
                    command['argv'] != ['/usr/bin/git', command['git']['operation']]):
                raise Invalid('Git operations use the fixed local adapter only')
            if any('.git' in inv['resources'][r]['path'].split('/')
                   for r in command['resources'] if r in inv['resources']):
                raise Invalid('Git metadata cannot be a worktree resource')
        cwd = relative(command.get('cwd', ''), empty=True)
        if cwd and not any(inv['resources'][r]['path'] == cwd or
                inv['resources'][r]['path'].startswith(cwd + '/') or
                (inv['resources'][r].get('kind') == 'tree' and cwd.startswith(inv['resources'][r]['path'] + '/'))
                for r in command['resources'] if r in inv['resources']):
            raise Invalid('Command cwd must be inside its declared input layout')
        if command["id"] in commands:
            raise Invalid("Duplicate command ID")
        if any("\x00" in a for a in command["argv"]):
            raise Invalid("NUL in command")
        if any("read" not in grants.get(r, set()) for r in command["resources"]):
            raise Invalid("Commands require project read permission for their resources")
        commands[command["id"]] = command
    for task in policy["tasks"]:
        if not set(task["commands"]) <= commands.keys():
            raise Invalid("Task commands expand project scope")
        task_grants = scope(task["grants"])
        if any("read" not in task_grants.get(r, set())
               for name in task["commands"] for r in commands[name]["resources"]):
            raise Invalid("Task command requires read permission for every input resource")
