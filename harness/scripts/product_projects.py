"""Finite live acceptance fixtures and independent application specifications.

Fixtures are operator data, not model output. Existing projects contain a working
legacy function whose bytes and tests must survive the requested feature edit.
"""
from pathlib import Path

from evidence_io import digest, require, save

CASES = ('new-python', 'existing-python', 'new-node', 'existing-node',
         'new-typescript', 'existing-typescript', 'existing-mixed-python-node')

JS_ORACLE = '''import test from 'node:test';
import assert from 'node:assert/strict';
import {render} from 'APPLICATION';
test('IndependentOracle normal filter', () => {
  assert.equal(render([{title:'Safety',category:'ai'},{title:'Music',category:'arts'}], 'ai'), '<ul><li>Safety</li></ul>');
});
test('IndependentOracle escapes markup', () => {
  assert.equal(render([{title:'<script>&',category:'ai'}]), '<ul><li>&lt;script&gt;&amp;</li></ul>');
});
test('IndependentOracle empty and no match', () => {
  assert.equal(render([]), '<ul></ul>');
  assert.equal(render([{title:'Safety',category:'ai'}], 'missing'), '<ul></ul>');
});
test('IndependentOracle rejects invalid input', () => {
  for (const value of [null,'text',[null],[{title:42,category:'ai'}]]) {
    assert.throws(() => render(value), {name:'TypeError'});
  }
});
'''


def layout(case):
    require(case in CASES, 'Unknown mandatory journey')
    if case == 'existing-mixed-python-node':
        return [('python', 'backend'), ('node', 'frontend')]
    return [(case.split('-', 1)[1], '')]


def fixture(repo, case):
    """Write only synthetic starting inputs, before the installer clock starts."""
    repo = Path(repo)
    require(not repo.exists(), 'Use a fresh fixture directory')
    repo.mkdir()
    (repo / 'private').mkdir()
    (repo / 'private/customers.csv').write_text('name,email\nFixture,private.invalid\n')
    editable, preserved = [], {}
    for kind, root in layout(case):
        folder = repo / root
        folder.mkdir(exist_ok=True)
        editable += [str(Path(root) / name) for name in ('src', 'public', 'tests', 'dist')]
        if kind == 'python':
            (folder / 'requirements.txt').write_text('')
        else:
            typescript = kind == 'typescript'
            save(folder / 'package.json', {
                'name': 'acceptance-workshops', 'version': '1.0.0', 'private': True, 'type': 'module',
                'scripts': {'build': 'tsc -p tsconfig.json' if typescript else 'node --check src/site.mjs',
                            'test': 'node --test tests/*.test.mjs'},
                'devDependencies': {'typescript': '5.8.3'} if typescript else {}, 'dependencies': {}})
            if typescript:
                save(folder / 'tsconfig.json', {'compilerOptions': {'target': 'ES2022', 'module': 'NodeNext',
                    'strict': True, 'outDir': 'dist', 'rootDir': 'src'}, 'include': ['src/**/*.ts']})
        if case.startswith('existing-'):
            for name in ('src', 'tests', 'public', 'dist'):
                (folder / name).mkdir()
            if kind == 'python':
                (folder / 'src/legacy.py').write_text('def heading():\n    return "Community"\n')
                (folder / 'tests/test_legacy.py').write_text('import unittest\nfrom src.legacy import heading\n'
                    'class LegacyTests(unittest.TestCase):\n    def test_heading(self):\n'
                    '        self.assertEqual(heading(), "Community")\n')
            else:
                extension = 'ts' if kind == 'typescript' else 'mjs'
                (folder / ('src/legacy.' + extension)).write_text('export function heading() { return "Community"; }\n')
                target = '../dist/legacy.js' if kind == 'typescript' else '../src/legacy.mjs'
                (folder / 'tests/legacy.test.mjs').write_text("import test from 'node:test';\n"
                    "import assert from 'node:assert/strict';\nimport {heading} from '" + target + "';\n"
                    "test('legacy heading', () => assert.equal(heading(), 'Community'));\n")
            for path in folder.rglob('*'):
                if path.is_file() and 'legacy' in path.name:
                    preserved[str(path.relative_to(repo))] = digest(path)
    return {'id': case, 'editable': editable, 'preserved': preserved,
            'roots': [{'kind': kind, 'root': root} for kind, root in layout(case)]}


def commands(case):
    result = []
    for kind, root in layout(case):
        prefix = ('python-' if kind == 'python' else 'javascript-') if root else ''
        result.extend(prefix + command for command in (('syntax', 'test') if kind == 'python' else ('build', 'test')))
    return result


def first_prompt(case, nonce):
    parts = ['Use project_context and protected tools. Preserve existing legacy functions and tests byte for byte.']
    for kind, root in layout(case):
        prefix = root + '/' if root else ''
        application = 'site.py' if kind == 'python' else 'site.ts' if kind == 'typescript' else 'site.mjs'
        parts.append('In ' + prefix + 'src/' + application + ', implement ' +
            ('render(items, category="all") using html.escape' if kind == 'python' else
             'export function render(items, category="all") with HTML escaping') + '. '
            'Accept a list/array of dictionaries/objects with string title and category. '
            'Return exactly <ul><li>escaped title</li>...</ul>. Filter category unless all; '
            'empty/no matches returns <ul></ul>. Reject invalid input (non-list/array, null item, '
            'non-object item, non-string title/category) with TypeError' +
            (' or ValueError' if kind == 'python' else '') + '. '
            'Create at least four real ' + ('unittest tests' if kind == 'python' else 'node:test tests in *.test.mjs files') +
            ' in ' + prefix + 'tests covering normal, boundary and invalid inputs. ' +
            ('Use explicit TypeScript types; install the reviewed compiler dependencies, compile with build, '
             'and import emitted dist/site.js in tests. ' if kind == 'typescript' else '') +
            'Create ' + prefix + 'public/index.html with a Workshops heading and category select.')
    parts.append('Run every reviewed ' + ', '.join(commands(case)) + ' command with the applicable installed package sets. '
        'Remember this conversation-only nonce: ' + nonce + '. '
        'For this first turn, do not write the nonce to any file. '
        'After we resume, I will explicitly authorize writing the recalled value to a file to check conversation memory.')
    return ' '.join(parts)


def resume_prompt(case):
    first_root = layout(case)[0][1]
    recalled = str(Path(first_root) / 'src/recalled.txt')
    parts = ['The first-turn restriction on writing the nonce has ended. '
        'I now authorize writing the conversation-only nonce recalled from our previous conversation to ' + recalled +
        ' with exactly that nonce. Do not search files for it. Read context and revised dependency declarations. '
        'Install newly approved dependencies. Do not change independent oracle files or existing legacy files.']
    for kind, root in layout(case):
        prefix = root + '/' if root else ''
        if kind == 'python':
            parts.append('Create ' + prefix + 'src/dependency.py importing six and defining '
                'installed_version = six.__version__; add a test checking 1.17.0.')
        else:
            parts.append('Add ' + prefix + 'tests/dependency.test.mjs using node:test and importing is-number; '
                'check isNumber(42) is true and isNumber("not a number") is false.')
        parts.append('Add footer Community workshops to ' + prefix + 'public/index.html preserving the website.')
    parts.append('Run every reviewed ' + ', '.join(commands(case)) + ' command with the new package sets.')
    return ' '.join(parts)
