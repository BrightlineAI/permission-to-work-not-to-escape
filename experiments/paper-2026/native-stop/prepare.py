#!/usr/bin/env python3
"""Prepare an isolated, portable copy; never run a model or benchmark itself."""
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--work',type=Path,required=True,help='new absolute directory on a Linux VPS')
    p.add_argument('--revision',help='optional included historical revision, e.g. 2f5bcba')
    p.add_argument('--codex',default=shutil.which('codex') or 'codex')
    p.add_argument('--sessions',type=Path,default=Path.home()/'.codex/sessions')
    a=p.parse_args()
    if platform.system()!='Linux':p.error('Prepare and run benchmark environments on a Linux VPS.')
    if not a.work.is_absolute():p.error('--work must be absolute')
    work=a.work.resolve()
    if work.exists():p.error('--work must not already exist; every environment is separate')
    package=Path(__file__).resolve().parent
    source=package/'historical'/a.revision if a.revision else package
    if a.revision and (not source.is_dir() or source.parent!=package/'historical'):
        p.error('unknown included historical revision')
    if package==work or package in work.parents:p.error('keep working directories outside the evidence package')
    work.mkdir(parents=True)
    code=work/'code'
    shutil.copytree(source,code,ignore=shutil.ignore_patterns('evidence','historical','__pycache__',
        '*.pyc','.git','.venv','.runtime-tools','MANIFEST.sha256','prepare.py','verify.py'))
    if (package/'support').exists() and not (code/'support').exists():
        shutil.copytree(package/'support',code/'support')
    runs=work/'runs';runs.mkdir()
    changes=[]
    ports={}
    codex_path=str(Path(a.codex).resolve()) if '/' in a.codex else a.codex
    if package.name=='vega-core':
        sockets=[]
        try:
            for old in ['39000','39080']:
                sock=socket.socket();sock.bind(('127.0.0.1',0));sockets.append(sock)
                ports[old]=str(sock.getsockname()[1])
        finally:
            for sock in sockets:sock.close()
    replacements={
        '/home/loon/benchmarks/vega/native-delegation/':str(runs)+'/',
        '/home/loon/benchmarks/vega/native-stop/':str(runs)+'/',
        '/home/loon/benchmarks/vega/native-stop':str(runs),
        '/home/loon/benchmarks/vega/benchmark-comparison/permission-diagnostics':str(runs),
        '/home/loon/.codex/sessions':str(a.sessions.resolve()),
        '/home/loon/.npm-global/bin/codex':codex_path,
        "['codex'":'['+repr(codex_path),
        "'--uid=loon'":repr('--uid='+getpass.getuser()),
        'ROOT.parent / "permission-preservation"':'ROOT / "support" / "permission-preservation"',
        'ROOT.parents[2]':'ROOT',
        '"evidence" not in path.parts':'"evidence" not in path.parts and ".git" not in path.parts',
        **ports,
    }
    for f in sorted(code.rglob('*')):
        if not f.is_file() or f.suffix not in {'.py','.sh','.yaml','.yml'}:continue
        original=f.read_text();updated=original
        applied=[]
        for old,new in replacements.items():
            if old in updated:updated=updated.replace(old,new);applied.append({'old':old,'new':new})
        if f.suffix=='.sh':
            old='nono=${VEGA_BENCHMARK_NONO:-/home/loon/benchmarks/vega/benchmark-comparison/20260912-basharena-nono/bin/nono}'
            updated=updated.replace(old,': "${VEGA_BENCHMARK_NONO:?set VEGA_BENCHMARK_NONO to the reviewed nono binary}"\nnono=$VEGA_BENCHMARK_NONO')
            updated=updated.replace('  doppler run -p algol -c prd -- env PYTHONPATH="$root/src" "${run[@]}"',
                '  echo "Set OPENROUTER_API_KEY for a model run, or explicitly select --forced-as-captures for a deterministic test." >&2\n  exit 2')
        if updated!=original:
            before=digest(f);f.write_text(updated)
            changes.append(dict(path=str(f.relative_to(code)),before=before,after=digest(f),path_replacements=applied))
    if package.name=='dtap-vega':
        for f in (code/'scripts').iterdir():
            if f.suffix in {'.py','.sh'}:f.chmod(0o755)
        (code/'scripts/vps-bin/docker').chmod(0o755)
    ignore=code/'.gitignore'
    before_ignore=ignore.read_text() if ignore.exists() else ''
    ignore.write_text(before_ignore+'\n# Portable experiment runtime files\n__pycache__/\n*.py[cod]\n.pytest_cache/\n*.egg-info/\n.venv/\n.runtime-tools/\n')
    changes.append(dict(path='.gitignore',before=hashlib.sha256(before_ignore.encode()).hexdigest(),
                        after=digest(ignore),reason='Ignore generated runtime files before freezing code.'))
    # Existing integrity guards require a clean code revision. Freeze this portable
    # copy in its own local repository; it has no remote and cannot modify the source.
    subprocess.run(['git','init','-q',str(code)],check=True)
    subprocess.run(['git','-C',str(code),'add','.'],check=True)
    subprocess.run(['git','-C',str(code),'-c','user.name=Experiment Reproducer',
        '-c','user.email=reproducer@localhost','-c','commit.gpgsign=false','commit','-qm',
        'Freeze isolated portable experiment source'],check=True)
    revision=subprocess.check_output(['git','-C',str(code),'rev-parse','HEAD'],text=True).strip()
    manifest=dict(experiment=package.name,original_revision=a.revision or 'exported-source',
        portable_code_commit=revision,work=str(work),source=str(source),path_adaptations=changes,allocated_ports=ports,
        source_hashes={str(f.relative_to(code)):digest(f) for f in sorted(code.rglob('*'))
            if f.is_file() and '.git' not in f.relative_to(code).parts},
        note='Fresh reproduction source; do not label its outputs as the historical recorded run.')
    (work/'preparation.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'code':str(code),'runs':str(runs),'portable_code_commit':revision,
        'adapted_files':len(changes),'model_calls':0},indent=2))


if __name__=='__main__':main()
