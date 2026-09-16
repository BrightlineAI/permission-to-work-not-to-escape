"""Bounded tmpfs build, registered with the project supervisor, exporting only data."""
import os
from pathlib import Path, PurePosixPath
import select
import shutil
import subprocess
import tarfile
import tempfile
import time

from .package_evidence import EvidenceError
from .supervisor import Supervisor

LIMIT = 512 * 1024 * 1024


class UnsafeExport(EvidenceError):
    """Export attempts a path/type operation outside the publication boundary."""


WRAPPER = """
import os,shutil,subprocess,sys,tarfile
shutil.copytree('/seed','/target',dirs_exist_ok=True)
r=subprocess.run(sys.argv[1:],stdin=subprocess.DEVNULL,stdout=sys.stderr,stderr=sys.stderr)
if r.returncode: sys.exit(r.returncode)
with tarfile.open(fileobj=sys.stdout.buffer,mode='w|') as out:
    # npm/esbuild legitimately creates hard links. Export independent bytes,
    # never host inode aliases. Keep symbolic links for explicit validation.
    def independent_files(info):
        out.inodes.clear()
        return info
    out.add('/target',arcname='result',recursive=True,filter=independent_files)
"""


def extract_result(archive_path, destination):
    """Validate all names before writing; never trust build-created tar metadata."""
    with tarfile.open(fileobj=archive_path, mode="r:") as archive:
        members, expanded = [], 0
        for member in archive:
            expanded += member.size
            if len(members) >= 50000 or expanded > LIMIT:
                raise EvidenceError("Build output exceeds publication limit")
            members.append(member)
        seen, links = set(), []
        for member in members:
            parts = PurePosixPath(member.name).parts
            if (not parts or parts[0] != "result" or "\\" in member.name or
                    any(p in ("", ".", "..") for p in member.name.rstrip("/").split("/")) or
                    member.name in seen or not (member.isfile() or member.isdir() or member.issym())):
                raise UnsafeExport("Unsafe build output member")
            seen.add(member.name)
            if len(parts) == 1:
                if not member.isdir():
                    raise UnsafeExport("Invalid build output root")
                continue
            if member.issym():
                link = Path(member.linkname)
                intended = destination.joinpath(*parts[1:]).parent / link
                if link.is_absolute() or not intended.resolve().is_relative_to(destination.resolve()):
                    raise UnsafeExport("Build output link escapes its package set")
                links.append(member)
        # A symlink may not be an ancestor of another output, even if it is created last.
        names = {m.name.rstrip("/") for m in links}
        if any(any(str(p) in names for p in PurePosixPath(m.name).parents) for m in members):
            raise UnsafeExport("Build output writes through a link")
        for member in members:
            parts = PurePosixPath(member.name).parts[1:]
            if not parts or member.issym():
                continue
            path = destination.joinpath(*parts)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, path.open("xb") as target:
                    shutil.copyfileobj(source, target, length=65536)
                path.chmod(0o700 if member.mode & 0o111 else 0o600)
        for member in links:
            path = destination.joinpath(*PurePosixPath(member.name).parts[1:])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(member.linkname)
        for member in links:
            path = destination.joinpath(*PurePosixPath(member.name).parts[1:])
            try:
                if not path.resolve(strict=True).is_relative_to(destination.resolve()):
                    raise UnsafeExport("Build output link escapes its package set")
            except (OSError, RuntimeError) as exc:
                raise UnsafeExport("Broken or cyclic build output link") from exc


def run_build(store, token, command, target):
    """Convert the adapter's sole writable bind into bounded disposable memory."""
    try:
        boundary = command.index("--")
        prefix, payload = command[:boundary], command[boundary + 1:]
        index = prefix.index("--bind")
        if prefix[index:index + 3] != ["--bind", str(target), "/target"] or "--bind" in prefix[index + 3:]:
            raise ValueError()
        prefix[index:index + 3] = ["--ro-bind", str(target), "/seed", "--size", str(LIMIT), "--tmpfs", "/target"]
    except ValueError as exc:
        raise EvidenceError("Build adapter supplied an unexpected mount layout") from exc
    bounded = prefix + ["--", "/usr/bin/python3", "-I", "-S", "-c", WRAPPER, *payload]
    supervisor = Supervisor(store)
    with tempfile.TemporaryFile(dir=store.directory) as logs, tempfile.TemporaryFile(dir=store.directory) as archive:
        process, unit = supervisor.engine(token, bounded, stderr=logs)
        process.stdin.close()
        deadline, size = time.monotonic() + 180, 0
        try:
            while True:
                if time.monotonic() >= deadline:
                    raise EvidenceError("Confined build timed out")
                ready, _, _ = select.select([process.stdout], [], [], .2)
                if not ready:
                    continue
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > LIMIT:
                    raise EvidenceError("Build output exceeds publication limit")
                archive.write(chunk)
            process.wait(timeout=10)
            if process.returncode:
                logs.seek(0, 2)
                logs.seek(max(0, logs.tell() - 2000))
                raise EvidenceError("Confined build failed: " + logs.read().decode("utf-8", "replace"))
        except (OSError, subprocess.SubprocessError) as exc:
            raise EvidenceError("Build supervision failed") from exc
        finally:
            state = supervisor.terminate(unit)
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
            process.stdout.close()
            if not state["confirmed_stopped"]:
                raise EvidenceError("Build process termination could not be confirmed")
        archive.seek(0)
        # A new empty directory avoids letting an export overwrite trusted seeds.
        output = target.with_name(target.name + "-export")
        output.mkdir(mode=0o700)
        try:
            extract_result(archive, output)
        except EvidenceError:
            raise
        except (ValueError, tarfile.TarError, OSError) as exc:
            raise EvidenceError("Invalid or incomplete build export") from exc
        os.rename(target, target.with_name(target.name + "-seed"))
        os.rename(output, target)
