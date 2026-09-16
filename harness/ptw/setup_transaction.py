"""Recoverable operator publication. A pending controller cannot issue sessions."""
import ctypes
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import stat

from .policy import Invalid, check_approval, digest, load, save
from .store import Store
from .workspace_policy import directory_fd


def sync(path):
    fd = directory_fd(path)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, value):
    temporary = path.with_name(path.name + "." + secrets.token_hex(8))
    save(temporary, value)
    os.replace(temporary, path)
    sync(path.parent)


def fingerprint(path):
    """No followed links, hardlinked files or special files, including parents."""
    fd = directory_fd(path.parent)
    try:
        try:
            info = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        result = {"device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode}
        if stat.S_ISDIR(info.st_mode):
            result["kind"] = "directory"
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 8 * 1024 * 1024:
            opened = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            with os.fdopen(opened, "rb") as stream:
                actual = os.fstat(stream.fileno())
                if (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino):
                    raise Invalid("Setup input changed while reading")
                result.update(kind="file", sha256=hashlib.sha256(stream.read(8 * 1024 * 1024 + 1)).hexdigest())
        else:
            raise Invalid("Setup requires bounded ordinary files/directories: " + str(path))
        return result
    finally:
        os.close(fd)


def move(source, destination):
    """Linux no-replace rename, with pinned, no-follow parent descriptors."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    if rename is None:
        raise Invalid("Transactional setup requires Linux renameat2 support")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    old, new = directory_fd(source.parent), directory_fd(destination.parent)
    try:
        if rename(old, os.fsencode(source.name), new, os.fsencode(destination.name), 1):
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code), str(destination))
        os.fsync(old)
        os.fsync(new)
    finally:
        os.close(old)
        os.close(new)


def validate_artifacts(journal):
    record = journal["record"]
    if load(Path(journal["directory"]) / "project.json") != record:
        raise Invalid("Setup registration changed")
    bundle = load(record["bundle"])
    if bundle["approval"]["sha256"] != record["policy_sha256"]:
        raise Invalid("Setup approval changed")
    if load(Path(record["repo"]) / ".ptw/policy.json") != bundle["policy"]:
        raise Invalid("Setup review copy changed")
    for operation in journal["operations"]:
        if fingerprint(Path(operation["destination"])) != operation["new"]:
            raise Invalid("Published setup artifact changed")


def validate_registration(record):
    """Later launches need the durable approval, not unchanged editable source bytes."""
    bundle = load(record["bundle"])
    check_approval(bundle)
    if (bundle["approval"]["sha256"] != record["policy_sha256"] or
            bundle["inventory"]["root"] != record["repo"] or
            bundle["policy"]["project"]["id"] != record["project"]):
        raise Invalid("Committed setup registration differs from its approval")
    store = Store(record["state"])
    with store.locked() as db:
        row, active = store.project(db, record["project"])
        if active != bundle or row["setup_pending"]:
            raise Invalid("Setup approval differs from controller state")
    review = fingerprint(Path(record["repo"]) / ".ptw/policy.json")
    if review is None or review["kind"] != "file":
        raise Invalid("Committed setup review copy is missing; recover it before launch")


def staging_entries(journal):
    """Check ownership before either successful cleanup or rollback removal."""
    local = Path(journal["local"])
    if fingerprint(local) is None:
        return []
    if fingerprint(local) != journal["local_identity"]:
        raise Invalid("Setup staging directory changed")
    expected = {Path(op[key]).name: op[value] for op in journal["operations"]
                for key, value in (("source", "new"), ("backup", "old")) if Path(op[key]).parent == local}
    entries = list(local.iterdir())
    for entry in entries:
        if fingerprint(entry) != expected.get(entry.name) or (entry.is_dir() and any(entry.iterdir())):
            raise Invalid("Recovery found unexpected staging content; preserving it")
    return entries


def remove_staging(journal):
    for entry in staging_entries(journal):
        # rmdir, never recursive removal: late directory additions must survive.
        if entry.is_dir():
            entry.rmdir()
        else:
            entry.unlink()
    Path(journal["local"]).rmdir()


def finish(journal):
    local = Path(journal["local"])
    staging_entries(journal)
    if not local.exists():
        return
    backup = Path(journal["record"]["bundle"]).parent / "publication-backups"
    shutil.copytree(local, backup, dirs_exist_ok=True)
    remove_staging(journal)
    sync(local.parent)


def recover(directory):
    """Run under onboarding.lock. Never activate an identity twice or revive old work."""
    path = directory / "setup-journal.json"
    if not path.exists():
        return
    journal = load(path)
    if journal["phase"] == "committed":
        finish(journal)
        return
    if journal["phase"] == "rolled-back":
        return
    if journal["phase"] == "preparing":
        # No destination or controller has changed. Partial objects may not yet
        # have identities in the journal; retain them outside the repository,
        # including any concurrent additions, rather than guessing ownership.
        journal["phase"] = "rolled-back"
        atomic(path, journal)
        return
    store = Store(directory / "controller")
    record = journal["record"]
    with store.locked() as db:
        row = db.execute("SELECT * FROM projects WHERE id=?", (record["project"],)).fetchone()
    if row is not None and not row["setup_pending"]:
        try:
            validate_artifacts(journal)
        except BaseException:
            store.stop(record["project"], "Committed setup artifacts need operator recovery")
            raise
        journal["phase"] = "committed"
        atomic(path, journal)
        finish(journal)
        return
    if row is not None:
        store.stop(record["project"], "Interrupted setup; history retained")
    journal["phase"] = "rolling-back"
    atomic(path, journal)
    try:
        for operation in reversed(journal["operations"]):
            destination, source, backup = map(Path, (operation["destination"], operation["source"], operation["backup"]))
            # A parent may not have been published yet.
            current = fingerprint(destination) if destination.parent.exists() else None
            if current == operation["new"]:
                if current["kind"] == "directory" and any(destination.iterdir()):
                    raise Invalid("Recovery found user changes in generated directory")
                move(destination, source)
                current = None
            if current is not None and current != operation["old"]:
                raise Invalid("Recovery conflict; preserving concurrent changes: " + str(destination))
            saved = fingerprint(backup) if backup.parent.exists() else None
            if saved is not None:
                if saved != operation["old"] or current is not None:
                    raise Invalid("Recovery backup conflict; inspect retained journal")
                move(backup, destination)
        local = Path(journal["local"])
        if local.exists():
            # Never discard edits to staged files or files added by another process.
            remove_staging(journal)
            sync(local.parent)
        journal["phase"] = "rolled-back"
        atomic(path, journal)
    except BaseException:
        journal["phase"] = "recovery-conflict"
        atomic(path, journal)
        raise


def publish(repo, directory, stage, bundle, record, generated, trees, inputs, previous=None):
    """Only called following explicit approval. Pre-commit errors roll back owned changes."""
    from .monitor import ensure
    from .supervisor import Supervisor
    approval = load(stage / "setup-approval.json")
    if (approval["policy_sha256"] != bundle["approval"]["sha256"] or
            approval["publication_sha256"] != digest({"generated": generated, "directories": trees}) or
            record["publication_sha256"] != approval["publication_sha256"]):
        raise Invalid("Publication changed after approval")
    sync(stage)
    sync(directory)
    # Prepare outside project data. Prefer the private attempt directory, but
    # keep renames on the project's filesystem when state is on another mount.
    device = repo.stat().st_dev
    parent = stage if stage.stat().st_dev == device else repo.parent
    if parent.stat().st_dev != device:
        raise Invalid("Setup needs external staging on the project filesystem; place PTW_USER_STATE there")
    local = parent / (".ptw-setup-" + secrets.token_hex(12))
    journal = {"phase": "preparing", "directory": str(directory), "record": record,
               "local": str(local), "local_identity": None, "operations": []}
    path = directory / "setup-journal.json"
    # Keep every attempt, including previous journals, in its unique private stage.
    if path.exists():
        save(stage / "preceding-journal.json", load(path))
    atomic(path, journal)
    try:
        for name, expected in inputs.items():
            if fingerprint(repo / name) != expected:
                raise Invalid("Repository changed since review: " + name)
        local.mkdir(mode=0o700)
        sync(local.parent)
        journal["local_identity"] = fingerprint(local)
        atomic(path, journal)
        destinations = [(repo / name, None) for name in trees]
        destinations += [(repo / name, content) for name, content in generated.items()]
        if not (repo / ".ptw").exists():
            destinations.append((repo / ".ptw", None))
        destinations.append((repo / ".ptw/policy.json", bundle["policy"]))
        destinations.append((directory / "project.json", record))
        for index, (destination, content) in enumerate(destinations):
            staging = stage if destination.parent == directory else local
            source, backup = staging / ("publish-" + str(index)), staging / ("backup-" + str(index))
            if content is None:
                source.mkdir()
            elif isinstance(content, str):
                with source.open("x") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
            else:
                save(source, content)
            sync(staging)
            old = fingerprint(destination) if destination.parent.exists() else None
            # Only the reviewed policy copy and protected registration may be replaced.
            if old is not None and destination not in (repo / ".ptw/policy.json", directory / "project.json"):
                raise Invalid("Generated destination already exists")
            operation = {"destination": str(destination), "source": str(source), "backup": str(backup),
                         "old": old, "new": fingerprint(source)}
            journal["operations"].append(operation)
            atomic(path, journal)
        # This durable boundary precedes ALL destination/controller effects.
        # Recovery can now require complete staged identities, as before.
        journal["phase"] = "approved"
        atomic(path, journal)
        store = Store(directory / "controller")
        ensure(store)
        if previous:
            store.stop(previous["project"], "Operator approved replacement policy " + record["project"])
            if any(not item["confirmed_stopped"] for item in Supervisor(store).reconcile()):
                raise Invalid("Old work has not stopped; revision cannot activate")
        journal["phase"] = "publishing"
        atomic(path, journal)
        for operation in journal["operations"]:
            destination = Path(operation["destination"])
            if fingerprint(destination) != operation["old"]:
                raise Invalid("Destination changed after review")
            if operation["old"] is not None:
                move(destination, Path(operation["backup"]))
            move(Path(operation["source"]), destination)
        store.activate(bundle, setup_pending=True)
        journal["phase"] = "activated-pending"
        atomic(path, journal)
        store.commit_setup(record["project"], record["policy_sha256"], lambda: validate_artifacts(journal))
        journal["phase"] = "committed"
        atomic(path, journal)
        # Backups and receipts are evidence; move them outside the user repository.
        finish(journal)
    except BaseException:
        recover(directory)
        raise
