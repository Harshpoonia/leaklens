"""Low-level git access.

Core idea: instead of diffing every commit (slow: the same file content gets
re-scanned on every commit that touches it), we enumerate every *unique blob*
(file content) that has ever existed in the repo and scan each one exactly once.
Findings are mapped back to commits afterwards, only for blobs that matched.

Uses only git plumbing commands, so there are no third-party dependencies:
  git rev-list --objects --all   -> every object reachable from any ref
  git cat-file --batch-check     -> type + size for each, to filter to blobs
  git cat-file --batch           -> stream blob contents in one process
"""
from __future__ import annotations

import subprocess
import threading
from dataclasses import dataclass
from typing import Iterable, Iterator


class GitError(RuntimeError):
    """Raised when a git command fails (not a repo, git missing, etc.)."""


def git(repo: str, *args: str, stdin: bytes | None = None) -> bytes:
    """Run a git command in `repo` and return stdout as bytes."""
    try:
        proc = subprocess.run(
            ["git", "-C", repo, *args],
            input=stdin,
            capture_output=True,
            check=True,
        )
    except FileNotFoundError as e:
        raise GitError("git is not installed or not on PATH") from e
    except subprocess.CalledProcessError as e:
        msg = e.stderr.decode(errors="replace").strip() or str(e)
        raise GitError(msg) from e
    return proc.stdout


@dataclass(frozen=True)
class BlobRef:
    sha: str
    path: str  # first path git saw this blob at (a blob can live at several)
    size: int


@dataclass(frozen=True)
class Blob:
    ref: BlobRef
    data: bytes


def ensure_repo(repo: str) -> None:
    git(repo, "rev-parse", "--git-dir")


def list_blobs(repo: str, max_size: int) -> list[BlobRef]:
    """Every unique blob reachable from any branch/tag, up to max_size bytes."""
    objects = git(repo, "rev-list", "--objects", "--all")
    if not objects.strip():
        return []  # empty repo, no commits yet

    info = git(
        repo,
        "cat-file",
        "--batch-check=%(objecttype) %(objectname) %(objectsize) %(rest)",
        stdin=objects,
    )

    refs: list[BlobRef] = []
    for line in info.decode("utf-8", "replace").splitlines():
        parts = line.split(" ", 3)
        if len(parts) < 3 or parts[0] != "blob":
            continue
        size = int(parts[2])
        if size > max_size:
            continue
        path = parts[3] if len(parts) == 4 else ""
        refs.append(BlobRef(sha=parts[1], path=path, size=size))
    return refs


def read_blobs(repo: str, refs: Iterable[BlobRef]) -> Iterator[Blob]:
    """Stream blob contents through a single `git cat-file --batch` process.

    A writer thread feeds SHAs on stdin while we read stdout, so neither pipe
    can fill up and deadlock on large repos.
    """
    refs = list(refs)
    if not refs:
        return

    proc = subprocess.Popen(
        ["git", "-C", repo, "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    assert proc.stdin and proc.stdout

    def feed() -> None:
        try:
            # One big write instead of one per SHA (profiling: 7% on Windows).
            # Still on a thread, because git won't read all of it until we
            # drain stdout, and a blocking write here would deadlock.
            proc.stdin.write(b"".join(ref.sha.encode() + b"\n" for ref in refs))
        except BrokenPipeError:
            pass
        finally:
            try:
                proc.stdin.close()
            except BrokenPipeError:
                pass

    writer = threading.Thread(target=feed, daemon=True)
    writer.start()

    try:
        for ref in refs:
            header = proc.stdout.readline()  # b"<sha> blob <size>\n"
            parts = header.split()
            if len(parts) < 3:  # "<sha> missing" or EOF
                continue
            size = int(parts[2])
            data = proc.stdout.read(size)
            proc.stdout.read(1)  # trailing newline after each object
            yield Blob(ref=ref, data=data)
    finally:
        proc.stdout.close()
        proc.wait()
        writer.join(timeout=1)
