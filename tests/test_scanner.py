"""End-to-end tests against throwaway git repos.

Fake keys are built by concatenation so this file doesn't trip the scanner
(or GitHub push protection) itself.
"""
import subprocess

import pytest

from leaklens.cli import main
from leaklens.scanner import scan_repo

GOOGLE = "AIza" + "Sy" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"   # 39 chars total
OPENAI = "sk-" + "proj-" + "Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78"


def sh(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    sh(tmp_path, "init", "-q")
    sh(tmp_path, "config", "user.email", "t@example.com")
    sh(tmp_path, "config", "user.name", "Test")
    sh(tmp_path, "config", "commit.gpgsign", "false")
    return tmp_path


def commit(repo, files, msg):
    for name, content in files.items():
        p = repo / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        sh(repo, "add", name)
    sh(repo, "commit", "-q", "-m", msg)


def test_key_deleted_but_still_in_history(repo):
    commit(repo, {"app.py": f'KEY = "{GOOGLE}"\nprint("hi")\n'}, "add gemini")
    commit(repo, {"app.py": 'import os\nKEY = os.environ["KEY"]\nprint("hi")\n'}, "remove key")

    res = scan_repo(str(repo))
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.rule_id == "google-api-key"
    assert not f.in_head
    assert [c.subject for c, _ in f.added_in] == ["add gemini"]
    assert [c.subject for c, _ in f.removed_in] == ["remove key"]
    assert GOOGLE not in f.masked


def test_editing_other_lines_is_not_a_removal(repo):
    commit(repo, {"cfg.py": f'K = "{OPENAI}"\n'}, "add key")
    commit(repo, {"cfg.py": f'K = "{OPENAI}"\nDEBUG = True\n'}, "unrelated edit")

    f = scan_repo(str(repo)).findings[0]
    assert f.in_head
    assert len(f.added_in) == 1 and f.removed_in == []
    assert len(f.locations) == 2  # same secret, two blob versions, one finding


def test_secret_on_unmerged_branch_is_found(repo):
    commit(repo, {"README.md": "hi\n"}, "init")
    sh(repo, "checkout", "-q", "-b", "experiment")
    commit(repo, {".env": f"OPENAI_API_KEY={OPENAI}\n"}, "oops")
    sh(repo, "checkout", "-q", "-")

    f = scan_repo(str(repo)).findings[0]
    assert f.rule_id == "openai-api-key"
    assert not f.in_head  # not on the checked-out branch, but still pushed-able


def test_lockfiles_and_binaries_skipped(repo):
    commit(repo, {"package-lock.json": f'"x": "{GOOGLE}"\n'}, "lock")
    (repo / "img.bin").write_bytes(b"\x00\x01" + GOOGLE.encode())
    sh(repo, "add", "img.bin")
    sh(repo, "commit", "-q", "-m", "bin")
    assert scan_repo(str(repo)).findings == []


def test_entropy_is_opt_in(repo):
    commit(repo, {"s.py": 'api_secret = "q8Zr2LmX9vB4nT7kW1pY6sD3"\n'}, "custom")
    assert scan_repo(str(repo)).findings == []
    f = scan_repo(str(repo), use_entropy=True).findings[0]
    assert f.confidence == "low"


def test_cli_exit_codes(repo, capsys):
    commit(repo, {"a.txt": "clean\n"}, "clean")
    assert main(["scan", str(repo)]) == 0
    commit(repo, {"b.py": f'k="{GOOGLE}"\n'}, "leak")
    assert main(["scan", str(repo)]) == 1
    assert main(["scan", str(repo / "nope")]) == 2


def test_rename_and_full_timeline(repo):
    """Mirrors a real repo: key in 3 files, one file renamed, then cleaned up."""
    from leaklens.report import render_text, timeline

    for name in ["youtube_api.py", "module.py", "streamlitApp.py"]:
        commit(repo, {name: f'K = "{GOOGLE}"\n'}, f"add {name}")
    commit(repo, {"youtube_api.py": "K = None\n"}, "drop from youtube_api")
    sh(repo, "mv", "streamlitApp.py", "StreamlitApp.py")
    sh(repo, "commit", "-q", "-m", "rename")
    commit(repo, {"StreamlitApp.py": "K = None\n", "module.py": "K = None\n"}, "clean up")

    f = scan_repo(str(repo)).findings[0]
    kinds = [e.kind for e in timeline(f)]
    assert kinds.count("added") == 3
    assert kinds.count("renamed") == 1      # not shown as removed + added
    assert kinds.count("removed") == 3      # youtube_api, StreamlitApp, module
    assert not f.in_head

    text = render_text(scan_repo(str(repo)))
    assert "moved streamlitApp.py -> StreamlitApp.py" in text
    assert "removed from module.py" in text  # was silently cut off before


def test_long_timeline_says_how_many_are_hidden(repo):
    from leaklens.report import TIMELINE_LIMIT, render_text

    for i in range(TIMELINE_LIMIT + 2):
        commit(repo, {f"f{i}.py": f'K = "{GOOGLE}"\n'}, f"c{i}")
    assert "+2 more event(s)" in render_text(scan_repo(str(repo)))


def test_skip_rules():
    from leaklens.scanner import _skip

    for p in ["package-lock.json", "web/yarn.lock", "dist/app.min.js", "a.js.map",
              "logo.svg", "node_modules/x/index.js", "site/node_modules/y.js", "Cargo.lock"]:
        assert _skip(p), p
    for p in ["app.py", ".env", "src/config.js", "lock.py", "node_modules.md", "README.md"]:
        assert not _skip(p), p


def test_empty_repo(repo):
    assert scan_repo(str(repo)).findings == []
