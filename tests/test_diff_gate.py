import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from diff_gate.cli import main
from diff_gate.gate import run_gate
from diff_gate.parser import DiffParseError, parse_diff


MODIFY = b"""diff --git a/hello.txt b/hello.txt
index ce01362..94954ab 100644
--- a/hello.txt
+++ b/hello.txt
@@ -1 +1 @@
-hello
+goodbye
"""


def git(root, *args):
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def repo(tmp_path):
    if not shutil.which("git"):
        pytest.skip("git unavailable")
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.email", "test@example.invalid")
    git(tmp_path, "config", "user.name", "Test")
    (tmp_path / "hello.txt").write_text("hello\n")
    git(tmp_path, "add", "hello.txt")
    git(tmp_path, "commit", "-qm", "initial")
    return tmp_path


def test_parse_normal_modify():
    result = parse_diff(MODIFY)
    assert result.paths == ("hello.txt",)
    assert result.file_count == 1


def test_traversal_and_absolute_are_rejected(tmp_path):
    traversal = MODIFY.replace(b"a/hello.txt", b"a/../../etc/passwd").replace(
        b"b/hello.txt", b"b/../../etc/passwd")
    result = run_gate(traversal, root=tmp_path)
    assert result.exit_code == 1
    assert result.status == "rejected"
    assert "parent component" in result.errors[0]
    absolute = b"--- /etc/passwd\n+++ /etc/passwd\n@@ -1 +1 @@\n-x\n+y\n"
    result = run_gate(absolute, root=tmp_path, strip=0)
    assert result.exit_code == 2
    assert result.status == "parse_error"
    assert "absolute" in result.errors[0]


def test_symlink_escape_and_internal_symlink_both_rejected(tmp_path):
    outside = tmp_path.parent / "outside"
    outside.mkdir(exist_ok=True)
    (tmp_path / "escape").symlink_to(outside, target_is_directory=True)
    patch = MODIFY.replace(b"hello.txt", b"escape/owned.txt")
    result = run_gate(patch, root=tmp_path)
    assert result.exit_code == 1
    assert result.paths[0]["safe"] is False
    assert "symbolic link" in result.paths[0]["reason"]
    (tmp_path / "inside").mkdir()
    (tmp_path / "alias").symlink_to(tmp_path / "inside", target_is_directory=True)
    result = run_gate(MODIFY.replace(b"hello.txt", b"alias/x"), root=tmp_path)
    assert result.exit_code == 1
    assert "symbolic link" in result.errors[0]


def test_quoted_path_c_escapes():
    patch = b'''diff --git "a/tab\\tname" "b/tab\\tname"
--- "a/tab\\tname"
+++ "b/tab\\tname"
@@ -1 +1 @@
-x
+y
'''
    parsed = parse_diff(patch)
    assert parsed.paths == ("tab\tname",)
    octal = patch.replace(b"tab\\tname", b"caf\\303\\251")
    assert parse_diff(octal).paths == ("caf\N{LATIN SMALL LETTER E WITH ACUTE}",)


def test_add_delete_dev_null():
    added = b"""diff --git a/new.txt b/new.txt
new file mode 100644
--- /dev/null
+++ b/new.txt
@@ -0,0 +1 @@
+new
"""
    deleted = b"""diff --git a/old.txt b/old.txt
deleted file mode 100644
--- a/old.txt
+++ /dev/null
@@ -1 +0,0 @@
-old
"""
    assert parse_diff(added).paths == ("new.txt",)
    assert parse_diff(deleted).paths == ("old.txt",)
    assert parse_diff(added).file_count == 1
    assert parse_diff(deleted).file_count == 1


def test_rename_and_copy_headers():
    rename = b"""diff --git a/old.txt b/new.txt
similarity index 100%
rename from old.txt
rename to new.txt
"""
    copy = b"""diff --git a/source.txt b/copy.txt
similarity index 100%
copy from source.txt
copy to copy.txt
"""
    assert parse_diff(rename).paths == ("new.txt", "old.txt")
    assert parse_diff(copy).paths == ("copy.txt", "source.txt")
    assert parse_diff(rename, strip=0).paths == ("new.txt", "old.txt")
    with pytest.raises(DiffParseError, match="unpaired rename"):
        parse_diff(rename.replace(b"rename to new.txt\n", b""))
    with pytest.raises(DiffParseError, match="conflict"):
        parse_diff(rename.replace(b"rename to new.txt", b"rename to other.txt"))


def test_symlink_mode_and_binary_rejected():
    symlink = b"diff --git a/link b/link\nnew file mode 120000\n--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n++/tmp/x\n"
    binary = b"diff --git a/x b/x\nnew file mode 100644\nGIT binary patch\nliteral 0\n"
    with pytest.raises(DiffParseError, match="symbolic-link"):
        parse_diff(symlink)
    with pytest.raises(DiffParseError, match="binary"):
        parse_diff(binary)
    with pytest.raises(DiffParseError, match="no patch operation"):
        parse_diff(b"diff --git a/x b/x\n")
    with pytest.raises(DiffParseError, match="malformed new file mode"):
        parse_diff(b"diff --git a/x b/x\nnew file mode nope\n")


def test_deny_wins_and_allow_must_match(tmp_path):
    patch = MODIFY.replace(b"hello.txt", b"secrets/key.txt")
    result = run_gate(patch, root=tmp_path, allow=("secrets/**",), deny=("**/key.txt",))
    assert result.exit_code == 1
    assert "denied" in result.paths[0]["reason"]
    result = run_gate(patch, root=tmp_path, allow=("src/**",))
    assert result.exit_code == 1
    assert "not matched" in result.paths[0]["reason"]
    nested = MODIFY.replace(b"hello.txt", b"src/deep/file.py")
    assert run_gate(nested, root=tmp_path, allow=("src/*",)).exit_code == 1
    assert run_gate(nested, root=tmp_path, allow=("src/**",)).exit_code == 0
    root_pem = MODIFY.replace(b"hello.txt", b"key.pem")
    assert run_gate(root_pem, root=tmp_path, deny=("**/*.pem",)).exit_code == 1


@pytest.mark.parametrize("patch", [
    b"", b"not a diff\n", b"--- a/x\n", b"+++ b/x\n",
    b"--- a/x\n+++ b/x\n@@ bad @@\n",
    b"--- a/x\n+++ b/x\n@@ -1 +1 @@\n-x\n",
])
def test_malformed_is_parse_error(patch):
    with pytest.raises(DiffParseError):
        parse_diff(patch)


def test_hunk_content_that_looks_like_header_is_not_a_path():
    patch = b"--- a/x\n+++ b/x\n@@ -1 +1 @@\n---- dangerous\n++++ safe\n"
    parsed = parse_diff(patch)
    assert parsed.paths == ("x",)


def test_check_and_happy_apply(tmp_path):
    root = repo(tmp_path)
    checked = run_gate(MODIFY, mode="check", root=root)
    assert checked.exit_code == 0
    assert checked.status == "safe"
    assert checked.checks["git_check"] is True
    applied = run_gate(MODIFY, mode="apply", root=root)
    assert applied.exit_code == 0
    assert applied.status == "applied"
    assert applied.checks["applied"] is True
    assert (root / "hello.txt").read_text() == "goodbye\n"


def test_dirty_tree_refusal_and_override(tmp_path):
    root = repo(tmp_path)
    (root / "untracked").write_text("dirty")
    result = run_gate(MODIFY, mode="apply", root=root)
    assert result.exit_code == 1
    assert result.checks["clean_tree"] is False
    assert (root / "hello.txt").read_text() == "hello\n"
    result = run_gate(MODIFY, mode="apply", root=root, allow_dirty=True)
    assert result.exit_code == 0
    assert (root / "hello.txt").read_text() == "goodbye\n"


def test_git_check_failure_does_not_mutate(tmp_path):
    root = repo(tmp_path)
    bad = MODIFY.replace(b"-hello", b"-not-present")
    result = run_gate(bad, mode="apply", root=root)
    assert result.exit_code == 1
    assert result.checks["git_check"] is False
    assert (root / "hello.txt").read_text() == "hello\n"


def test_cli_json_and_exit_codes(tmp_path, capsys):
    good = tmp_path / "good.patch"
    good.write_bytes(MODIFY)
    assert main(["inspect", str(good), "--root", str(tmp_path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "safe"
    assert payload["paths"][0]["path"] == "hello.txt"
    bad = tmp_path / "bad.patch"
    bad.write_bytes(b"garbage")
    assert main(["inspect", str(bad), "--root", str(tmp_path)]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "parse_error"
    denied = tmp_path / "denied.patch"
    denied.write_bytes(MODIFY)
    assert main(["inspect", str(denied), "--root", str(tmp_path), "--deny", "hello.txt"]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "rejected"


def test_inspect_needs_no_git_or_existing_root(tmp_path, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _: None)
    missing = tmp_path / "missing"
    result = run_gate(MODIFY, mode="inspect", root=missing)
    assert result.exit_code == 0
    assert result.checks["git_available"] is None
    assert not missing.exists()


def test_strip_zero_and_too_large():
    assert parse_diff(MODIFY, strip=0).paths == ("a/hello.txt", "b/hello.txt")
    with pytest.raises(DiffParseError, match="too few"):
        parse_diff(MODIFY, strip=2)
