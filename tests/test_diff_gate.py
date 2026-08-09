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


@pytest.mark.parametrize("name, reason", [
    (b"a/../../escape", "parent component"),
    (b"a/dir\\escape", "backslash"),
    (b"a/C:/escape", "Windows drive"),
    (b"a/name. ", "trailing dot or space"),
])
def test_hostile_path_forms_fail_closed(tmp_path, name, reason):
    patch = MODIFY.replace(b"a/hello.txt", name).replace(b"b/hello.txt", name.replace(b"a/", b"b/", 1))
    result = run_gate(patch, root=tmp_path)
    assert result.exit_code in (1, 2)
    assert reason in (result.errors[0] + " " + " ".join(str(p["reason"]) for p in result.paths))


def test_quoted_escape_traversal_nul_and_header_mismatch(tmp_path):
    traversal = MODIFY.replace(b"a/hello.txt", b'"a/safe/\\056\\056/escape"').replace(
        b"b/hello.txt", b'"b/safe/\\056\\056/escape"')
    result = run_gate(traversal, root=tmp_path)
    assert result.exit_code == 1
    assert "parent component" in result.errors[0]
    with pytest.raises(DiffParseError, match="NUL"):
        parse_diff(MODIFY.replace(b"a/hello.txt", b'"a/x\\000y"'))
    mismatch = MODIFY.replace(b"+++ b/hello.txt", b'+++ "b/other.txt"')
    with pytest.raises(DiffParseError, match="conflicting"):
        parse_diff(mismatch)


@pytest.mark.parametrize("patch", [
    b"--- a/x\n+++ b/x\n",
    b"diff --git a/x b/x\nunknown metadata\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-x\n+y\n",
    b"diff --git a/x b/x\n--- a/x\n+++ b/x\n--- a/y\n+++ b/y\n@@ -1 +1 @@\n-x\n+y\n",
    b"diff --git a/x b/x\nindex not-a-hash\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-x\n+y\n",
])
def test_incomplete_duplicate_and_unknown_syntax_is_parse_error(patch):
    with pytest.raises(DiffParseError):
        parse_diff(patch)


def test_huge_hunk_number_and_overlong_path_are_parse_errors():
    huge = b"9" * 5000
    patch = b"--- a/x\n+++ b/x\n@@ -1," + huge + b" +1 @@\n"
    with pytest.raises(DiffParseError, match="too large"):
        parse_diff(patch)
    long_path = b"a/" + b"x" * 4097
    with pytest.raises(DiffParseError, match="4096"):
        parse_diff(MODIFY.replace(b"a/hello.txt", long_path).replace(b"b/hello.txt", b"b/" + b"x" * 4097))


def test_multi_file_rejects_if_any_path_escapes(tmp_path):
    unsafe = MODIFY.replace(b"hello.txt", b"../../escape")
    result = run_gate(MODIFY + unsafe, root=tmp_path)
    assert result.exit_code == 1
    assert result.status == "rejected"
    assert any(not item["safe"] for item in result.paths)


def test_existing_target_symlink_is_rejected(tmp_path):
    outside = tmp_path.parent / "outside-file"
    outside.write_text("outside\n")
    (tmp_path / "hello.txt").symlink_to(outside)
    result = run_gate(MODIFY, root=tmp_path)
    assert result.exit_code == 1
    assert "symbolic link" in result.errors[0]
    assert outside.read_text() == "outside\n"


def test_cli_refuses_patch_file_outside_root_or_through_symlink(tmp_path, capsys):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.patch"
    outside.write_bytes(MODIFY)
    assert main(["inspect", str(outside), "--root", str(root)]) == 2
    assert "inside the workspace" in json.loads(capsys.readouterr().out)["errors"][0]
    (root / "link.patch").symlink_to(outside)
    assert main(["inspect", str(root / "link.patch"), "--root", str(root)]) == 2
    assert "symbolic link" in json.loads(capsys.readouterr().out)["errors"][0]


def test_cli_invalid_args_and_nul_root_return_structured_usage_error(capsys):
    assert main(["bogus", "-"]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "usage_error"
    assert payload["exit_code"] == 2
    assert main(["inspect", "-", "--root", "bad\x00root"]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "usage_error"


def test_no_newline_marker_remains_supported():
    patch = b"--- a/x\n+++ b/x\n@@ -1 +1 @@\n-x\n\\ No newline at end of file\n+y\n\\ No newline at end of file\n"
    assert parse_diff(patch).paths == ("x",)


@pytest.mark.parametrize("name", [b".git/config", b"src/.GIT/config", b"NUL", b"aux.txt", b"dir/COM1.log"])
def test_git_admin_and_windows_device_names_are_rejected(tmp_path, name):
    patch = MODIFY.replace(b"hello.txt", name)
    result = run_gate(patch, root=tmp_path)
    assert result.exit_code == 1
    assert "reserved" in result.errors[0]


def test_empty_file_addition_with_headers_is_valid():
    patch = b"diff --git a/empty b/empty\nnew file mode 100644\n--- /dev/null\n+++ b/empty\n"
    assert parse_diff(patch).paths == ("empty",)


def test_git_missing_is_structured_for_check_but_not_inspect(tmp_path, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _: None)
    inspected = run_gate(MODIFY, mode="inspect", root=tmp_path)
    assert inspected.exit_code == 0
    checked = run_gate(MODIFY, mode="check", root=tmp_path)
    assert checked.exit_code == 2
    assert checked.status == "usage_error"
    assert checked.checks["git_available"] is False
    assert "git executable" in checked.errors[0]


def test_git_root_must_equal_selected_root(tmp_path):
    root = repo(tmp_path)
    child = root / "child"
    child.mkdir()
    result = run_gate(MODIFY, mode="check", root=child)
    assert result.exit_code == 2
    assert "Git work-tree root" in result.errors[0]


@pytest.mark.parametrize("mode", [b"120001", b"120755", b"160000", b"040000"])
def test_noncanonical_symlink_and_nonregular_modes_never_apply(tmp_path, mode):
    root = repo(tmp_path)
    patch = (b"diff --git a/hostile b/hostile\nnew file mode " + mode
             + b"\n--- /dev/null\n+++ b/hostile\n@@ -0,0 +1 @@\n+/tmp/outside\n")
    result = run_gate(patch, mode="apply", root=root)
    assert result.exit_code == 2
    assert result.status == "parse_error"
    assert not (root / "hostile").exists()
    assert not (root / "hostile").is_symlink()


def test_symlink_type_bits_in_index_header_are_rejected():
    patch = MODIFY.replace(b"100644\n", b"120001\n")
    with pytest.raises(DiffParseError, match="symbolic-link"):
        parse_diff(patch)


def test_mixed_safe_and_escape_patch_never_partially_applies(tmp_path):
    root = repo(tmp_path)
    unsafe = MODIFY.replace(b"hello.txt", b"../../escape")
    result = run_gate(MODIFY + unsafe, mode="apply", root=root)
    assert result.exit_code == 1
    assert result.checks["git_check"] is None
    assert (root / "hello.txt").read_text() == "hello\n"


def test_policy_is_case_sensitive_and_deny_wins_at_multiple_depths(tmp_path):
    upper = MODIFY.replace(b"hello.txt", b"Src/Deep/File.py")
    assert run_gate(upper, root=tmp_path, allow=("src/**",)).exit_code == 1
    lower = MODIFY.replace(b"hello.txt", b"src/deep/file.py")
    result = run_gate(lower, root=tmp_path, allow=("src/**",), deny=("src/**/file.py",))
    assert result.exit_code == 1
    assert "denied" in result.errors[0]


@pytest.mark.parametrize("patch", [
    b"diff --git a/x b/x\n--- /dev/null\n+++ /dev/null\n@@ -0,0 +1 @@\n+x\n",
    b"diff --git a/x b/x\nindex 1111111..2222222 100644\nindex 1111111..2222222 100644\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n",
    b"diff --git a/x b/x\nsimilarity index 100%\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n",
    b"diff --git a/x b/x\n--- a/x\n+++ b/x\nindex 1111111..2222222 100644\n@@ -1 +1 @@\n-a\n+b\n",
])
def test_null_duplicate_and_misplaced_metadata_fail_closed(patch):
    with pytest.raises(DiffParseError):
        parse_diff(patch)
