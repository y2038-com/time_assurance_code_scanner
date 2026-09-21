# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for credentials embedded in repository URLs.

A URL such as ``https://user:TEST_CREDENTIAL_VALUE@github.com/org/private.git`` would otherwise
reach the always-visible repo header, meta.json, status.json, summary.json, and
git failure messages -- and cloning would record it in the cache clone's
.git/config. SECURITY.md puts credential leakage through logs and reports in
scope, so such a URL is rejected on input and redacted everywhere it could still
be printed or stored.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import tacs.batch_scan_repos as bsr

TEST_CREDENTIAL_VALUE = "TEST_CREDENTIAL_VALUE"

CREDENTIAL_URLS = [
    f"https://user:{TEST_CREDENTIAL_VALUE}@github.com/org/private.git",
    f"https://{TEST_CREDENTIAL_VALUE}@github.com/org/private.git",
    f"http://user:{TEST_CREDENTIAL_VALUE}@example.com/org/private.git",
    f"ssh://user:{TEST_CREDENTIAL_VALUE}@example.com/org/private.git",
]

CLEAN_URLS = [
    "https://github.com/org/public.git",
    "ssh://git@github.com/org/public.git",
    "git@github.com:org/public.git",
]


# --- detection --------------------------------------------------------------


@pytest.mark.parametrize("url", CREDENTIAL_URLS)
def test_credential_urls_are_detected(url: str) -> None:
    assert bsr.url_carries_credentials(url)


@pytest.mark.parametrize("url", CLEAN_URLS)
def test_ordinary_urls_are_not_flagged(url: str) -> None:
    """A bare username on an SSH remote is an identity, not a secret."""
    assert not bsr.url_carries_credentials(url)


def test_at_sign_in_path_is_not_userinfo() -> None:
    assert not bsr.url_carries_credentials("https://example.com/org/repo@v2.git")


# --- redaction --------------------------------------------------------------


@pytest.mark.parametrize("url", CREDENTIAL_URLS)
def test_redaction_removes_the_secret(url: str) -> None:
    redacted = bsr.redact_url_credentials(url)

    assert TEST_CREDENTIAL_VALUE not in redacted
    # The host and path stay recognizable.
    assert redacted.endswith("/org/private.git")


def test_redaction_keeps_host_and_path_readable() -> None:
    assert (
        bsr.redact_url_credentials(f"https://user:{TEST_CREDENTIAL_VALUE}@github.com/org/p.git")
        == "https://***@github.com/org/p.git"
    )
    assert (
        bsr.redact_url_credentials(f"ssh://user:{TEST_CREDENTIAL_VALUE}@example.com/org/p.git")
        == "ssh://user:***@example.com/org/p.git"
    )


def test_redaction_leaves_ordinary_urls_untouched() -> None:
    for url in CLEAN_URLS:
        assert bsr.redact_url_credentials(url) == url


def test_redaction_works_on_surrounding_text() -> None:
    """git stderr names the remote inside a sentence."""
    message = (
        f"git clone --no-tags https://user:{TEST_CREDENTIAL_VALUE}@github.com/org/p.git /tmp/x failed: "
        f"fatal: could not read from https://user:{TEST_CREDENTIAL_VALUE}@github.com/org/p.git"
    )
    redacted = bsr.redact_url_credentials(message)

    assert TEST_CREDENTIAL_VALUE not in redacted
    assert redacted.count("https://***@github.com/org/p.git") == 2


# --- rejection on input -----------------------------------------------------


@pytest.mark.parametrize("url", CREDENTIAL_URLS)
def test_repos_file_entry_with_credentials_is_skipped(
    url: str, tmp_path: Path
) -> None:
    """The repo is not scanned, and the warning does not quote the URL back."""
    repos_file = tmp_path / "repos.jsonl"
    repos_file.write_text(
        json.dumps({"repo_url": url}) + "\n"
        + json.dumps({"repo_url": "https://github.com/org/public.git"}) + "\n",
        encoding="utf-8",
    )

    tasks, warnings = bsr._load_repo_tasks(repos_file)

    assert [t.repo_url for t in tasks] == ["https://github.com/org/public.git"]
    assert len(warnings) == 1
    assert TEST_CREDENTIAL_VALUE not in warnings[0]
    assert "credential" in warnings[0].lower()


def test_rejection_warning_points_at_the_alternatives(tmp_path: Path) -> None:
    repos_file = tmp_path / "repos.jsonl"
    repos_file.write_text(
        json.dumps({"repo_url": f"https://{TEST_CREDENTIAL_VALUE}@github.com/org/p.git"}) + "\n",
        encoding="utf-8",
    )

    _tasks, warnings = bsr._load_repo_tasks(repos_file)

    assert "credential helper" in warnings[0]
    assert "SSH" in warnings[0]


# --- nothing leaks into a run's output or artifacts -------------------------


def test_run_artifacts_and_console_never_carry_the_token(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """End to end: a credential URL reaches no header, artifact, or clone."""
    repos_file = tmp_path / "repos.jsonl"
    repos_file.write_text(
        json.dumps({"repo_url": f"https://user:{TEST_CREDENTIAL_VALUE}@github.com/org/private.git"})
        + "\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "out"
    cache_dir = tmp_path / "cache"

    bsr.main(
        [
            "--repos-file",
            str(repos_file),
            "--out-dir",
            str(out_dir),
            "--cache-dir",
            str(cache_dir),
            "--log-level",
            "error",
        ]
    )

    captured = capsys.readouterr()
    assert TEST_CREDENTIAL_VALUE not in captured.out
    assert TEST_CREDENTIAL_VALUE not in captured.err

    for path in out_dir.rglob("*"):
        if path.is_file():
            assert TEST_CREDENTIAL_VALUE not in path.read_text(encoding="utf-8", errors="ignore"), path

    # Rejected before any clone, so no credential lands in .git/config either.
    assert not cache_dir.exists() or not list(cache_dir.rglob("config"))


def test_git_failure_message_is_redacted(tmp_path: Path) -> None:
    """A real git failure naming a credential URL must not echo the token."""
    with pytest.raises(RuntimeError) as excinfo:
        bsr._git(
            [
                "clone",
                "--no-tags",
                f"https://user:{TEST_CREDENTIAL_VALUE}@127.0.0.1:1/org/p.git",
                str(tmp_path / "dest"),
            ],
            timeout=60,
        )

    assert TEST_CREDENTIAL_VALUE not in str(excinfo.value)
    assert "***@127.0.0.1:1" in str(excinfo.value)
