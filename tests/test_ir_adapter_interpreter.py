# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression: IR adapter must invoke the active interpreter via sys.executable."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

from tacs.core.ir_adapter import IRAdapter

SCANNER = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "tacs"
    / "python"
    / "y2038scan_fast_json_group.py"
)
RULES = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "tacs"
    / "rules"
    / "y2038_sample_rules.json"
)


def test_ir_adapter_uses_sys_executable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    adapter = IRAdapter(str(SCANNER))
    monkeypatch.setattr(adapter, "_scan_for_defines", lambda *a, **k: [])
    monkeypatch.setattr(adapter, "_scan_for_arithmetic", lambda *a, **k: [])

    captured: dict[str, list[str]] = {}

    class FakeProc:
        def __init__(self, cmd, *args, **kwargs):
            captured["cmd"] = list(cmd)
            out_path = Path(cmd[cmd.index("--json-out") + 1])
            out_path.write_text("[]", encoding="utf-8")
            self.stderr = io.StringIO("")
            self.stdout = io.StringIO("")
            self.returncode = 0

        def communicate(self):
            return ("", "")

    monkeypatch.setattr("tacs.core.ir_adapter.subprocess.Popen", FakeProc)

    root = tmp_path / "tree"
    root.mkdir()
    (root / "empty.c").write_text("int x;\n", encoding="utf-8")

    adapter.discover_candidates(str(root), str(RULES), min_risk="low")

    assert "cmd" in captured
    assert captured["cmd"][0] == sys.executable
    # Guard against the old hardcoded argv[0] when the active interpreter is not
    # the bare name "python" (the usual venv / absolute-path case).
    if sys.executable != "python":
        assert captured["cmd"][0] != "python"
