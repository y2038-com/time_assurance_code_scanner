# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Discovery artifacts must not mutate packaged/tracked rules files."""

from __future__ import annotations

import json
from pathlib import Path

from tacs.core.discovery_manager import DiscoveryManager


def test_update_rules_writes_only_under_output_dir(tmp_path: Path) -> None:
    rules = tmp_path / "packaged_rules.json"
    rules.write_text(
        json.dumps(
            [
                {
                    "symbol": "time_t",
                    "risk": "high",
                    "category": "type",
                    "description": "base",
                }
            ]
        ),
        encoding="utf-8",
    )
    rules_mtime = rules.stat().st_mtime_ns
    sibling = tmp_path / "packaged_rules_with_discoveries.json"
    assert not sibling.exists()

    out_dir = tmp_path / "prescan"
    mgr = DiscoveryManager()
    aliases = {
        "my_time_t": [
            f"{tmp_path / 'sample.c'}:8: typedef time_t my_time_t;"
        ]
    }
    updated = Path(
        mgr.update_rules_with_discoveries(
            str(rules),
            aliases,
            {},
            output_dir=str(out_dir),
            root_path=str(tmp_path),
        )
    )

    assert updated.parent == out_dir
    assert updated.name == "rules_with_discoveries.json"
    assert updated.is_file()
    assert not sibling.exists()
    assert rules.stat().st_mtime_ns == rules_mtime

    payload = json.loads(updated.read_text(encoding="utf-8"))
    discovered = [r for r in payload if r.get("discovered")]
    assert len(discovered) == 1
    # Absolute path under root should be relativized in the artifact.
    assert discovered[0]["definitions"][0].startswith("sample.c:")


def test_discovery_report_path(tmp_path: Path) -> None:
    mgr = DiscoveryManager()
    report = tmp_path / "discovery_report.json"
    mgr.save_discovery_report(
        {"my_time_t": [f"{tmp_path / 'a.c'}:1: typedef time_t my_time_t;"]},
        {},
        str(report),
        root_path=str(tmp_path),
    )
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["discovery_summary"]["typedef_aliases_count"] == 1
    assert data["typedef_aliases"]["my_time_t"][0].startswith("a.c:")
