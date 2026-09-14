# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from tacs.core.include_patterns import build_include_patterns


LOGGER = logging.getLogger("batch_scan_repos")

DEFAULT_FALLBACK_CONFIG_ID = "ilp32_signed_32bit"
VALID_CONFIG_IDS = {
    "ilp32_signed_32bit",
    "ilp32_signed_64bit",
    "ilp32_unsigned_32bit",
    "ilp32_unsigned_64bit",
    "lp64_signed_32bit",
    "lp64_signed_64bit",
    "lp64_unsigned_32bit",
    "lp64_unsigned_64bit",
}


@dataclass
class RepoTask:
    repo_url: str
    ref: str | None = None
    name: str | None = None
    enabled: bool = True
    scan_overrides: dict[str, Any] | None = None
    source_line: int = 0


@dataclass
class RepoIdentity:
    host: str
    owner: str
    repo: str
    cache_path: Path


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _run_id_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _sanitize_token(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("_") or "unknown"


def _parse_repo_identity(repo_url: str, cache_dir: Path) -> RepoIdentity:
    url = repo_url.strip()
    if not url:
        raise ValueError("repo_url is empty")

    host = ""
    owner = ""
    repo = ""

    if "://" in url:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path_parts = [p for p in parsed.path.split("/") if p]
        if len(path_parts) >= 2:
            owner = path_parts[-2]
            repo = path_parts[-1]
    elif "@" in url and ":" in url:
        # git@github.com:org/repo.git
        lhs, rhs = url.split(":", 1)
        host = lhs.split("@", 1)[-1]
        path_parts = [p for p in rhs.split("/") if p]
        if len(path_parts) >= 2:
            owner = path_parts[-2]
            repo = path_parts[-1]

    repo = repo.removesuffix(".git")
    if not host or not owner or not repo:
        raise ValueError(f"could not parse repo identity from URL: {repo_url}")

    host_s = _sanitize_token(host.lower())
    owner_s = _sanitize_token(owner)
    repo_s = _sanitize_token(repo)
    cache_path = cache_dir / host_s / owner_s / f"{repo_s}.gitwork"
    return RepoIdentity(host=host, owner=owner, repo=repo, cache_path=cache_path)


def _source_label_for_host(host: str) -> str:
    host_l = host.strip().lower()
    if "github" in host_l:
        return "github"
    return _sanitize_token(host_l or "source")


def _short_ref_label(ref_value: str) -> str:
    ref = ref_value.strip()
    # Full/long SHA -> compact label for readability.
    if re.fullmatch(r"[0-9a-fA-F]{16,}", ref):
        return ref[:12].lower()
    return _sanitize_token(ref)


def _repo_key(identity: RepoIdentity, ref_value: str) -> str:
    source = _source_label_for_host(identity.host)
    owner = _sanitize_token(identity.owner)
    repo = _sanitize_token(identity.repo)
    ref = _short_ref_label(ref_value or "default")
    return f"{source}__{owner}__{repo}__{ref}"


def _git(args: list[str], cwd: Path | None = None, timeout: int = 300) -> str:
    cmd = ["git", *args]
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {stderr or stdout or 'unknown error'}")
    return (proc.stdout or "").strip()


def _load_repo_tasks(repos_file: Path) -> tuple[list[RepoTask], list[str]]:
    tasks: list[RepoTask] = []
    warnings: list[str] = []
    if not repos_file.exists():
        raise FileNotFoundError(f"repos file not found: {repos_file}")

    with repos_file.open("r", encoding="utf-8") as f:
        for idx, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as e:
                warnings.append(f"line {idx}: invalid JSON ({e})")
                continue
            if not isinstance(payload, dict):
                warnings.append(f"line {idx}: expected object, got {type(payload).__name__}")
                continue
            repo_url = payload.get("repo_url")
            if not isinstance(repo_url, str) or not repo_url.strip():
                warnings.append(f"line {idx}: missing/invalid repo_url")
                continue
            task = RepoTask(
                repo_url=repo_url.strip(),
                ref=payload.get("ref") if isinstance(payload.get("ref"), str) else None,
                name=payload.get("name") if isinstance(payload.get("name"), str) else None,
                enabled=payload.get("enabled", True) is not False,
                scan_overrides=payload.get("scan_overrides") if isinstance(payload.get("scan_overrides"), dict) else None,
                source_line=idx,
            )
            tasks.append(task)
    return tasks, warnings


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _parse_findings_summary(findings_path: Path) -> dict[str, int]:
    if not findings_path.exists():
        return {"total_findings": 0, "yes_findings": 0, "no_findings": 0, "abstain_findings": 0}
    data = json.loads(findings_path.read_text(encoding="utf-8"))
    findings = data.get("findings", []) if isinstance(data, dict) else []
    yes = 0
    no = 0
    abstain = 0
    for f in findings:
        issue = ""
        if isinstance(f, dict):
            issue = str(f.get("y2038_issue", "")).strip().lower()
        if issue == "yes":
            yes += 1
        elif issue == "no":
            no += 1
        elif issue == "abstain":
            abstain += 1
    return {
        "total_findings": len(findings),
        "yes_findings": yes,
        "no_findings": no,
        "abstain_findings": abstain,
    }


def _extract_scan_metrics(results_obj: Any) -> dict[str, Any]:
    """Extract metrics from ScanResults in a JSON-safe form."""
    default_metrics: dict[str, Any] = {
        "total_files": 0,
        "total_lines": 0,
        "total_chars": 0,
        "total_words": 0,
    }
    try:
        meta = getattr(results_obj, "meta", None)
        metrics = getattr(meta, "metrics", None) if meta is not None else None
        if metrics is None:
            return default_metrics
        if hasattr(metrics, "model_dump"):
            payload = metrics.model_dump()
        elif hasattr(metrics, "dict"):
            payload = metrics.dict()
        elif isinstance(metrics, dict):
            payload = metrics
        else:
            return default_metrics
        return {
            "total_files": int(payload.get("total_files", 0) or 0),
            "total_lines": int(payload.get("total_lines", 0) or 0),
            "total_chars": int(payload.get("total_chars", 0) or 0),
            "total_words": int(payload.get("total_words", 0) or 0),
            "max_line_length": int(payload.get("max_line_length", 0) or 0),
            "avg_line_length": round(float(payload.get("avg_line_length", 0.0) or 0.0), 1),
            "max_file_length": int(payload.get("max_file_length", 0) or 0),
            "avg_file_length": round(float(payload.get("avg_file_length", 0.0) or 0.0), 1),
        }
    except Exception:
        return default_metrics


def _count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    count = 0
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for _ in fh:
            count += 1
    return count


def _latest_scan_dir(scan_root: Path) -> Path | None:
    scans_root = scan_root / "results" / "scans"
    if not scans_root.exists():
        return None
    candidates = [p for p in scans_root.iterdir() if p.is_dir()]
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0]


def _extract_stage_stats(scan_root: Path) -> dict[str, Any]:
    """
    Best-effort stage stats from persisted scan artifacts.
    """
    stats: dict[str, Any] = {
        "prescan": {"time_t_aliases": 0},
        "ir": {"candidates": 0, "after_structural_filter": None},
        "io_boundary": {"candidates": None},
        "llm": {
            "total_tokens": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "requests": 0,
            "by_pass": {},
        },
    }
    scan_dir = _latest_scan_dir(scan_root)
    if scan_dir is None:
        return stats

    # Prescan aliases (if persisted)
    stats["prescan"]["time_t_aliases"] = _count_lines(scan_dir / "prescan" / "typedefs.jsonl")

    # IR candidate volume
    stats["ir"]["candidates"] = _count_lines(scan_dir / "ir" / "candidates.jsonl")

    summary_path = scan_dir / "findings" / "summary.txt"
    if summary_path.exists():
        text = summary_path.read_text(encoding="utf-8", errors="ignore")

        def _int_from(pattern: str) -> int | None:
            m = re.search(pattern, text, re.IGNORECASE)
            if not m:
                return None
            try:
                return int(m.group(1).replace(",", ""))
            except Exception:
                return None

        sf = _int_from(r"After structural filter:\s*([0-9,]+)")
        if sf is not None:
            stats["ir"]["after_structural_filter"] = sf

        total_tokens = _int_from(r"Total tokens:\s*([0-9,]+)")
        prompt_tokens = _int_from(r"Prompt tokens:\s*([0-9,]+)")
        completion_tokens = _int_from(r"Completion tokens:\s*([0-9,]+)")
        reqs = _int_from(r"Total LLM requests:\s*([0-9,]+)")
        if total_tokens is not None:
            stats["llm"]["total_tokens"] = total_tokens
        if prompt_tokens is not None:
            stats["llm"]["prompt_tokens"] = prompt_tokens
        if completion_tokens is not None:
            stats["llm"]["completion_tokens"] = completion_tokens
        if reqs is not None:
            stats["llm"]["requests"] = reqs

        for m in re.finditer(
            r"-\s*(S\d+_P\d+):\s*([0-9,]+)\s*tokens\s*\(([0-9,]+)\s*prompt\s*\+\s*([0-9,]+)\s*completion\)\s*in\s*([0-9,]+)\s*request",
            text,
            re.IGNORECASE,
        ):
            pass_name = m.group(1).upper()
            stats["llm"]["by_pass"][pass_name] = {
                "total_tokens": int(m.group(2).replace(",", "")),
                "prompt_tokens": int(m.group(3).replace(",", "")),
                "completion_tokens": int(m.group(4).replace(",", "")),
                "requests": int(m.group(5).replace(",", "")),
            }

    # I/O candidate count is not always in summary artifacts; try run log as fallback.
    run_log = scan_dir / "logs" / "run.log"
    if run_log.exists():
        run_text = run_log.read_text(encoding="utf-8", errors="ignore")
        m_io = re.search(r"I/O boundary analysis:\s*([0-9,]+)\s*candidates found", run_text, re.IGNORECASE)
        if m_io:
            try:
                stats["io_boundary"]["candidates"] = int(m_io.group(1).replace(",", ""))
            except Exception:
                pass

    return stats


def _scan_overrides(overrides: dict[str, Any] | None) -> tuple[dict[str, Any], list[str]]:
    allowed = {
        "file_extensions",
        "exclude_patterns",
        "max_file_size",
        "enable_llm",
        "disable_stage1",
        "detect_y2106",
        "confidence_threshold",
        "confidence_floor",
        "include_no_findings",
        "config_override",
    }
    cleaned: dict[str, Any] = {}
    warnings: list[str] = []
    if not overrides:
        return cleaned, warnings
    for key, value in overrides.items():
        if key in allowed:
            cleaned[key] = value
        else:
            warnings.append(f"ignoring unknown scan_overrides key: {key}")
    return cleaned, warnings


def _config_id_to_env_json(config_id: str) -> dict[str, Any]:
    parts = config_id.strip().lower().split("_")
    if len(parts) != 3:
        raise ValueError(f"invalid config id: {config_id}")
    model, signedness, bits_part = parts
    if model not in {"ilp32", "lp64"}:
        raise ValueError(f"invalid hardware model in config id: {config_id}")
    if signedness not in {"signed", "unsigned"}:
        raise ValueError(f"invalid signedness in config id: {config_id}")
    if bits_part not in {"32bit", "64bit"}:
        raise ValueError(f"invalid time_t size in config id: {config_id}")

    return {
        "hardware_model": model.upper(),
        "time_t_size_bits": 32 if bits_part == "32bit" else 64,
        "time_t_signed": signedness,
        "time64_functions_available": False,
        "d_time_bits_supported": False,
        "d_time_bits_setting": "not_available",
        "c_library": "glibc",
        "os_or_rtos": "Linux",
        "notes": f"{model.upper()} {bits_part.replace('bit', '-bit')} {signedness} time_t",
        "scenario_hint": (
            "ILP32-32bit-signed-time64_no-N/A"
            if model == "ilp32" and bits_part == "32bit" and signedness == "signed"
            else "ILP32-32bit-unsigned-time64_no-N/A"
            if model == "ilp32" and bits_part == "32bit" and signedness == "unsigned"
            else "LP64-64bit-signed-time64_yes-N/A"
        ),
        "mitigation_path": "upgrade_env" if bits_part == "32bit" else "none",
    }


def _parse_detector_recommended_id(recommended_obj: Any) -> str | None:
    if recommended_obj is None:
        return None
    if isinstance(recommended_obj, dict):
        cid = recommended_obj.get("config_id")
        if isinstance(cid, str) and cid.strip().lower() in VALID_CONFIG_IDS:
            return cid.strip().lower()
        try:
            hardware = str(recommended_obj.get("hardware_model", "")).lower()
            signed = str(recommended_obj.get("time_t_signed", "")).lower()
            bits = int(recommended_obj.get("time_t_size_bits"))
            cid = f"{hardware}_{signed}_{bits}bit"
            return cid if cid in VALID_CONFIG_IDS else None
        except Exception:
            return None
    try:
        hardware = str(getattr(recommended_obj, "hardware_model").value).lower()
        signed = str(getattr(recommended_obj, "time_t_signed").value).lower()
        bits = int(getattr(recommended_obj, "time_t_size_bits").value)
        cid = f"{hardware}_{signed}_{bits}bit"
        return cid if cid in VALID_CONFIG_IDS else None
    except Exception:
        return None


def _top_likelihood_config_id(likelihoods: list[Any]) -> str | None:
    best: tuple[float, str] | None = None
    for item in likelihoods:
        config_id = None
        score = None
        if hasattr(item, "config_id"):
            config_id = getattr(item, "config_id", None)
            score = getattr(item, "likelihood", None)
        elif isinstance(item, dict):
            config_id = item.get("config_id") or item.get("name")
            score = item.get("likelihood")
        if not isinstance(config_id, str):
            continue
        cid = config_id.strip().lower()
        if cid not in VALID_CONFIG_IDS:
            continue
        try:
            s = float(score)
        except (TypeError, ValueError):
            continue
        if best is None or s > best[0]:
            best = (s, cid)
    return best[1] if best else None


def _to_plain_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        return value.model_dump()  # pydantic v2
    if hasattr(value, "dict"):
        return value.dict()  # pydantic v1
    return {}


def _resolve_ref(repo: Path, requested_ref: str | None) -> tuple[str, str, str]:
    if requested_ref:
        # Try direct parse as branch/tag/SHA.
        try:
            sha = _git(["rev-parse", "--verify", requested_ref], cwd=repo)
            return requested_ref, sha, requested_ref
        except RuntimeError:
            pass
        remote_ref = f"origin/{requested_ref}"
        try:
            sha = _git(["rev-parse", "--verify", remote_ref], cwd=repo)
            return requested_ref, sha, requested_ref
        except RuntimeError as e:
            raise RuntimeError(f"requested ref not found: {requested_ref}") from e

    # Default to remote HEAD, then main, then master.
    candidates: list[str] = []
    origin_head = _git(["symbolic-ref", "--short", "refs/remotes/origin/HEAD"], cwd=repo)
    if origin_head:
        candidates.append(origin_head.replace("origin/", "", 1))
    candidates.extend(["main", "master"])

    seen: set[str] = set()
    for cand in candidates:
        if cand in seen:
            continue
        seen.add(cand)
        try:
            sha = _git(["rev-parse", "--verify", f"origin/{cand}"], cwd=repo)
            return cand, sha, cand
        except RuntimeError:
            continue
    raise RuntimeError("unable to resolve default ref (origin HEAD/main/master)")


def _checkout_clean(repo: Path, resolved_ref: str, resolved_sha: str) -> None:
    # If remote-tracking branch exists, force-reset local branch to it for deterministic scans.
    try:
        _git(["rev-parse", "--verify", f"origin/{resolved_ref}"], cwd=repo)
        _git(["checkout", "-B", resolved_ref, f"origin/{resolved_ref}"], cwd=repo)
        _git(["reset", "--hard", f"origin/{resolved_ref}"], cwd=repo)
    except RuntimeError:
        _git(["checkout", "--detach", resolved_sha], cwd=repo)
    _git(["clean", "-fd"], cwd=repo)


def _prepare_repo(identity: RepoIdentity, repo_url: str) -> None:
    if not identity.cache_path.exists():
        identity.cache_path.parent.mkdir(parents=True, exist_ok=True)
        _git(["clone", "--no-tags", repo_url, str(identity.cache_path)])
        return
    _git(["remote", "set-url", "origin", repo_url], cwd=identity.cache_path)
    _git(["fetch", "--prune", "origin"], cwd=identity.cache_path)


def _build_pipeline(
    *,
    include_no_findings: bool,
    enable_llm: bool,
    llm_type: str,
    model: str,
    disable_stage1: bool,
    detect_y2106: bool,
    confidence_floor: float,
    timeout_sec: int,
) -> Any:
    # Import lazily so `--dry-run` can work without installing full scanner deps.
    from tacs.core.pipeline import ScanningPipeline

    project_root = Path(__file__).resolve().parents[1]
    scanner_path = project_root / "scanner" / "python" / "y2038scan_fast_json_group.py"
    return ScanningPipeline(
        scanner_path=str(scanner_path),
        llm_type=llm_type if enable_llm else "none",
        model=model,
        confidence_floor=confidence_floor,
        batch_size_pass1=100,
        timeout_sec=timeout_sec,
        enable_discovery=True,
        max_typedef_hops=5,
        max_aliases=64,
        max_macros=64,
        enable_llm_logging=False,
        redact_prompts=True,
        allow_raw_code_logging=False,
        batch_size_pass2=40,
        batch_size_pass3=20,
        token_budget=250000,
        environment_config_path=None,
        debug_pass2=False,
        debug_candidates=False,
        debug_pass2_detailed=False,
        debug_llm_raw=False,
        debug_pass2_prompt=False,
        bypass_pass1=False,
        bypass_pass3=False,
        function_first=True,
        enable_pass1=(enable_llm and not disable_stage1),
        detect_y2106=detect_y2106,
        max_function_iters=2,
        batch_size_func=15,
        max_function_lines=10000,
        max_function_chars=20000,
        enable_io_analysis=True,
        io_score_threshold=6.0,
        io_check_literal_widths=True,
        migration_mode=False,
        migration_from_config_path=None,
        migration_to_config_path=None,
        include_no_findings=include_no_findings,
    )


def _repo_matches_filters(task: RepoTask, filters: Iterable[str]) -> bool:
    terms = [t.lower() for t in filters if t]
    if not terms:
        return True
    hay = f"{task.repo_url} {task.name or ''}".lower()
    return any(term in hay for term in terms)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Batch scan repositories for Y2038 issues")
    parser.add_argument("--repos-file", required=True, help="Path to JSONL repos file")
    parser.add_argument("--cache-dir", default=".repo_cache", help="Repo cache directory")
    parser.add_argument("--out-dir", default="batch_runs", help="Batch output root directory")
    parser.add_argument("--continue-on-error", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--fail-fast", action="store_true", help="Stop on first repository failure")
    parser.add_argument("--ref-override", help="Override ref for all repos")
    parser.add_argument("--repo", action="append", default=[], help="Filter repos by substring (repeatable)")
    parser.add_argument("--limit", type=int, help="Maximum repositories to process")
    parser.add_argument("--dry-run", action="store_true", help="Resolve/plan only, do not clone/scan")
    parser.add_argument("--scanner-timeout-sec", type=int, default=3600, help="Per-repo scan timeout")
    parser.add_argument("--enable-llm", action=argparse.BooleanOptionalAction, default=True, help="Enable LLM stages (default: enabled)")
    parser.add_argument("--llm-type", choices=["ollama", "openai", "anthropic", "gemini"], default="ollama", help="LLM provider when enabled (default: ollama)")
    parser.add_argument("--model", default="gpt-oss:120b-cloud", help="Model name for selected LLM provider (or TACS_MODEL)")
    parser.add_argument("--disable-stage1", action=argparse.BooleanOptionalAction, default=True, help="Disable Stage 1 line-level pass (default: disabled)")
    parser.add_argument("--detect-y2106", action=argparse.BooleanOptionalAction, default=True, help="Enable Y2106 detection (default: enabled)")
    parser.add_argument("--confidence-floor", type=float, default=0.85, help="Confidence floor for classifications (default: 0.85)")
    parser.add_argument("--fallback-config", default=DEFAULT_FALLBACK_CONFIG_ID, help=f"Fallback config id when detection is uncertain (default: {DEFAULT_FALLBACK_CONFIG_ID})")
    parser.add_argument("--config-min-confidence", type=float, default=0.70, help="Minimum detection confidence to accept recommended config (default: 0.70)")
    parser.add_argument("--include-no-findings", action=argparse.BooleanOptionalAction, default=False, help="Include NO findings in output (default: disabled)")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args(argv)

    fallback_config_id = args.fallback_config.strip().lower()
    if fallback_config_id not in VALID_CONFIG_IDS:
        raise SystemExit(f"invalid --fallback-config: {args.fallback_config}")

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    start_ts = time.time()
    run_id = _run_id_now()
    repos_file = Path(args.repos_file).resolve()
    cache_dir = Path(args.cache_dir).resolve()
    out_root = Path(args.out_dir).resolve()
    run_dir = out_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    all_tasks, parse_warnings = _load_repo_tasks(repos_file)
    tasks = [t for t in all_tasks if t.enabled and _repo_matches_filters(t, args.repo)]
    if args.limit is not None:
        tasks = tasks[: max(0, args.limit)]

    results: list[dict[str, Any]] = []
    counters = {"success": 0, "failed": 0, "timeout": 0, "skipped": 0}
    config_source_counts = {"explicit": 0, "detected": 0, "fallback": 0}
    llm_enabled_count = 0
    stage1_disabled_count = 0
    y2106_enabled_count = 0
    aggregate_metrics = {
        "total_files_scanned": 0,
        "total_lines_scanned": 0,
        "total_chars_scanned": 0,
        "total_words_scanned": 0,
        "repos_with_metrics": 0,
    }
    aggregate_stage_stats = {
        "prescan": {"time_t_aliases": 0},
        "ir": {"candidates": 0},
        "io_boundary": {"candidates": 0, "repos_with_io_stat": 0},
        "llm": {"total_tokens": 0, "prompt_tokens": 0, "completion_tokens": 0, "requests": 0},
    }

    LOGGER.info("starting batch run %s with %d repos", run_id, len(tasks))

    for idx, task in enumerate(tasks, start=1):
        repo_started = time.time()
        status = "success"
        stage = "prepare_repo"
        error_code: str | None = None
        error_message: str | None = None
        repo_warnings: list[str] = []
        resolved_ref = ""
        resolved_sha = ""
        resolved_ref_input = ""
        config_source = "fallback"
        effective_config_id = ""
        config_reason = ""
        detector_overall_confidence = 0.0
        detector_recommended_id: str | None = None
        detector_top_id: str | None = None
        repo_metrics: dict[str, Any] = {
            "total_files": 0,
            "total_lines": 0,
            "total_chars": 0,
            "total_words": 0,
        }
        stage_stats: dict[str, Any] = {
            "prescan": {"time_t_aliases": 0},
            "ir": {"candidates": 0, "after_structural_filter": None},
            "io_boundary": {"candidates": None},
            "llm": {"total_tokens": 0, "prompt_tokens": 0, "completion_tokens": 0, "requests": 0, "by_pass": {}},
        }
        identity: RepoIdentity | None = None
        repo_dir: Path | None = None
        per_repo_dir: Path | None = None

        try:
            identity = _parse_repo_identity(task.repo_url, cache_dir)
            repo_dir = identity.cache_path
            requested_ref = args.ref_override or task.ref
            dry_ref_label = requested_ref or "default"
            dry_repo_key = _repo_key(identity, dry_ref_label)
            per_repo_dir = run_dir / "repos" / dry_repo_key
            per_repo_dir.mkdir(parents=True, exist_ok=True)

            LOGGER.info("[%d/%d] %s", idx, len(tasks), dry_repo_key)
            if args.dry_run:
                stage = "done"
                status = "skipped"
                counters["skipped"] += 1
                results.append(
                    {
                        "repo_key": dry_repo_key,
                        "repo_url": task.repo_url,
                        "status": status,
                        "stage": stage,
                        "message": "dry-run: skipped execution",
                    }
                )
                continue

            _prepare_repo(identity, task.repo_url)
            resolved_ref_input, resolved_sha, resolved_ref = _resolve_ref(repo_dir, requested_ref)
            _checkout_clean(repo_dir, resolved_ref, resolved_sha)

            resolved_repo_key = _repo_key(identity, resolved_ref or resolved_sha or dry_ref_label)
            if resolved_repo_key != dry_repo_key:
                resolved_repo_dir = run_dir / "repos" / resolved_repo_key
                if per_repo_dir.exists() and not any(per_repo_dir.iterdir()):
                    per_repo_dir.rename(resolved_repo_dir)
                else:
                    resolved_repo_dir.mkdir(parents=True, exist_ok=True)
                per_repo_dir = resolved_repo_dir

            stage = "config_detect"
            # Experimental auto-detect; prefer explicit config_id in JSONL when known.
            from config_detector.likelihoods import detect_config_likelihoods

            detection = detect_config_likelihoods(str(repo_dir), use_llm=False)
            if detection.get("experimental"):
                LOGGER.warning(
                    "config auto-detect is experimental; prefer explicit config_id/env_config when known"
                )
            detector_overall_confidence = float(detection.get("overall_confidence") or 0.0)
            detector_recommended_id = detection.get("recommended_config_id")
            if not isinstance(detector_recommended_id, str) or not detector_recommended_id:
                detector_recommended_id = _parse_detector_recommended_id(detection.get("recommended"))
            elif detector_recommended_id.strip().lower() not in VALID_CONFIG_IDS:
                detector_recommended_id = None
            else:
                detector_recommended_id = detector_recommended_id.strip().lower()
            detector_top_id = _top_likelihood_config_id(detection.get("likelihoods", []))
            detection_payload = {
                "overall_confidence": detector_overall_confidence,
                "recommended": _to_plain_dict(detection.get("recommended")) if detection.get("recommended") else None,
                "recommended_config_id": detector_recommended_id,
                "top_likelihood_config_id": detector_top_id,
                "likelihoods": [_to_plain_dict(l) for l in detection.get("likelihoods", [])],
                "experimental": bool(detection.get("experimental", True)),
            }
            _write_json(per_repo_dir / "config_detection.json", detection_payload)

            overrides, override_warnings = _scan_overrides(task.scan_overrides)
            repo_warnings.extend(override_warnings)
            explicit_config_override = overrides.get("config_override")
            explicit_config_id = (
                explicit_config_override.strip().lower()
                if isinstance(explicit_config_override, str) and explicit_config_override.strip()
                else None
            )
            if explicit_config_id is not None and explicit_config_id not in VALID_CONFIG_IDS:
                raise RuntimeError(f"invalid config_override: {explicit_config_override}")

            if explicit_config_id:
                effective_config_id = explicit_config_id
                config_source = "explicit"
                config_reason = "repo override config_override provided"
            elif detector_recommended_id and detector_overall_confidence >= args.config_min_confidence:
                effective_config_id = detector_recommended_id
                config_source = "detected"
                config_reason = "detector recommendation meets confidence threshold"
            else:
                effective_config_id = fallback_config_id
                config_source = "fallback"
                config_reason = "detector recommendation missing or below confidence threshold"

            env_config_path = per_repo_dir / "env_config.json"
            _write_json(env_config_path, _config_id_to_env_json(effective_config_id))

            include_patterns = build_include_patterns(
                overrides.get("file_extensions")
                if isinstance(overrides.get("file_extensions"), list)
                else [".c", ".cpp", ".c++", ".h", ".hpp", ".h++"],
                None,
            )
            exclude_patterns = (
                overrides.get("exclude_patterns")
                if isinstance(overrides.get("exclude_patterns"), list)
                else ["**/tests/**", "**/test/**"]
            )
            include_no_findings = bool(overrides.get("include_no_findings", args.include_no_findings))
            enable_llm = bool(overrides.get("enable_llm", args.enable_llm))
            llm_type = str(overrides.get("llm_type", args.llm_type)).strip().lower()
            model = str(overrides.get("model", args.model)).strip()
            if llm_type not in {"ollama", "openai", "anthropic", "gemini"}:
                raise ValueError(f"invalid llm_type override: {llm_type}")
            disable_stage1 = bool(overrides.get("disable_stage1", args.disable_stage1))
            detect_y2106 = bool(overrides.get("detect_y2106", args.detect_y2106))
            confidence_floor_raw = overrides.get("confidence_floor", overrides.get("confidence_threshold", args.confidence_floor))
            confidence_floor = float(confidence_floor_raw)
            llm_enabled_count += int(enable_llm)
            stage1_disabled_count += int(disable_stage1)
            y2106_enabled_count += int(detect_y2106)
            config_source_counts[config_source] = config_source_counts.get(config_source, 0) + 1

            stage = "scan"
            pipeline = _build_pipeline(
                include_no_findings=include_no_findings,
                enable_llm=enable_llm,
                llm_type=llm_type,
                model=model,
                disable_stage1=disable_stage1,
                detect_y2106=detect_y2106,
                confidence_floor=confidence_floor,
                timeout_sec=args.scanner_timeout_sec,
            )
            pipeline.environment_config_path = str(env_config_path)

            rules_path = (Path(__file__).resolve().parent / "rules" / "y2038_sample_rules.json")
            if not rules_path.exists():
                raise FileNotFoundError(f"rules path not found: {rules_path}")

            scan_out = per_repo_dir / "scan" / "findings.json"
            scan_out.parent.mkdir(parents=True, exist_ok=True)
            # Run scan with cwd scoped to this repo's scan folder so legacy
            # relative writes (e.g., findings.json) do not land in project root.
            original_cwd = Path.cwd()
            os.chdir(scan_out.parent)
            try:
                results_obj = pipeline.scan(
                    root_path=str(repo_dir),
                    rules_path=str(rules_path),
                    include_patterns=include_patterns,
                    exclude_patterns=exclude_patterns,
                    min_risk="medium",
                    output_base=str(scan_out.parent.resolve()),
                )
            finally:
                os.chdir(original_cwd)
            pipeline.save_results(results_obj, str(scan_out))
            finding_summary = _parse_findings_summary(scan_out)
            repo_metrics = _extract_scan_metrics(results_obj)
            stage_stats = _extract_stage_stats(scan_out.parent)
            if repo_metrics.get("total_files", 0) > 0 or repo_metrics.get("total_lines", 0) > 0:
                aggregate_metrics["repos_with_metrics"] += 1
            aggregate_metrics["total_files_scanned"] += int(repo_metrics.get("total_files", 0) or 0)
            aggregate_metrics["total_lines_scanned"] += int(repo_metrics.get("total_lines", 0) or 0)
            aggregate_metrics["total_chars_scanned"] += int(repo_metrics.get("total_chars", 0) or 0)
            aggregate_metrics["total_words_scanned"] += int(repo_metrics.get("total_words", 0) or 0)
            aggregate_stage_stats["prescan"]["time_t_aliases"] += int(stage_stats.get("prescan", {}).get("time_t_aliases", 0) or 0)
            aggregate_stage_stats["ir"]["candidates"] += int(stage_stats.get("ir", {}).get("candidates", 0) or 0)
            io_candidates = stage_stats.get("io_boundary", {}).get("candidates")
            if isinstance(io_candidates, int):
                aggregate_stage_stats["io_boundary"]["candidates"] += io_candidates
                aggregate_stage_stats["io_boundary"]["repos_with_io_stat"] += 1
            aggregate_stage_stats["llm"]["total_tokens"] += int(stage_stats.get("llm", {}).get("total_tokens", 0) or 0)
            aggregate_stage_stats["llm"]["prompt_tokens"] += int(stage_stats.get("llm", {}).get("prompt_tokens", 0) or 0)
            aggregate_stage_stats["llm"]["completion_tokens"] += int(stage_stats.get("llm", {}).get("completion_tokens", 0) or 0)
            aggregate_stage_stats["llm"]["requests"] += int(stage_stats.get("llm", {}).get("requests", 0) or 0)
            counters["success"] += 1
            stage = "done"

            _write_json(
                per_repo_dir / "meta.json",
                {
                    "repo_url": task.repo_url,
                    "name": task.name,
                    "source_line": task.source_line,
                    "resolved_ref_input": resolved_ref_input,
                    "resolved_ref": resolved_ref,
                    "resolved_commit_sha": resolved_sha,
                    "cache_path": str(repo_dir),
                    "config_source": config_source,
                    "config_reason": config_reason,
                    "effective_config_id": effective_config_id,
                    "detector_overall_confidence": detector_overall_confidence,
                    "detector_recommended_config_id": detector_recommended_id,
                    "detector_top_likelihood_config_id": detector_top_id,
                    "effective_options": {
                        "enable_llm": enable_llm,
                        "disable_stage1": disable_stage1,
                        "detect_y2106": detect_y2106,
                        "confidence_floor": confidence_floor,
                        "include_no_findings": include_no_findings,
                    },
                },
            )
            _write_json(
                per_repo_dir / "status.json",
                {
                    "repo_key": resolved_repo_key,
                    "repo_url": task.repo_url,
                    "name": task.name,
                    "started_at": datetime.fromtimestamp(repo_started, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
                    "completed_at": _utc_now_iso(),
                    "duration_sec": round(time.time() - repo_started, 3),
                    "stage": stage,
                    "status": status,
                    "error_code": error_code,
                    "error_message": error_message,
                    "resolved_commit_sha": resolved_sha,
                    "config_source": config_source,
                    "effective_config_id": effective_config_id or None,
                    "warnings": repo_warnings,
                    "findings_summary": finding_summary,
                    "scan_metrics": repo_metrics,
                    "stage_stats": stage_stats,
                },
            )
            results.append(
                {
                    "repo_key": resolved_repo_key,
                    "repo_url": task.repo_url,
                    "status": status,
                    "resolved_commit_sha": resolved_sha,
                    "config_source": config_source,
                    "effective_config_id": effective_config_id,
                    "findings_summary": finding_summary,
                    "scan_metrics": repo_metrics,
                    "stage_stats": stage_stats,
                }
            )
        except subprocess.TimeoutExpired:
            status = "timeout"
            error_code = "SCAN_TIMEOUT"
            error_message = f"scan exceeded timeout ({args.scanner_timeout_sec}s)"
            counters["timeout"] += 1
        except RuntimeError as e:
            status = "failed"
            msg = str(e).lower()
            if "requested ref not found" in msg:
                error_code = "REF_NOT_FOUND"
            elif "clone" in msg:
                error_code = "CLONE_FAILED"
            elif "fetch" in msg:
                error_code = "FETCH_FAILED"
            elif "checkout" in msg:
                error_code = "CHECKOUT_FAILED"
            elif "invalid config_override" in msg:
                error_code = "INVALID_CONFIG_OVERRIDE"
            else:
                error_code = "SCAN_FAILED"
            error_message = str(e)
            counters["failed"] += 1
        except Exception as e:
            # If config detection fails, the user wants that called out explicitly.
            status = "failed"
            if stage == "config_detect":
                error_code = "CONFIG_DETECT_FAILED"
            else:
                error_code = "INTERNAL_ERROR"
            error_message = str(e)
            counters["failed"] += 1

        if status != "success":
            repo_key = _repo_key(identity, resolved_ref or resolved_sha or (args.ref_override or task.ref or "default")) if identity else f"line_{task.source_line}"
            LOGGER.error("repo failed [%s]: %s (%s)", repo_key, error_message, error_code)
            results.append(
                {
                    "repo_key": repo_key,
                    "repo_url": task.repo_url,
                    "status": status,
                    "stage": stage,
                    "error_code": error_code,
                    "error_message": error_message,
                }
            )
            if per_repo_dir is not None:
                _write_json(
                    per_repo_dir / "status.json",
                    {
                        "repo_key": repo_key,
                        "repo_url": task.repo_url,
                        "name": task.name,
                        "started_at": datetime.fromtimestamp(repo_started, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
                        "completed_at": _utc_now_iso(),
                        "duration_sec": round(time.time() - repo_started, 3),
                        "stage": stage,
                        "status": status,
                        "error_code": error_code,
                        "error_message": error_message,
                        "resolved_commit_sha": resolved_sha or None,
                        "config_source": config_source,
                        "effective_config_id": effective_config_id or None,
                        "llm_type": llm_type if enable_llm else "none",
                        "model": model if enable_llm else None,
                        "warnings": repo_warnings,
                        "scan_metrics": repo_metrics,
                        "stage_stats": stage_stats,
                    },
                )
            if args.fail_fast or not args.continue_on_error:
                break

    summary = {
        "run_id": run_id,
        "started_at": datetime.fromtimestamp(start_ts, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        "completed_at": _utc_now_iso(),
        "duration_sec": round(time.time() - start_ts, 3),
        "args": {
            "repos_file": str(repos_file),
            "cache_dir": str(cache_dir),
            "out_dir": str(out_root),
            "continue_on_error": args.continue_on_error,
            "fail_fast": args.fail_fast,
            "ref_override": args.ref_override,
            "repo_filters": args.repo,
            "limit": args.limit,
            "dry_run": args.dry_run,
            "scanner_timeout_sec": args.scanner_timeout_sec,
            "enable_llm": args.enable_llm,
            "llm_type": args.llm_type,
            "model": args.model,
            "disable_stage1": args.disable_stage1,
            "detect_y2106": args.detect_y2106,
            "confidence_floor": args.confidence_floor,
            "fallback_config": fallback_config_id,
            "config_min_confidence": args.config_min_confidence,
            "include_no_findings": args.include_no_findings,
            "verbose": args.verbose,
        },
        "counts": {
            "total_input_records": len(all_tasks) + len(parse_warnings),
            "eligible_repos": len(tasks),
            "processed": len(results),
            **counters,
        },
        "aggregates": {
            "config_source_counts": config_source_counts,
            "llm_enabled_count": llm_enabled_count,
            "stage1_disabled_count": stage1_disabled_count,
            "y2106_enabled_count": y2106_enabled_count,
            "scan_metrics": aggregate_metrics,
            "stage_stats": aggregate_stage_stats,
        },
        "warnings": parse_warnings,
        "results": results,
    }
    _write_json(run_dir / "summary.json", summary)

    LOGGER.info("batch complete: success=%d failed=%d timeout=%d skipped=%d", counters["success"], counters["failed"], counters["timeout"], counters["skipped"])
    LOGGER.info("summary written: %s", run_dir / "summary.json")
    return 0 if counters["failed"] == 0 and counters["timeout"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
