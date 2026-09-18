# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import json
import logging
import re
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from tacs.batch_repo_scan import (
    DEFAULT_GRACE_SEC,
    RepoScanJob,
    RepoScanOutcome,
    discard_staged_findings,
    run_repo_scan_with_deadline,
)
from tacs.core.env_capabilities import UNKNOWN_SETTING, time64_suffix
from tacs.core.file_limits import validate_max_file_size
from tacs.core.llm_client import DEFAULT_CONFIDENCE_FLOOR
from tacs.core.include_patterns import build_include_patterns
from tacs.core.path_utils import display_local_path, update_latest_symlink
from tacs.core.run_ids import new_run_id
from tacs.core.status_logger import StatusLogger, format_count
from tacs.llm.env import DEFAULT_MODEL, default_llm_type, default_model_id


LOGGER = logging.getLogger("tacs.batch_scan_repos")


class RepoScanTimeout(Exception):
    """One repository's scan outran the ``--scanner-timeout-sec`` wall clock."""


class RepoScanFailed(Exception):
    """One repository's scan process failed rather than timing out."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str = "SCAN_FAILED",
        detail: str | None = None,
    ) -> None:
        super().__init__(message)
        self.error_code = error_code
        # The child's traceback, shown only at DEBUG: the failure happened in
        # another process, so printing its stack with the error would be noise.
        self.detail = detail


def _run_repo_scan(job: RepoScanJob, *, deadline_sec: float) -> RepoScanOutcome:
    """Seam for running one repository's scan under the deadline."""
    return run_repo_scan_with_deadline(job, deadline_sec=deadline_sec)

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

    @property
    def safe_url(self) -> str:
        """The repo URL with embedded credentials removed, for output and artifacts."""
        return redact_url_credentials(self.repo_url)


@dataclass
class RepoIdentity:
    host: str
    owner: str
    repo: str
    cache_path: Path


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sanitize_token(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("_") or "unknown"


# Userinfo in a URL: the "user" or "user:password" between the scheme and the
# host. The character class stops at the authority so an "@" later in the path
# is not mistaken for a credential separator.
_URL_USERINFO = re.compile(
    r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*)://(?P<userinfo>[^/?#@\s]*)@"
)
_SECRET_SCHEMES = {"http", "https"}


def url_carries_credentials(url: str) -> bool:
    """
    True when a repository URL embeds a credential.

    Over http(s) any userinfo counts: an access token is conventionally passed as
    the username with no password at all, so ``https://TOKEN@host/repo.git`` is
    the common shape. Other transports use a bare username routinely -- nothing
    is secret about ``ssh://git@host/repo.git`` -- so there only an embedded
    password counts.
    """
    match = _URL_USERINFO.match((url or "").strip())
    if not match:
        return False
    if match.group("scheme").lower() in _SECRET_SCHEMES:
        return True
    return ":" in match.group("userinfo")


def redact_url_credentials(text: str) -> str:
    """
    Remove credentials from any URL appearing in ``text``.

    Applied to console output, persisted artifacts, and error messages. Credential
    URLs are rejected when the repo list is read, so this mainly guards text TACS
    did not compose itself -- notably git's stderr, which echoes the remote URL
    recorded in a clone's config.
    """

    def _replace(match: re.Match[str]) -> str:
        scheme = match.group("scheme")
        userinfo = match.group("userinfo")
        if scheme.lower() in _SECRET_SCHEMES:
            return f"{scheme}://***@"
        if ":" in userinfo:
            # Keep the username: on these transports it is a routine identity.
            return f"{scheme}://{userinfo.split(':', 1)[0]}:***@"
        return match.group(0)

    return _URL_USERINFO.sub(_replace, text or "")


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
        # Message becomes error_message in status.json and summary.json.
        raise ValueError(
            "could not parse repo identity from URL: "
            f"{redact_url_credentials(repo_url)}"
        )

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
        # The message reaches the console, status.json, and summary.json. Both the
        # arguments (a clone URL) and git's own output can name a remote.
        raise RuntimeError(
            redact_url_credentials(
                f"git {' '.join(args)} failed: {stderr or stdout or 'unknown error'}"
            )
        )
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
            if url_carries_credentials(repo_url):
                # The URL itself is never quoted back: the warning is persisted in
                # summary.json, which is exactly where the token must not land.
                # Cloning would also write it into the cache clone's .git/config.
                warnings.append(
                    f"line {idx}: repo_url embeds credentials; skipped. Remove them "
                    "and authenticate with a git credential helper or an SSH remote"
                )
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


def _format_no_llm_repo_summary(repo_key: str, finding_summary: dict[str, int]) -> str:
    """Build the per-repo INFO summary line when LLM classification is disabled."""
    total = int(finding_summary.get("total_findings", 0) or 0)
    if total == 0:
        return f"{repo_key}: No Y2038 candidate findings detected"
    yes = int(finding_summary.get("yes_findings", 0) or 0)
    abstain = int(finding_summary.get("abstain_findings", 0) or 0)
    return (
        f"{repo_key}: {yes} confirmed Y2038 issues; "
        f"{format_count(abstain, 'candidate finding')} "
        f"{'remains' if abstain == 1 else 'remain'} unclassified (LLM disabled)"
    )


def _format_llm_repo_summary(
    repo_key: str,
    finding_summary: dict[str, int],
    classification: dict[str, int] | None,
    function_classification: dict[str, int] | None = None,
) -> str:
    """Build the per-repo INFO summary line when LLM classification ran.

    Safe ("no") verdicts are dropped before findings are persisted. Function
    classifications (one verdict per function_id) are reported separately from
    the retained finding-record count, because one function-level yes can expand
    into multiple retained records.
    """
    retained = int(finding_summary.get("total_findings", 0) or 0)
    retained_text = f"retained finding records: {retained}"
    counts = function_classification if function_classification else classification
    if not counts:
        return f"{repo_key}: {retained_text}"
    label = (
        "final function classifications"
        if function_classification
        else "finding classifications"
    )
    return (
        f"{repo_key}: {label}: {int(counts.get('yes', 0) or 0)} yes, "
        f"{int(counts.get('no', 0) or 0)} no, "
        f"{int(counts.get('abstain', 0) or 0)} abstain; "
        f"{retained_text}"
    )


def _classification_counts_payload(pipeline: Any) -> dict[str, int] | None:
    """Read finding-level verdict counts recorded before output filtering."""
    counts = getattr(pipeline, "last_classification_counts", None)
    if not isinstance(counts, dict):
        return None
    return {k: int(v) for k, v in counts.items() if isinstance(v, int)}


def _function_classification_counts_payload(pipeline: Any) -> dict[str, int] | None:
    """Read function-level verdict counts recorded before output filtering."""
    counts = getattr(pipeline, "last_function_classification_counts", None)
    if not isinstance(counts, dict):
        return None
    return {k: int(v) for k, v in counts.items() if isinstance(v, int)}


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


def _extract_stage_stats(repo_dir: Path) -> dict[str, Any]:
    """
    Read per-stage counters from the scan's stage_stats.json.

    Returns zeroed defaults when the file is missing or unreadable, so a repo that
    failed before the scan finished still aggregates cleanly.
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

    stats_path = repo_dir / "stage_stats.json"
    if not stats_path.is_file():
        return stats

    try:
        persisted = json.loads(stats_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return stats
    if not isinstance(persisted, dict):
        return stats

    for section, defaults in stats.items():
        values = persisted.get(section)
        if isinstance(values, dict):
            defaults.update({k: v for k, v in values.items() if k in defaults})

    return stats


#: Per-repository ``scan_overrides`` keys a repos file may set. Every key here is
#: read when the repository is scanned; anything else is reported and dropped.
#: ``confidence_threshold`` is an alias for ``confidence_floor``, which wins when
#: both appear.
SUPPORTED_SCAN_OVERRIDES = (
    "file_extensions",
    "exclude_patterns",
    "max_file_size",
    "llm",
    "model",
    "disable_stage1",
    "detect_y2106",
    "confidence_threshold",
    "confidence_floor",
    "include_no_findings",
    "config_override",
)

#: Providers a per-repository ``llm`` may name, matching ``--llm`` (including none).
SUPPORTED_LLM_PROVIDERS = ("none", "ollama", "openai", "anthropic", "gemini")

#: Former override keys: rejected with a clear error rather than accepted or ignored.
REMOVED_SCAN_OVERRIDES = {
    "enable_llm": (
        'scan_overrides.enable_llm is no longer supported; '
        'use "llm": "none" or a provider name (e.g. "ollama") instead'
    ),
    "llm_type": (
        'scan_overrides.llm_type is no longer supported; '
        'use "llm" instead (e.g. "anthropic" or "none")'
    ),
}


def _cli_default_llm() -> str:
    value = default_llm_type()
    return value if value in SUPPORTED_LLM_PROVIDERS else "none"


def _scan_overrides(overrides: dict[str, Any] | None) -> tuple[dict[str, Any], list[str]]:
    allowed = set(SUPPORTED_SCAN_OVERRIDES)
    cleaned: dict[str, Any] = {}
    warnings: list[str] = []
    if not overrides:
        return cleaned, warnings
    for key, value in overrides.items():
        if key in REMOVED_SCAN_OVERRIDES:
            raise ValueError(REMOVED_SCAN_OVERRIDES[key])
        if key in allowed:
            cleaned[key] = value
        else:
            warnings.append(f"ignoring unknown scan_overrides key: {key}")
    return cleaned, warnings


def _config_id_to_env_json(config_id: str) -> dict[str, Any]:
    """
    Build an environment config payload from a compact config id.

    Every field is derived from the three facts the config id establishes: hardware
    model, time_t signedness, and time_t width. Platform details the id does not
    imply (C library, OS/RTOS, time64 entry points, _TIME_BITS support) are left
    unspecified or unknown rather than guessed, because this payload is loaded by
    the pipeline and reaches the I/O analyzer and LLM prompts.
    """
    from tacs.core.config_validator import ConfigValidator

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

    normalized_id = f"{model}_{signedness}_{bits_part}"
    hardware_model = model.upper()
    time_t_size_bits = 32 if bits_part == "32bit" else 64

    config_info = ConfigValidator.get_config_info(normalized_id) or {}
    description = config_info.get(
        "description", f"{hardware_model} with {signedness} {time_t_size_bits}-bit time_t"
    )

    return {
        "config_id": normalized_id,
        "hardware_model": hardware_model,
        "time_t_size_bits": time_t_size_bits,
        "time_t_signed": signedness,
        # A config id names an ABI, and an ABI ships no entry points: a 64-bit
        # time_t does not put time64 variants in the C library, and nothing here
        # says whether that library honours _TIME_BITS. Recording false would
        # report a library nobody inspected as lacking features nobody checked.
        "time64_functions_available": None,
        "d_time_bits_supported": None,
        "d_time_bits_setting": UNKNOWN_SETTING,
        "c_library": "other",
        "c_library_other_text": "unspecified (derived from config id)",
        "os_or_rtos": "unspecified",
        "notes": (
            f"{description}. Derived from config id {normalized_id}; "
            "C library, OS/RTOS, time64 entry points and _TIME_BITS support are "
            "not established by the config id."
        ),
        "scenario_hint": (
            f"{hardware_model}-{time_t_size_bits}bit-{signedness}"
            f"-time64_{time64_suffix(None)}"
        ),
        "mitigation_path": "upgrade_env" if time_t_size_bits == 32 else None,
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
    llm: str,
    model: str,
    disable_stage1: bool,
    detect_y2106: bool,
    confidence_floor: float,
    timeout_sec: int,
    environment_config_path: str,
    max_file_size: int | None = None,
) -> Any:
    """
    Construct the scanning pipeline for one repository.

    ``environment_config_path`` is required: the pipeline loads the environment
    config in its constructor and hands it to the I/O analyzer and LLM clients, so
    it cannot be supplied afterwards.

    ``llm`` is the provider selection (``none`` | ``ollama`` | …), matching
    ``tacs scan --llm``. When ``llm`` is ``none``, the model recorded on the
    pipeline is also ``none``.
    """
    # Import lazily so `--dry-run` can work without installing full scanner deps.
    from tacs.core.pipeline import ScanningPipeline

    # Packaged with tacs (same resolution as scan_command.py); not the pre-split src/scanner/ layout.
    scanner_path = Path(__file__).resolve().parent / "python" / "y2038scan_fast_json_group.py"
    if not scanner_path.exists():
        raise FileNotFoundError(f"Scanner script not found: {scanner_path}")
    if not Path(environment_config_path).is_file():
        raise FileNotFoundError(f"Environment config not found: {environment_config_path}")
    effective_llm = str(llm).strip().lower()
    effective_model = "none" if effective_llm == "none" else model
    return ScanningPipeline(
        scanner_path=str(scanner_path),
        llm_type=effective_llm,
        model=effective_model,
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
        environment_config_path=environment_config_path,
        debug_pass2=False,
        debug_candidates=False,
        debug_pass2_detailed=False,
        debug_llm_raw=False,
        debug_pass2_prompt=False,
        bypass_pass1=False,
        bypass_pass3=False,
        function_first=True,
        # Stage S1 needs an LLM, but the pipeline already skips it when llm_type is
        # "none", so this stays a plain read of the flag and keeps
        # --no-disable-stage1 meaning the same thing it means for tacs scan.
        enable_pass1=not disable_stage1,
        detect_y2106=detect_y2106,
        max_file_size=max_file_size,
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


def _resolve_effective_config(
    *,
    explicit_config_id: str | None,
    repo_dir: Path,
    fallback_config_id: str,
    config_min_confidence: float,
    detect_fn=None,
) -> tuple[str, str, str, dict[str, Any]]:
    """
    Choose effective ABI/time_t config for a repo.

    When ``explicit_config_id`` is set, auto-detection is skipped entirely.
    Returns ``(effective_config_id, config_source, config_reason, detection_payload)``.
    """
    if explicit_config_id:
        payload = {
            "skipped": True,
            "reason": "explicit config_override provided",
            "config_override": explicit_config_id,
            "experimental": True,
        }
        return (
            explicit_config_id,
            "explicit",
            "repo override config_override provided",
            payload,
        )

    if detect_fn is None:
        from config_detector.likelihoods import detect_config_likelihoods as detect_fn

    detection = detect_fn(str(repo_dir), use_llm=False)
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
        "recommended": _to_plain_dict(detection.get("recommended"))
        if detection.get("recommended")
        else None,
        "recommended_config_id": detector_recommended_id,
        "top_likelihood_config_id": detector_top_id,
        "likelihoods": [_to_plain_dict(l) for l in detection.get("likelihoods", [])],
        "experimental": bool(detection.get("experimental", True)),
    }
    if detector_recommended_id and detector_overall_confidence >= config_min_confidence:
        return (
            detector_recommended_id,
            "detected",
            "detector recommendation meets confidence threshold",
            detection_payload,
        )
    return (
        fallback_config_id,
        "fallback",
        "detector recommendation missing or below confidence threshold",
        detection_payload,
    )


def _repo_matches_filters(task: RepoTask, filters: Iterable[str]) -> bool:
    terms = [t.lower() for t in filters if t]
    if not terms:
        return True
    hay = f"{task.repo_url} {task.name or ''}".lower()
    return any(term in hay for term in terms)


def _build_parser() -> argparse.ArgumentParser:
    """
    Build the ``tacs repos`` parser.

    Kept separate from ``main()`` so tests can read the batch defaults and compare
    them against ``tacs scan``: the two commands drive one scanning engine and
    drifted apart once already.
    """
    parser = argparse.ArgumentParser(description="Batch scan repositories for Y2038 issues")
    parser.add_argument("--repos-file", required=True, help="Path to JSONL repos file")
    parser.add_argument(
        "--cache-dir",
        default=".repo_cache",
        help=(
            "Directory where cloned repositories are stored and retained for reuse "
            "across runs (default: .repo_cache; delete it to discard the clones)"
        ),
    )
    parser.add_argument(
        "--out-dir",
        default="results/batches",
        help="Batch output root directory (default: results/batches)",
    )
    parser.add_argument("--continue-on-error", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--fail-fast", action="store_true", help="Stop on first repository failure")
    parser.add_argument("--ref-override", help="Override ref for all repos")
    parser.add_argument("--repo", action="append", default=[], help="Filter repos by substring (repeatable)")
    parser.add_argument("--limit", type=int, help="Maximum repositories to process")
    parser.add_argument("--dry-run", action="store_true", help="Resolve/plan only, do not clone/scan")
    parser.add_argument(
        "--scanner-timeout-sec",
        type=int,
        default=3600,
        help=(
            "Per-repository scan timeout in seconds (default: 3600). The scan "
            "phase runs in its own process and is terminated once this deadline "
            "passes; cloning, ref resolution and config detection happen before "
            "it starts and are not counted. This is when termination begins, not "
            "the total elapsed time: shutting the process down can add up to "
            f"{int(DEFAULT_GRACE_SEC)}s more."
        ),
    )
    parser.add_argument(
        "--request-timeout-sec",
        type=int,
        default=300,
        help=(
            "Timeout in seconds for a single LLM request inside a scan "
            "(default: 300, matching tacs scan --timeout-sec). Ollama Cloud "
            "requests get twice this, and a failed request is retried up to 3 "
            "times, so one batch can take several multiples of this value "
            "before the per-repository deadline ends it."
        ),
    )
    parser.add_argument(
        "--log-level",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "debug", "info", "warning", "error"],
        help="Console diagnostic log level (default: INFO; --verbose implies DEBUG)",
    )
    parser.add_argument(
        "--llm",
        choices=list(SUPPORTED_LLM_PROVIDERS),
        default=None,
        help=(
            "LLM provider (default: none — set --llm or TACS_LLM_PROVIDER to opt in; "
            "matches tacs scan)"
        ),
    )
    parser.add_argument(
        "--model",
        default=None,
        help=(
            f"Model name for selected provider "
            f"(default: {DEFAULT_MODEL} or TACS_MODEL; ignored when --llm none)"
        ),
    )
    parser.add_argument("--disable-stage1", action=argparse.BooleanOptionalAction, default=True, help="Disable Stage 1 line-level pass (default: disabled)")
    parser.add_argument("--detect-y2106", action=argparse.BooleanOptionalAction, default=False, help="Enable Y2106 detection (default: disabled, matching tacs scan)")
    parser.add_argument("--confidence-floor", type=float, default=DEFAULT_CONFIDENCE_FLOOR, help=f"Confidence a classification needs to count as decided; the LLM prompts quote it too (default: {DEFAULT_CONFIDENCE_FLOOR})")
    parser.add_argument("--fallback-config", default=DEFAULT_FALLBACK_CONFIG_ID, help=f"Fallback config id when detection is uncertain (default: {DEFAULT_FALLBACK_CONFIG_ID})")
    parser.add_argument("--config-min-confidence", type=float, default=0.70, help="Minimum detection confidence to accept recommended config (default: 0.70)")
    parser.add_argument("--include-no-findings", action=argparse.BooleanOptionalAction, default=False, help="Include NO findings in output (default: disabled)")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    # Resolve provider/model the same way tacs scan does: explicit CLI wins,
    # otherwise TACS_LLM_PROVIDER / TACS_MODEL (and aliases), otherwise none /
    # DEFAULT_MODEL. Done after parse so env is read at invocation time.
    if args.llm is None:
        args.llm = _cli_default_llm()
    if args.model is None:
        args.model = default_model_id()

    from tacs.core.logging_config import configure_logging, resolve_log_level

    effective_log_level = resolve_log_level(
        log_level=args.log_level, verbose=bool(args.verbose)
    )
    configure_logging(effective_log_level)

    fallback_config_id = args.fallback_config.strip().lower()
    if fallback_config_id not in VALID_CONFIG_IDS:
        raise SystemExit(f"invalid --fallback-config: {args.fallback_config}")
    if args.scanner_timeout_sec <= 0:
        raise SystemExit(
            "error: --scanner-timeout-sec must be greater than 0 "
            f"(got {args.scanner_timeout_sec})"
        )
    if args.request_timeout_sec <= 0:
        raise SystemExit(
            "error: --request-timeout-sec must be greater than 0 "
            f"(got {args.request_timeout_sec})"
        )

    # Logging already configured above; keep verbose flag for summary metadata only.

    start_ts = time.time()
    run_id = new_run_id()
    repos_file = Path(args.repos_file).resolve()
    if not repos_file.is_file():
        raise SystemExit(f"error: --repos-file not found: {repos_file}")
    cache_dir = Path(args.cache_dir).resolve()
    out_root = Path(args.out_dir).resolve()
    run_dir = out_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # Point <out-dir>/latest at this run now rather than on completion, so the
    # link is usable while the batch is running and still resolves to the run
    # that failed if one does. A dry run is not a result worth pointing at.
    if not args.dry_run:
        latest_link = out_root / "latest"
        if update_latest_symlink(latest_link, run_dir):
            LOGGER.debug("latest link: %s -> %s", latest_link, run_id)
        else:
            LOGGER.warning("could not update latest link: %s", latest_link)

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
        # Defaults so the failure path can report options even if a repo fails
        # before per-repo overrides are resolved.
        llm = str(args.llm).strip().lower()
        model = "none" if llm == "none" else str(args.model)
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

            # Essential progress: visible at every log level (not filtered as INFO).
            # Omit "@ default" — that token is a resolve instruction, not a Git ref.
            if requested_ref:
                StatusLogger.always(
                    f"[{idx}/{len(tasks)}] {identity.owner}/{identity.repo} "
                    f"@ {requested_ref} — {task.safe_url}"
                )
            else:
                StatusLogger.always(
                    f"[{idx}/{len(tasks)}] {identity.owner}/{identity.repo} "
                    f"— {task.safe_url}"
                )
            if args.dry_run:
                stage = "done"
                status = "skipped"
                counters["skipped"] += 1
                results.append(
                    {
                        "repo_key": dry_repo_key,
                        "repo_url": task.safe_url,
                        "status": status,
                        "stage": stage,
                        "message": "dry-run: skipped execution",
                    }
                )
                continue

            _prepare_repo(identity, task.repo_url)
            resolved_ref_input, resolved_sha, resolved_ref = _resolve_ref(repo_dir, requested_ref)
            _checkout_clean(repo_dir, resolved_ref, resolved_sha)
            if not requested_ref:
                short_sha = (resolved_sha or "")[:12] or "unknown"
                branch = resolved_ref or short_sha
                LOGGER.info("Resolved ref: %s @ %s", branch, short_sha)

            resolved_repo_key = _repo_key(identity, resolved_ref or resolved_sha or dry_ref_label)
            if resolved_repo_key != dry_repo_key:
                resolved_repo_dir = run_dir / "repos" / resolved_repo_key
                if per_repo_dir.exists() and not any(per_repo_dir.iterdir()):
                    per_repo_dir.rename(resolved_repo_dir)
                else:
                    resolved_repo_dir.mkdir(parents=True, exist_ok=True)
                per_repo_dir = resolved_repo_dir

            stage = "scan_overrides"
            overrides, override_warnings = _scan_overrides(task.scan_overrides)
            repo_warnings.extend(override_warnings)

            stage = "config_detect"
            explicit_config_override = overrides.get("config_override")
            explicit_config_id = (
                explicit_config_override.strip().lower()
                if isinstance(explicit_config_override, str) and explicit_config_override.strip()
                else None
            )
            if explicit_config_id is not None and explicit_config_id not in VALID_CONFIG_IDS:
                raise RuntimeError(f"invalid config_override: {explicit_config_override}")

            effective_config_id, config_source, config_reason, detection_payload = (
                _resolve_effective_config(
                    explicit_config_id=explicit_config_id,
                    repo_dir=repo_dir,
                    fallback_config_id=fallback_config_id,
                    config_min_confidence=args.config_min_confidence,
                )
            )
            if config_source == "explicit":
                LOGGER.debug(
                    "skipping config auto-detect for %s (config_override=%s)",
                    dry_repo_key,
                    explicit_config_id,
                )

            _write_json(per_repo_dir / "config_detection.json", detection_payload)

            env_config_path = per_repo_dir / "env_config.json"
            _write_json(env_config_path, _config_id_to_env_json(effective_config_id))

            # Own stage so a rejected override is not reported as a config-detection
            # failure, which is what the caller would go looking at.
            stage = "scan_overrides"
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
            # Per-repo provider/model win over the batch-wide CLI defaults. Both are
            # validated here so a bad value fails this repository with a clear
            # message instead of reaching a provider call. ``llm=none`` is the only
            # way to disable LLM analysis for a repository.
            llm = str(overrides.get("llm", args.llm)).strip().lower()
            if llm not in SUPPORTED_LLM_PROVIDERS:
                raise ValueError(
                    f"invalid llm override: {overrides.get('llm')!r} "
                    f"(supported: {', '.join(SUPPORTED_LLM_PROVIDERS)})"
                )
            if llm == "none":
                model = "none"
            else:
                model = str(overrides.get("model", args.model)).strip()
                if not model:
                    raise ValueError("model override must not be empty")
            max_file_size = validate_max_file_size(overrides.get("max_file_size"))
            disable_stage1 = bool(overrides.get("disable_stage1", args.disable_stage1))
            detect_y2106 = bool(overrides.get("detect_y2106", args.detect_y2106))
            confidence_floor_raw = overrides.get("confidence_floor", overrides.get("confidence_threshold", args.confidence_floor))
            confidence_floor = float(confidence_floor_raw)
            llm_enabled_count += int(llm != "none")
            stage1_disabled_count += int(disable_stage1)
            y2106_enabled_count += int(detect_y2106)
            config_source_counts[config_source] = config_source_counts.get(config_source, 0) + 1

            stage = "scan"
            rules_path = (Path(__file__).resolve().parent / "rules" / "y2038_sample_rules.json")
            if not rules_path.exists():
                raise FileNotFoundError(f"rules path not found: {rules_path}")

            # The scan runs in a child process so the deadline below is a real
            # wall clock: nothing inside a scan (subprocesses, provider sockets,
            # C extensions) can be interrupted reliably from within.
            job = RepoScanJob(
                repo_key=per_repo_dir.name,
                repo_root=str(repo_dir),
                rules_path=str(rules_path),
                per_repo_dir=str(per_repo_dir.resolve()),
                env_config_path=str(env_config_path),
                include_patterns=list(include_patterns),
                exclude_patterns=list(exclude_patterns),
                include_no_findings=include_no_findings,
                llm=llm,
                model=model,
                disable_stage1=disable_stage1,
                detect_y2106=detect_y2106,
                confidence_floor=confidence_floor,
                max_file_size=max_file_size,
                # Bounds one LLM request; the deadline below bounds the
                # repository. A wedged request should not spend the whole
                # repository budget, so these are set separately.
                request_timeout_sec=args.request_timeout_sec,
                log_level=effective_log_level,
            )
            outcome = _run_repo_scan(job, deadline_sec=args.scanner_timeout_sec)
            if outcome.timed_out:
                raise RepoScanTimeout(
                    f"scan exceeded timeout ({args.scanner_timeout_sec}s)"
                )
            if outcome.status == "crashed":
                raise RepoScanFailed(
                    "scan process exited without a result "
                    f"(exit code {outcome.exit_code})",
                    error_code="SCAN_CRASHED",
                )
            if not outcome.payload.get("ok"):
                error_type = str(outcome.payload.get("error_type") or "Exception")
                message = str(outcome.payload.get("error_message") or "scan failed")
                # A scanner subprocess that ran out of time inside the child is
                # still a timeout, as it was when the scan ran in the parent.
                if error_type == "TimeoutExpired":
                    raise RepoScanTimeout(message)
                raise RepoScanFailed(
                    f"{error_type}: {message}",
                    detail=outcome.payload.get("error_traceback"),
                )

            finding_summary = outcome.payload.get("findings_summary") or {}
            classification_counts = outcome.payload.get("classification_counts")
            function_classification_counts = outcome.payload.get(
                "function_classification_counts"
            )
            repo_metrics = outcome.payload.get("scan_metrics") or repo_metrics
            stage_stats = outcome.payload.get("stage_stats") or stage_stats
            # Read off the pipeline the child actually built, so this says how the
            # scan was configured rather than what was requested.
            effective = outcome.payload.get("effective") or {}
            LOGGER.debug(
                "scan finished in %.1fs: llm=%s model=%s",
                outcome.duration_sec,
                effective.get("llm"),
                effective.get("model"),
            )
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
                    "repo_url": task.safe_url,
                    "name": task.name,
                    "source_line": task.source_line,
                    "resolved_ref_input": resolved_ref_input,
                    "resolved_ref": resolved_ref,
                    "resolved_commit_sha": resolved_sha,
                    "config_source": config_source,
                    "config_reason": config_reason,
                    "effective_config_id": effective_config_id,
                    "detector_overall_confidence": detector_overall_confidence,
                    "detector_recommended_config_id": detector_recommended_id,
                    "detector_top_likelihood_config_id": detector_top_id,
                    "effective_options": {
                        "llm": llm,
                        "model": model if llm != "none" else "none",
                        "max_file_size": max_file_size,
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
                    "repo_url": task.safe_url,
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
                    # Finding-level verdicts before safe findings were dropped.
                    "classification_counts": classification_counts,
                    # Function-level verdicts (comparable to Stage 8/9 summaries).
                    "function_classification_counts": function_classification_counts,
                    "scan_metrics": repo_metrics,
                    "stage_stats": stage_stats,
                },
            )
            results.append(
                {
                    "repo_key": resolved_repo_key,
                    "repo_url": task.safe_url,
                    "status": status,
                    "resolved_commit_sha": resolved_sha,
                    "config_source": config_source,
                    "effective_config_id": effective_config_id,
                    "findings_summary": finding_summary,
                    "classification_counts": classification_counts,
                    "function_classification_counts": function_classification_counts,
                    "scan_metrics": repo_metrics,
                    "stage_stats": stage_stats,
                }
            )
        except RepoScanTimeout as e:
            status = "timeout"
            error_code = "SCAN_TIMEOUT"
            error_message = str(e)
            counters["timeout"] += 1
        except RepoScanFailed as e:
            status = "failed"
            error_code = e.error_code
            error_message = str(e)
            if e.detail:
                LOGGER.debug("scan process failure detail:\n%s", e.detail)
            counters["failed"] += 1
        except subprocess.TimeoutExpired:
            # Git operations during preparation carry their own timeout.
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
            elif stage == "scan_overrides":
                error_code = "INVALID_SCAN_OVERRIDE"
            else:
                error_code = "INTERNAL_ERROR"
            error_message = str(e)
            counters["failed"] += 1

        if status != "success":
            repo_key = _repo_key(identity, resolved_ref or resolved_sha or (args.ref_override or task.ref or "default")) if identity else f"line_{task.source_line}"
            LOGGER.error("repo failed [%s]: %s (%s)", repo_key, error_message, error_code)
            # A killed child can leave the staged findings file behind. Artifacts
            # it finished writing are kept; this one was never complete, and
            # publishing it would claim a scan that did not finish.
            if per_repo_dir is not None:
                discard_staged_findings(per_repo_dir)
            results.append(
                {
                    "repo_key": repo_key,
                    "repo_url": task.safe_url,
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
                        "repo_url": task.safe_url,
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
                        "llm": llm,
                        "model": model if llm != "none" else "none",
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
            "repos_file": display_local_path(repos_file),
            "cache_dir": display_local_path(cache_dir),
            "out_dir": display_local_path(out_root),
            "continue_on_error": args.continue_on_error,
            "fail_fast": args.fail_fast,
            "ref_override": args.ref_override,
            "repo_filters": args.repo,
            "limit": args.limit,
            "dry_run": args.dry_run,
            "scanner_timeout_sec": args.scanner_timeout_sec,
            "request_timeout_sec": args.request_timeout_sec,
            "llm": args.llm,
            "model": "none" if args.llm == "none" else args.model,
            "disable_stage1": args.disable_stage1,
            "detect_y2106": args.detect_y2106,
            "confidence_floor": args.confidence_floor,
            "fallback_config": fallback_config_id,
            "config_min_confidence": args.config_min_confidence,
            "include_no_findings": args.include_no_findings,
            "log_level": resolve_log_level(
                log_level=args.log_level, verbose=bool(args.verbose)
            ),
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
