# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for what the LLM prompts actually tell the model.

Three defects motivate these: prompts quoted a hardcoded 0.85 while the run
applied a configured ``--confidence-floor``; examples once contradicted the
environment facts they shipped with (or were rewritten from them); and the
function-first prompt's JSON examples reached the model with doubled braces, so
every example of the required output format was malformed.

These assert on prompt text, which is deliberate: the prompt is the interface to
the model, and a scan's verdicts cannot be read as measurements of a model if the
instructions disagree with the configuration they were produced under.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tacs.core.function_llm_client import FunctionLLMClient
from tacs.core.function_schemas import FunctionBatch, FunctionBody
from tacs.core.llm_client import DEFAULT_CONFIDENCE_FLOOR, LLMClient
from tacs.core.llm_prompt import LLMPromptParts
from tacs.core.schema import Candidate, LLMResponse, Y2038Issue

SCANNER = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "tacs"
    / "python"
    / "y2038scan_fast_json_group.py"
)

ILP32_SIGNED = {
    "hardware_model": "ILP32",
    "time_t_size_bits": 32,
    "time_t_signed": "signed",
    "scenario_hint": "ILP32-32bit-signed-time64_no",
    "c_library": "glibc",
}
ILP32_UNSIGNED = {
    "hardware_model": "ILP32",
    "time_t_size_bits": 32,
    "time_t_signed": "unsigned",
    "scenario_hint": "ILP32-32bit-unsigned-time64_no",
    "c_library": "newlib",
}
LP64 = {
    "hardware_model": "LP64",
    "time_t_size_bits": 64,
    "time_t_signed": "signed",
    "scenario_hint": "LP64-64bit-signed-time64_yes",
    "c_library": "glibc",
}
UNKNOWN_WIDTH = {
    "hardware_model": "unknown",
    "time_t_size_bits": 0,
    "time_t_signed": "unknown",
    "scenario_hint": "unknown",
    "c_library": "unknown",
}

ENVIRONMENTS = {
    "ilp32_signed": ILP32_SIGNED,
    "ilp32_unsigned": ILP32_UNSIGNED,
    "lp64": LP64,
    "unknown": UNKNOWN_WIDTH,
    "absent": None,
}


def _candidate() -> Candidate:
    return Candidate(
        file="a.c",
        line=12,
        symbol="now",
        one_line_snippet="time_t now = time(NULL);",
        risk="high",
    )


def _response() -> LLMResponse:
    return LLMResponse(
        id="a.c:12",
        y2038_issue=Y2038Issue.ABSTAIN,
        confidence=0.4,
        reason="needs context",
        needs_more_context=True,
    )


def _function_batch() -> FunctionBatch:
    return FunctionBatch(
        functions=[
            FunctionBody(
                function_id="a.c@measure:10-14",
                file_path="a.c",
                symbol="measure",
                start_line=10,
                end_line=14,
                body="time_t measure(void) {\n    return time(NULL);\n}",
                candidate_lines=[11],
            )
        ],
        batch_id="batch-1",
    )


def _function_client(floor: float, environment=ILP32_SIGNED, detect_y2106: bool = False):
    return FunctionLLMClient(
        llm_type="none",
        model="none",
        environment_config=environment,
        timeout_sec=30,
        batch_size_func=5,
        confidence_floor=floor,
        detect_y2106=detect_y2106,
    )


def _payload(prompt: LLMPromptParts) -> dict:
    """The JSON object a prompt's untrusted channel carries."""
    return json.loads(prompt.user[prompt.user.index("{"):])


def _legacy_prompts(client: LLMClient) -> dict[str, LLMPromptParts]:
    """Every prompt the legacy client builds, keyed by the pass that sends it."""
    candidate = _candidate()
    return {
        "pass1": client._build_prompt([candidate]),
        "pass2": client._build_pass2_prompt([(_response(), candidate, "   12: time_t now = time(NULL);")]),
        "pass3": client._build_pass3_prompt([(_response(), candidate, "int main(void) { return 0; }")]),
    }


# --- The floor the prompt quotes is the floor the run applies -----------------
#
# The floor is validated operational policy, so it belongs to the trusted
# instructions rather than to the analysis data the model is asked to judge.


@pytest.mark.parametrize("floor", [0.5, 0.7, 0.9, 0.95])
def test_function_prompt_quotes_the_configured_floor(floor: float) -> None:
    prompt = _function_client(floor)._build_pass_f1_prompt(_function_batch())

    assert f"{floor:.2f}".rstrip("0").rstrip(".") in prompt.system
    assert "0.85" not in prompt.system


def test_function_prompt_quotes_the_default_floor() -> None:
    prompt = _function_client(DEFAULT_CONFIDENCE_FLOOR)._build_pass_f1_prompt(_function_batch())

    assert str(DEFAULT_CONFIDENCE_FLOOR) in prompt.system


@pytest.mark.parametrize("name", sorted(ENVIRONMENTS))
def test_legacy_prompts_quote_the_configured_floor(name: str) -> None:
    client = LLMClient("none", "none", ENVIRONMENTS[name], confidence_floor=0.7)

    for pass_name, prompt in _legacy_prompts(client).items():
        assert "0.85" not in prompt.system, f"{pass_name} still quotes a hardcoded floor"
        assert "0.85" not in prompt.user, f"{pass_name} still quotes a hardcoded floor"


def test_environment_rules_quote_the_configured_floor() -> None:
    rules = LLMClient("none", "none", ILP32_SIGNED, confidence_floor=0.6)._build_environment_rules()

    assert "0.6" in rules
    assert "0.85" not in rules


def test_function_client_hands_its_floor_to_the_base_client() -> None:
    client = _function_client(0.55)

    assert client.base_client.confidence_floor == 0.55


@pytest.mark.parametrize("function_first", [True, False])
def test_pipeline_hands_its_floor_to_the_client_it_builds(function_first: bool) -> None:
    from tacs.core.pipeline import ScanningPipeline

    pipeline = ScanningPipeline(
        scanner_path=str(SCANNER),
        llm_type="none",
        model="none",
        function_first=function_first,
        confidence_floor=0.65,
    )

    client = pipeline.function_llm_client if function_first else pipeline.llm_client
    assert client.confidence_floor == 0.65


def test_a_yes_above_the_configured_floor_survives_parsing() -> None:
    client = LLMClient("none", "none", ILP32_SIGNED, confidence_floor=0.7)
    item = {"id": "a.c:12", "y2038_issue": "yes", "confidence": 0.8, "reason": "signed 32-bit"}

    parsed = client._parse_single_response(item, [_candidate()], 0)

    assert parsed.y2038_issue == Y2038Issue.YES


def test_a_yes_below_the_configured_floor_becomes_an_abstain() -> None:
    client = LLMClient("none", "none", ILP32_SIGNED, confidence_floor=0.9)
    item = {"id": "a.c:12", "y2038_issue": "yes", "confidence": 0.86, "reason": "signed 32-bit"}

    parsed = client._parse_single_response(item, [_candidate()], 0)

    assert parsed.y2038_issue == Y2038Issue.ABSTAIN


def test_both_clis_default_to_the_shared_floor() -> None:
    from tacs.batch_scan_repos import _build_parser
    from tacs.scan_command import main as scan_cmd

    batch_default = _build_parser().get_default("confidence_floor")
    scan_default = next(
        param.default for param in scan_cmd.params if param.name == "confidence_floor"
    )

    assert batch_default == scan_default == DEFAULT_CONFIDENCE_FLOOR


# --- Examples are static; environment facts do not rewrite them --------------


def _all_example_responses(client: LLMClient) -> list[dict]:
    return [
        example["response"]
        for example in (
            client._get_scenario_examples()
            + client._get_pass2_examples()
            + client._get_pass3_examples()
        )
    ]


@pytest.mark.parametrize("name", sorted(ENVIRONMENTS))
def test_no_example_claims_the_environment_cannot_settle_signedness(name: str) -> None:
    client = LLMClient("none", "none", ENVIRONMENTS[name])

    for response in _all_example_responses(client):
        reason = response["reason"].lower()
        assert "cannot determine if time_t is signed" not in reason
        assert "cannot determine if timespec" not in reason
        assert not ("cannot determine" in reason and "unsigned" in reason), reason


def test_static_examples_still_teach_the_narrowing_case() -> None:
    examples = LLMClient("none", "none", None)._get_scenario_examples()

    narrowing = [e for e in examples if "int32_t" in e["code"]]
    assert narrowing, "the static set must teach narrowing as a Y2038 risk"
    assert all(e["response"]["y2038_issue"] == "yes" for e in narrowing)


def test_static_examples_do_not_claim_a_cast_to_long_is_safe_or_unsafe() -> None:
    """Casting to long depends on ILP32 vs LP64; the example must not pick one."""
    examples = LLMClient("none", "none", None)._get_scenario_examples()

    long_cast = next(e for e in examples if "(long)" in e["code"])
    assert long_cast["response"]["y2038_issue"] == "abstain"
    assert "environment facts" in long_cast["response"]["reason"].lower()


@pytest.mark.parametrize("name", sorted(ENVIRONMENTS))
def test_env_dependent_examples_abstain_rather_than_guess(name: str) -> None:
    """Storing time() / timespec used to be answered from the current config."""
    client = LLMClient("none", "none", ENVIRONMENTS[name])

    for examples in (
        client._get_scenario_examples(),
        client._get_pass2_examples(),
        client._get_pass3_examples(),
    ):
        for example in examples:
            blob = str(example.get("code", "") or example.get("context", "") or example.get("file", ""))
            response = example["response"]
            if "time(NULL)" in blob and "int32_t" not in blob and "< 0" not in blob and "-1" not in blob:
                assert response["y2038_issue"] == "abstain", blob
            if "tv_sec" in blob or "clock_gettime" in blob:
                assert response["y2038_issue"] == "abstain", blob


def test_no_example_set_repeats_itself() -> None:
    codes = [example["code"] for example in LLMClient("none", "none", None)._get_scenario_examples()]
    assert len(codes) == len(set(codes)), "static example set repeats an example"


@pytest.mark.parametrize("name", sorted(ENVIRONMENTS))
def test_example_severity_agrees_with_its_verdict(name: str) -> None:
    for response in _all_example_responses(LLMClient("none", "none", ENVIRONMENTS[name])):
        if response["y2038_issue"] == "yes":
            assert response["severity"] is not None
        else:
            assert response["severity"] is None


def test_example_sets_are_identical_across_environments() -> None:
    baseline = LLMClient("none", "none", None)
    base = (
        baseline._get_scenario_examples(),
        baseline._get_pass2_examples(),
        baseline._get_pass3_examples(),
    )
    for name in ENVIRONMENTS:
        client = LLMClient("none", "none", ENVIRONMENTS[name])
        assert client._get_scenario_examples() == base[0]
        assert client._get_pass2_examples() == base[1]
        assert client._get_pass3_examples() == base[2]


# --- The function-first prompt is well formed ---------------------------------


@pytest.mark.parametrize("detect_y2106", [False, True])
def test_function_prompt_carries_no_doubled_braces(detect_y2106: bool) -> None:
    """The examples sit after the .format() call, so doubling escaped them."""
    client = _function_client(DEFAULT_CONFIDENCE_FLOOR, detect_y2106=detect_y2106)

    prompt = client._build_pass_f1_prompt(_function_batch())

    assert "{{" not in prompt.system
    assert "}}" not in prompt.system


@pytest.mark.parametrize("detect_y2106", [False, True])
def test_function_prompt_examples_are_valid_json(detect_y2106: bool) -> None:
    client = _function_client(DEFAULT_CONFIDENCE_FLOOR, detect_y2106=detect_y2106)

    prompt = client._build_pass_f1_prompt(_function_batch())

    examples = re.findall(r"^Response: (\{.*\})$", prompt.system, flags=re.MULTILINE)
    assert examples, "the prompt should show the model what a response looks like"
    for example in examples:
        parsed = json.loads(example)
        assert "function_id" in parsed
        assert "y2038_summary" in parsed


def test_later_function_passes_are_also_well_formed() -> None:
    client = _function_client(DEFAULT_CONFIDENCE_FLOOR)
    batch = _function_batch()

    for prompt in (
        client._build_pass_f2_prompt(batch, iteration=2),
        client._build_pass_f3_prompt(batch),
    ):
        assert "{{" not in prompt.system
        assert "}}" not in prompt.system


def test_every_pass_shows_the_function_body_as_written(tmp_path: Path) -> None:
    """Stage 9 escaped braces without formatting, doubling every one in the code."""
    source = tmp_path / "measure.c"
    source.write_text(
        "#include <time.h>\n\nstruct holder { time_t at; };\n\n"
        "time_t measure(void) {\n    return time(NULL);\n}\n",
        encoding="utf-8",
    )
    body = "time_t measure(void) {\n    return time(NULL);\n}"
    batch = FunctionBatch(
        functions=[
            FunctionBody(
                function_id="measure.c@measure:5-7",
                file_path=str(source),
                symbol="measure",
                start_line=5,
                end_line=7,
                body=body,
                candidate_lines=[6],
            )
        ],
        batch_id="batch-1",
    )
    client = _function_client(DEFAULT_CONFIDENCE_FLOOR)

    for prompt in (
        client._build_pass_f1_prompt(batch),
        client._build_pass_f2_prompt(batch, iteration=2),
        client._build_pass_f3_prompt(batch),
    ):
        # The body is repository content, so it rides the untrusted channel; JSON
        # encoding is the only thing between the source and the text sent.
        assert _payload(prompt)["functions"][0]["body"] == body
        assert body not in prompt.system

    # Pass F3 also carries the file's leading lines and its type definitions.
    file_context = _payload(client._build_pass_f3_prompt(batch))["functions"][0]["file_context"]
    assert "struct holder { time_t at; };" in file_context["leading_lines"]
