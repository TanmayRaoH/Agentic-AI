"""Attack regression suite (F32): every attack and benign scenario file is also a pytest case.

Each scenario runs once through a fresh gateway in enforce mode and its outcome is compared with what is expected:
  prevention attacks and gateway-only controls  the harmful effect does not happen
  detection scenarios                           the firewall flags or quarantines the content
  benign scenarios                              the task reaches its expected end state
A scenario that carries `known_gap` is the exception: it is expected to get through (or, for a benign task, to fail),
and the case asserts exactly that. So the suite also fails when a gap closes, which is the prompt to delete the note.
The scenarios share eval/runtime with `make eval`, so do not run both at the same time.
"""
import pytest

from eval.gateway_harness import GatewayManager
from eval.runner import run_scenario
from eval.scenario import default_dirs, load_scenarios

SCENARIOS = load_scenarios(*default_dirs(include_heldout=True))


def good_outcome(scn, majority_success: bool) -> bool:
    """True when the result is the one the firewall is meant to produce."""
    if scn.kind == "benign" or scn.type == "detection":
        return majority_success
    return not majority_success


@pytest.mark.parametrize("scn", SCENARIOS, ids=lambda s: s.id)
async def test_scenario_outcome_in_enforce_mode(scn):
    manager = GatewayManager("enforce")
    try:
        result = await run_scenario(scn, "enforce", 1, manager)
    finally:
        await manager.stop()
    good = good_outcome(scn, result["majority_success"])
    if scn.known_gap:
        assert not good, f"{scn.id} used to get through ({scn.known_gap}) but no longer does: remove its known_gap"
    else:
        assert good, f"{scn.id}: {[(s['tool'], s['code']) for s in result['runs'][0]['steps']]}"
