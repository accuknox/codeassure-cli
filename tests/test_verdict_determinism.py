"""Determinism of majority voting — the winner (and the selected verdict object's
reason/severity) must not depend on the order votes arrive in, which is the
completion order of parallel voting rounds."""

from sast_verify.agents.runner import _majority_verdict
from sast_verify.schema import Verdict


def _v(verdict, conf="medium", reason="", sec=True):
    return Verdict(verdict=verdict, is_security_vulnerability=sec,
                   severity="medium", confidence=conf, reason=reason)


def test_clear_majority_is_order_independent():
    votes = [_v("true_positive"), _v("true_positive"), _v("false_positive")]
    for perm in (votes, list(reversed(votes)), votes[1:] + votes[:1]):
        assert _majority_verdict(perm).verdict == "true_positive"


def test_vote_tie_breaks_deterministically_and_by_priority():
    # 1 vs 1 vote tie, equal confidence weight → fixed priority prefers flagging.
    votes = [_v("false_positive", "high"), _v("true_positive", "high")]
    r1 = _majority_verdict(votes)
    r2 = _majority_verdict(list(reversed(votes)))
    assert r1.verdict == r2.verdict == "true_positive"  # priority TP > FP on a pure tie


def test_selected_object_reason_is_reproducible_on_confidence_tie():
    # same verdict wins; two winners tie on confidence → reason picked by stable key.
    votes = [_v("true_positive", "high", "alpha"), _v("true_positive", "high", "zeta"),
             _v("false_positive", "low", "x")]
    r1 = _majority_verdict(votes)
    r2 = _majority_verdict(list(reversed(votes)))
    assert r1.verdict == r2.verdict == "true_positive"
    assert r1.reason == r2.reason  # deterministic selection, not input-order dependent
