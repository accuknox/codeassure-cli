from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field

from .schema import Evidence, EvidenceBundle, Finding

log = logging.getLogger(__name__)

CO_LOCATION_GAP = 3


@dataclass
class FindingGroup:
    """A cluster of related findings to be analyzed together."""

    group_key: str  # e.g. "nessus/nessus.py:187"
    bundles: list[EvidenceBundle]
    original_indices: list[int]  # position-in-group → original findings index
    shared_evidence: list[Evidence]  # deduplicated code windows (for prompt + validation)
    evidence_map: dict[int, list[Evidence]]  # original_index → finding's own evidence
    relationship: str  # "co-located" | "solo"
    coherence_note: str | None = None


def _short_check_id(check_id: str) -> str:
    return check_id.rsplit(".", 1)[-1]


def compute_pattern_stats(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for f in findings:
        counts[_short_check_id(f.check_id)] += 1
    return dict(counts)


def deduplicate_evidence(bundles: list[EvidenceBundle]) -> list[Evidence]:
    all_ev: list[Evidence] = []
    for b in bundles:
        all_ev.extend(b.evidence)

    if not all_ev:
        return []

    by_path: dict[str, list[Evidence]] = defaultdict(list)
    for ev in all_ev:
        by_path[ev.path].append(ev)

    merged: list[Evidence] = []
    for path, evs in by_path.items():
        evs.sort(key=lambda e: e.start_line)
        current = evs[0]
        for ev in evs[1:]:
            if ev.start_line <= current.end_line + CO_LOCATION_GAP:
                if ev.end_line > current.end_line:
                    wider = ev if (ev.end_line - ev.start_line) > (current.end_line - current.start_line) else current
                    current = Evidence(
                        path=path,
                        start_line=current.start_line,
                        end_line=ev.end_line,
                        content=wider.content,
                    )
            else:
                merged.append(current)
                current = ev
        merged.append(current)

    return merged


def build_evidence_map(
    bundles: list[EvidenceBundle],
    original_indices: list[int],
) -> dict[int, list[Evidence]]:
    emap: dict[int, list[Evidence]] = {}
    for idx, bundle in zip(original_indices, bundles):
        emap[idx] = list(bundle.evidence)
    return emap


def _build_coherence_note(bundles: list[EvidenceBundle]) -> str | None:
    if len(bundles) <= 1:
        return None
    checks = [_short_check_id(b.finding.check_id) for b in bundles]
    unique_checks = list(dict.fromkeys(checks))
    check_str = ", ".join(unique_checks)
    path = bundles[0].finding.path
    lines = sorted(set(b.finding.line for b in bundles))
    line_str = str(lines[0]) if len(lines) == 1 else f"{lines[0]}-{lines[-1]}"
    return (
        f"{len(bundles)} findings on the same code at {path}:{line_str} "
        f"({check_str}). "
        "These describe the same code — verdicts must be coherent."
    )


def build_groups(
    bundles: list[EvidenceBundle],
    original_indices: list[int],
) -> list[FindingGroup]:
    by_file: dict[str, list[tuple[int, EvidenceBundle]]] = defaultdict(list)
    for idx, bundle in zip(original_indices, bundles):
        by_file[bundle.finding.path].append((idx, bundle))

    groups: list[FindingGroup] = []

    for path, file_entries in by_file.items():
        file_entries.sort(key=lambda x: x[1].finding.line)

        clusters: list[list[tuple[int, EvidenceBundle]]] = []
        current_cluster: list[tuple[int, EvidenceBundle]] = [file_entries[0]]
        cluster_end = file_entries[0][1].finding.end_line

        for idx, bundle in file_entries[1:]:
            if bundle.finding.line <= cluster_end + CO_LOCATION_GAP:
                current_cluster.append((idx, bundle))
                cluster_end = max(cluster_end, bundle.finding.end_line)
            else:
                clusters.append(current_cluster)
                current_cluster = [(idx, bundle)]
                cluster_end = bundle.finding.end_line
        clusters.append(current_cluster)

        for cluster in clusters:
            c_indices = [idx for idx, _ in cluster]
            c_bundles = [b for _, b in cluster]
            first_line = c_bundles[0].finding.line

            if len(cluster) == 1:
                groups.append(FindingGroup(
                    group_key=f"{path}:{first_line}",
                    bundles=c_bundles,
                    original_indices=c_indices,
                    shared_evidence=list(c_bundles[0].evidence),
                    evidence_map={c_indices[0]: list(c_bundles[0].evidence)},
                    relationship="solo",
                ))
            else:
                groups.append(FindingGroup(
                    group_key=f"{path}:{first_line}",
                    bundles=c_bundles,
                    original_indices=c_indices,
                    shared_evidence=deduplicate_evidence(c_bundles),
                    evidence_map=build_evidence_map(c_bundles, c_indices),
                    relationship="co-located",
                    coherence_note=_build_coherence_note(c_bundles),
                ))

    co_count = sum(1 for g in groups if g.relationship == "co-located")
    solo_count = sum(1 for g in groups if g.relationship == "solo")
    co_findings = sum(len(g.bundles) for g in groups if g.relationship == "co-located")
    log.info(
        "Grouped %d findings into %d groups (co-located=%d covering %d findings, solo=%d)",
        len(bundles), len(groups), co_count, co_findings, solo_count,
    )

    return groups
