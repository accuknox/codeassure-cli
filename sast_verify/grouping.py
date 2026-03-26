from __future__ import annotations

from dataclasses import dataclass, field

from .schema import Evidence, EvidenceBundle

_CO_LOCATE_WINDOW = 3  # lines; findings within this gap are co-located


@dataclass
class FindingGroup:
    group_key: str                               # "file.py:187"
    bundles: list[EvidenceBundle]                # findings in this group
    original_indices: list[int]                  # maps position-in-group → original findings index
    shared_evidence: list[Evidence]              # deduplicated code windows (for prompt + validation)
    evidence_map: dict[int, list[Evidence]]      # original_index → finding's original evidence
    relationship: str                            # "co-located" | "solo"
    coherence_note: str | None                   # injected into prompt if co-located


def _merge_two(a: Evidence, b: Evidence) -> Evidence:
    """Merge two overlapping or adjacent evidence windows (same path)."""
    new_start = min(a.start_line, b.start_line)
    new_end = max(a.end_line, b.end_line)

    a_lines = a.content.splitlines()
    b_lines = b.content.splitlines()

    # Build line-number → text mapping from both windows
    line_map: dict[int, str] = {}
    for i, line in enumerate(a_lines):
        line_map[a.start_line + i] = line
    for i, line in enumerate(b_lines):
        ln = b.start_line + i
        if ln not in line_map:
            line_map[ln] = line

    merged = [line_map.get(ln, "") for ln in range(new_start, new_end + 1)]
    return Evidence(
        path=a.path,
        start_line=new_start,
        end_line=new_end,
        content="\n".join(merged),
    )


def deduplicate_evidence(bundles: list[EvidenceBundle]) -> list[Evidence]:
    """Merge overlapping/adjacent code windows across all bundles in a group."""
    if not bundles:
        return []

    # Collect all evidence, grouped by path
    by_path: dict[str, list[Evidence]] = {}
    for b in bundles:
        for ev in b.evidence:
            by_path.setdefault(ev.path, []).append(ev)

    result: list[Evidence] = []
    for evs in by_path.values():
        sorted_evs = sorted(evs, key=lambda e: e.start_line)
        merged: list[Evidence] = [sorted_evs[0]]
        for ev in sorted_evs[1:]:
            last = merged[-1]
            # Merge if overlapping or adjacent (within 1 line)
            if ev.start_line <= last.end_line + 1:
                merged[-1] = _merge_two(last, ev)
            else:
                merged.append(ev)
        result.extend(merged)

    return result


def build_evidence_map(
    bundles: list[EvidenceBundle],
    original_indices: list[int],
) -> dict[int, list[Evidence]]:
    """Per-finding evidence windows for post-analysis validation."""
    return {
        original_indices[i]: list(bundle.evidence)
        for i, bundle in enumerate(bundles)
    }


def build_groups(
    bundles: list[EvidenceBundle],
    original_indices: list[int],
) -> list[FindingGroup]:
    """Group by file → cluster by line proximity (within 3 lines).

    Clusters with 2+ findings → co-located group. Singles → solo.
    No same-file mega-grouping in Phase 1.
    """
    if not bundles:
        return []

    # Group by file path
    by_file: dict[str, list[tuple[int, EvidenceBundle]]] = {}
    for orig_idx, bundle in zip(original_indices, bundles):
        by_file.setdefault(bundle.finding.path, []).append((orig_idx, bundle))

    groups: list[FindingGroup] = []

    for path, items in by_file.items():
        # Sort by finding line number
        items_sorted = sorted(items, key=lambda x: x[1].finding.line)

        # Cluster by evidence-window proximity
        clusters: list[list[tuple[int, EvidenceBundle]]] = []
        current: list[tuple[int, EvidenceBundle]] = [items_sorted[0]]

        for item in items_sorted[1:]:
            prev_bundle = current[-1][1]
            curr_bundle = item[1]

            prev_end = max(
                (ev.end_line for ev in prev_bundle.evidence),
                default=prev_bundle.finding.end_line,
            )
            curr_start = min(
                (ev.start_line for ev in curr_bundle.evidence),
                default=curr_bundle.finding.line,
            )

            if curr_start <= prev_end + _CO_LOCATE_WINDOW:
                current.append(item)
            else:
                clusters.append(current)
                current = [item]
        clusters.append(current)

        for cluster in clusters:
            cluster_orig_indices = [x[0] for x in cluster]
            cluster_bundles = [x[1] for x in cluster]

            is_co_located = len(cluster) >= 2
            shared_evidence = deduplicate_evidence(cluster_bundles)
            evidence_map = build_evidence_map(cluster_bundles, cluster_orig_indices)

            min_line = min(b.finding.line for b in cluster_bundles)
            group_key = f"{path}:{min_line}"

            coherence_note: str | None = None
            if is_co_located:
                coherence_note = (
                    f"These {len(cluster)} findings are co-located on the same code region. "
                    "Your reachability and risk assessment must be consistent across all of them."
                )

            groups.append(FindingGroup(
                group_key=group_key,
                bundles=cluster_bundles,
                original_indices=cluster_orig_indices,
                shared_evidence=shared_evidence,
                evidence_map=evidence_map,
                relationship="co-located" if is_co_located else "solo",
                coherence_note=coherence_note,
            ))

    return groups
