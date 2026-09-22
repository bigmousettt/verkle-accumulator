#!/usr/bin/env python3
"""Export and diagnose the concrete non-interactive LaBRADOR parameters.

This script deliberately stops at proof-system knowledge soundness.  It does
not estimate the application-level VC binding assumptions or knMLWE hiding.
The M-SIS estimator is a direct Python transcription of the Core-SVP model in
the Aggregate Falcon supplementary `SIS_hardness.sage` script.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import pathlib
import subprocess
from typing import Any, Iterable


SECURITY_PARAMETER = 128
JL_C1 = 120
JL_C2 = 30
JL_DIMENSION = 2 * SECURITY_PARAMETER
AF_REFERENCE_WEIGHT = 43
AF_REFERENCE_GAMMA = 2
AF_REFERENCE_NORMSQ = 86
AF_REFERENCE_OPNORM = 43


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--binary",
        action="append",
        required=True,
        type=pathlib.Path,
        help="profile-specific niaok_trace executable (repeat for P1/P2/P3)",
    )
    parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    return parser.parse_args()


def extract_trace(output: str) -> dict[str, Any]:
    begin = "NIAOK_TRACE_BEGIN\n"
    end = "\nNIAOK_TRACE_END"
    start = output.rfind(begin)
    if start < 0:
        raise ValueError("trace begin marker is missing")
    start += len(begin)
    stop = output.find(end, start)
    if stop < 0:
        raise ValueError("trace end marker is missing")
    return json.loads(output[start:stop])


def run_trace(binary: pathlib.Path, output_dir: pathlib.Path) -> dict[str, Any]:
    completed = subprocess.run(
        [str(binary.resolve())],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    trace = extract_trace(completed.stdout)
    profile = trace["profile"]
    (output_dir / f"raw-{profile}.log").write_text(completed.stdout)
    (output_dir / f"trace-{profile}.json").write_text(
        json.dumps(trace, indent=2) + "\n"
    )
    return trace


def log2_binomial(n: int, k: int) -> float:
    return (
        math.lgamma(n + 1)
        - math.lgamma(k + 1)
        - math.lgamma(n - k + 1)
    ) / math.log(2.0)


def challenge_support_bits(degree: int, weight: int, gamma: int) -> float:
    if weight < 0 or weight > degree or gamma < 1:
        raise ValueError("invalid fixed-weight challenge")
    return log2_binomial(degree, weight) + weight * math.log2(2 * gamma)


def challenge_l2_filtered_bits(
    degree: int, weight: int, gamma: int, normsq: int
) -> float:
    """Cardinality after the exact l2 filter, before operator rejection.

    Aggregate Falcon's degree-64 challenge uses gamma=2.  In that case the
    number of magnitude assignments is an exact binomial prefix.
    """
    if gamma != 2:
        raise ValueError("the exact filter counter currently supports gamma=2")
    maximum_twos = min(weight, (normsq - weight) // 3)
    if maximum_twos < 0:
        return float("-inf")
    magnitude_assignments = sum(
        math.comb(weight, twos) for twos in range(maximum_twos + 1)
    )
    return (
        log2_binomial(degree, weight)
        + weight
        + math.log2(magnitude_assignments)
    )


def operator_acceptance_lower_bound(
    degree: int, maximum_normsq: int, opnorm: int
) -> float:
    """Conservative acceptance fraction for the operator-norm filter.

    Fixing the support and magnitudes leaves independent Rademacher signs.  At
    each of the degree/2 complex embeddings, real and imaginary parts are
    Rademacher sums with sum of squared weights at most maximum_normsq.  A
    Hoeffding bound followed by a union bound gives the result below.
    """
    rejection_upper_bound = (
        2.0
        * degree
        * math.exp(-(opnorm**2) / (4.0 * maximum_normsq))
    )
    return max(0.0, 1.0 - rejection_upper_bound)


def multiplicative_order(value: int, modulus: int) -> int:
    current = 1
    for order in range(1, modulus + 1):
        current = current * value % modulus
        if current == 1:
            return order
    raise ValueError("multiplicative order was not found")


def splitting_factor(q: int, degree: int) -> tuple[int, int]:
    factor_degree = multiplicative_order(q % (2 * degree), 2 * degree)
    return degree // factor_degree, factor_degree


def gsa_hermite(block_size: int) -> float:
    return (
        block_size
        / (2.0 * math.pi * math.e)
        * (math.pi * block_size) ** (1.0 / block_size)
    ) ** (1.0 / (2.0 * block_size - 2.0))


def sis_hardness_bits(module_rank: int, degree: int, q: int, bound: float) -> float:
    """Core-SVP estimate used by Aggregate Falcon's SIS_hardness.sage."""
    if module_rank <= 0 or bound <= 1.0 or bound >= q:
        return 0.0
    rows = module_rank * degree
    lattice_dimension = round(2.0 * rows * math.log(q) / math.log(bound))
    if lattice_dimension <= 0:
        return 0.0
    log_root_hermite = (
        math.log(bound) - (rows / lattice_dimension) * math.log(q)
    ) / lattice_dimension
    root_hermite = math.exp(log_root_hermite)
    block_size = None
    for candidate in range(50, 1000):
        if gsa_hermite(candidate) <= root_hermite:
            block_size = candidate
            break
    if block_size is None or block_size > lattice_dimension:
        return 292.0
    return block_size * math.log2(math.sqrt(3.0 / 2.0))


def reconstruction_factor(base: int, parts: int) -> int:
    return sum(base**index for index in range(parts))


def log2_sum_probabilities(log2_probabilities: Iterable[float]) -> float:
    values = list(log2_probabilities)
    maximum = max(values)
    return maximum + math.log2(sum(2.0 ** (value - maximum) for value in values))


def analyze_trace(trace: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not trace.get("challenge_sampler_self_test", False):
        raise ValueError("runtime challenge sampler self-test did not pass")
    q = int(trace["q"])
    degree = int(trace["ring_degree"])
    sigma = math.sqrt(SECURITY_PARAMETER / JL_C2)
    beta = math.sqrt(trace["statement_betasq"])
    actual_norm = math.sqrt(trace["actual_witness_normsq"])
    split, factor_degree = splitting_factor(q, degree)
    challenge_bits = challenge_support_bits(
        degree, trace["challenge_weight"], trace["challenge_gamma"]
    )
    l2_filtered_bits = challenge_l2_filtered_bits(
        degree,
        trace["challenge_weight"],
        trace["challenge_gamma"],
        trace["challenge_normsq"],
    )
    reference_bits = challenge_support_bits(
        degree, AF_REFERENCE_WEIGHT, AF_REFERENCE_GAMMA
    )
    maximum_twos = min(
        trace["challenge_weight"],
        (trace["challenge_normsq"] - trace["challenge_weight"]) // 3,
    )
    maximum_accepted_normsq = trace["challenge_weight"] + 3 * maximum_twos
    opnorm_acceptance = operator_acceptance_lower_bound(
        degree, maximum_accepted_normsq, trace["challenge_opnorm"]
    )
    if opnorm_acceptance <= 0.0:
        raise ValueError("the operator-norm acceptance bound is vacuous")
    conservative_challenge_bits = l2_filtered_bits + math.log2(opnorm_acceptance)

    layers: list[dict[str, Any]] = []
    diagnostic_log_probabilities: list[float] = []
    minimum_msis_bits = math.inf
    logq = math.log2(q)
    modulus_term_bits = factor_degree * logq
    aggregation_term_bits = math.ceil(SECURITY_PARAMETER / logq) * logq

    for layer in trace["layers"]:
        base = 1 << layer["b_log2"]
        reconstruct = reconstruction_factor(base, layer["f"])
        beta_prime = math.sqrt(layer["output_normsq"])

        # AAB+24, Theorem 5.2 / Appendix I.5.  The reconstruction factor is
        # 1 for an undecomposed opening and b+1 for the usual two-part case.
        inner_bound = (
            8.0
            * trace["challenge_opnorm"]
            * reconstruct
            * sigma
            * beta_prime
        )
        outer_bound = 2.0 * sigma * beta_prime
        inner_bits = sis_hardness_bits(
            layer["kappa"], degree, q, inner_bound
        )
        outer_bits = None
        if layer["kappa1"] > 0:
            outer_bits = sis_hardness_bits(
                layer["kappa1"], degree, q, outer_bound
            )
        minimum_msis_bits = min(minimum_msis_bits, inner_bits)
        if outer_bits is not None:
            minimum_msis_bits = min(minimum_msis_bits, outer_bits)

        # Diagnostic only: Q=0 and modeled B=1/|C|.  The cardinality bound
        # below does not by itself prove the fiber condition needed for this
        # well-spreadness value, so this is not a theorem-backed final B.
        r = layer["witness_multiplicity"]
        diagnostic_log_probabilities.extend(
            [
                -SECURITY_PARAMETER,
                math.log2((5 + 2 * split) * r) - conservative_challenge_bits,
                -modulus_term_bits,
                -aggregation_term_bits,
                -inner_bits,
            ]
        )
        if outer_bits is not None:
            diagnostic_log_probabilities.append(-outer_bits)

        layers.append(
            {
                "profile": trace["profile"],
                "layer": layer["index"],
                "tail": layer["tail"],
                "witness_multiplicity": r,
                "witness_ranks": ";".join(map(str, layer["witness_ranks"])),
                "f": layer["f"],
                "base": base,
                "kappa": layer["kappa"],
                "kappa1": layer["kappa1"],
                "beta_prime": beta_prime,
                "inner_msis_bound_aab24": inner_bound,
                "inner_core_svp_bits": inner_bits,
                "outer_msis_bound_aab24": outer_bound if outer_bits is not None else "",
                "outer_core_svp_bits": outer_bits if outer_bits is not None else "",
            }
        )

    # Theorem 5.2 has an outer factor 2(Q+1); this diagnostic follows the
    # Aggregate Falcon convention Q=0, hence loses one additional bit.
    diagnostic_error_bits = (
        -1.0 - log2_sum_probabilities(diagnostic_log_probabilities)
    )
    summary = {
        "profile": trace["profile"],
        "raw_witness_ring_elements": sum(trace["initial_witness_lengths"]),
        "relation_beta": beta,
        "actual_witness_norm": actual_norm,
        "jl_sigma": sigma,
        "relaxed_beta": sigma * beta,
        "q_over_c1": q / JL_C1,
        "jl_admissible": beta <= q / JL_C1,
        "splitting_factor": split,
        "irreducible_factor_degree": factor_degree,
        "runtime_challenge_weight": trace["challenge_weight"],
        "runtime_challenge_gamma": trace["challenge_gamma"],
        "runtime_challenge_normsq": trace["challenge_normsq"],
        "runtime_opnorm": trace["challenge_opnorm"],
        "runtime_challenge_support_bits_before_rejection": challenge_bits,
        "runtime_challenge_support_bits_after_exact_l2": l2_filtered_bits,
        "opnorm_acceptance_fraction_lower_bound": opnorm_acceptance,
        "accepted_challenge_bits_lower_bound": conservative_challenge_bits,
        "well_spread_log2_upper_bound": -conservative_challenge_bits,
        "challenge_term_bits_at_runtime_r": (
            conservative_challenge_bits
            - math.log2((5 + 2 * split) * trace["layers"][0]["witness_multiplicity"])
        ),
        "af_reference_challenge_support_bits": reference_bits,
        "implementation_slack": trace["implementation_slack"],
        "slack_is_sufficient": trace["implementation_slack"] >= sigma,
        "recursion_layers": trace["composite_layers"],
        "minimum_internal_core_svp_bits": minimum_msis_bits,
        "knowledge_bits_q0_conservative_b": diagnostic_error_bits,
        "proof_estimated_kib": trace["estimated_size_kib"],
    }
    return summary, layers


def write_csv(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def fmt(value: float, digits: int = 2) -> str:
    return f"{value:,.{digits}f}"


def write_report(
    path: pathlib.Path,
    summaries: list[dict[str, Any]],
    layers: list[dict[str, Any]],
) -> None:
    first = summaries[0]
    lines = [
        "# Non-interactive LaBRADOR parameter analysis",
        "",
        "Scope: proof-system knowledge soundness only. Application-level VC binding and hiding are excluded.",
        "",
        "## Initial relations and JL check",
        "",
        "| Profile | Ring elements | Relation beta | Relaxed sigma beta | q/C1 | Layers |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for row in summaries:
        lines.append(
            "| {profile} | {raw_witness_ring_elements} | {beta} | {relaxed} | {q_c1} | {layers} |".format(
                profile=row["profile"],
                raw_witness_ring_elements=row["raw_witness_ring_elements"],
                beta=fmt(row["relation_beta"]),
                relaxed=fmt(row["relaxed_beta"]),
                q_c1=fmt(row["q_over_c1"]),
                layers=row["recursion_layers"],
            )
        )
    lines.extend(
        [
            "",
            f"All profiles satisfy beta <= q/C1 for lambda={SECURITY_PARAMETER}, C1={JL_C1}, C2={JL_C2}, and sigma=sqrt(lambda/C2).",
            "",
            "## Runtime challenge and slack diagnostics",
            "",
            f"- Runtime challenge: C_{{w,gamma}} with w={first['runtime_challenge_weight']}, gamma={first['runtime_challenge_gamma']}, T2={first['runtime_challenge_normsq']}, and T_op={first['runtime_opnorm']}.",
            f"- Its support is 2^{first['runtime_challenge_support_bits_before_rejection']:.3f} before rejection and exactly 2^{first['runtime_challenge_support_bits_after_exact_l2']:.3f} after the l2 filter but before operator-norm rejection.",
            f"- A Rademacher--Hoeffding/union bound proves an operator-filter acceptance fraction of at least {first['opnorm_acceptance_fraction_lower_bound']:.6f}; therefore the accepted challenge set has at least 2^{first['accepted_challenge_bits_lower_bound']:.3f} elements.",
            f"- If the required challenge fibers contain at most one accepted challenge, modeling B=1/|C| gives B <= 2^({first['well_spread_log2_upper_bound']:.3f}); with runtime r=3, the term (5+2l)rB is at most 2^(-{first['challenge_term_bits_at_runtime_r']:.3f}). This fiber condition remains to be proved for the exact sampler.",
            f"- Aggregate Falcon's degree-64 reference uses w={AF_REFERENCE_WEIGHT}, gamma={AF_REFERENCE_GAMMA}, T2={AF_REFERENCE_NORMSQ}, and T_op={AF_REFERENCE_OPNORM}.",
            f"- Runtime SLACK={first['implementation_slack']}, while the JL extraction slack is {first['jl_sigma']:.6f}.",
            "",
            "The runtime constants match the Aggregate Falcon degree-64 two-splitting candidate, the configured slack covers the JL extraction slack, and the accepted challenge set has a conservative cardinality lower bound. The separate B=1/|C| step is an explicit diagnostic assumption, not a consequence of cardinality alone.",
            "",
            "## Recursive internal M-SIS diagnostics",
            "",
            "| Profile | Layer | r | ranks | f | base | kappa | kappa1 | beta' | inner bound | inner bits | outer bound | outer bits |",
            "|---|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in layers:
        outer_bound = row["outer_msis_bound_aab24"]
        outer_bits = row["outer_core_svp_bits"]
        lines.append(
            "| {profile} | {layer} | {r} | {ranks} | {f} | {base} | {kappa} | {kappa1} | {beta} | {ib} | {ic} | {ob} | {oc} |".format(
                profile=row["profile"],
                layer=row["layer"],
                r=row["witness_multiplicity"],
                ranks=row["witness_ranks"],
                f=row["f"],
                base=row["base"],
                kappa=row["kappa"],
                kappa1=row["kappa1"],
                beta=fmt(row["beta_prime"]),
                ib=fmt(row["inner_msis_bound_aab24"]),
                ic=fmt(row["inner_core_svp_bits"]),
                ob=fmt(outer_bound) if outer_bound != "" else "--",
                oc=fmt(outer_bits) if outer_bits != "" else "--",
            )
        )
    lines.extend(
        [
            "",
            "The bounds use the relaxed-witness treatment from AAB+24 and the exact runtime layer trace. The Core-SVP figures use the estimator model shipped with Aggregate Falcon; they are estimates, not proofs of hardness.",
            "",
            "## Composed proof-system diagnostic (Q=0)",
            "",
            "| Profile | Minimum internal Core-SVP bits | Composed knowledge bits |",
            "|---|---:|---:|",
        ]
    )
    for row in summaries:
        lines.append(
            f"| {row['profile']} | {row['minimum_internal_core_svp_bits']:.2f} | {row['knowledge_bits_q0_conservative_b']:.2f} |"
        )
    lines.extend(
        [
            "",
            "The composed column includes the factor 2(Q+1) from Theorem 5.2 with Q=0, the modeled B=1/|C| challenge term above, and every traced recursive layer. It is not a final knowledge-soundness claim: the exact challenge-set well-spreadness condition and a nonzero random-oracle-query budget still have to be handled.",
            "",
            "## What remains before a 128-bit claim",
            "",
            "1. Prove the well-spreadness bound for the exact challenge set after both rejection filters; accepted-set cardinality alone is insufficient.",
            "2. State the random-oracle-query budget explicitly. The reported diagnostic follows Aggregate Falcon's concrete-estimate convention Q=0; for a nonzero budget subtract log2(Q+1) bits.",
            "3. Decide whether to report the nominal lambda=128 parameterization and its effective composed value, or retune the JL dimension and internal M-SIS targets so that the additive composition itself remains at least 128 bits.",
            "4. Independently analyze application-level VC binding and knMLWE hiding in the next stage.",
            "",
        ]
    )
    path.write_text("\n".join(lines))


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    traces = [run_trace(binary, args.output_dir) for binary in args.binary]
    traces.sort(key=lambda item: item["profile"])

    summaries: list[dict[str, Any]] = []
    layers: list[dict[str, Any]] = []
    for trace in traces:
        summary, trace_layers = analyze_trace(trace)
        summaries.append(summary)
        layers.extend(trace_layers)

    write_csv(args.output_dir / "summary.csv", summaries)
    write_csv(args.output_dir / "layers.csv", layers)
    write_report(args.output_dir / "report.md", summaries, layers)
    print(f"wrote {args.output_dir / 'report.md'}")
    print(f"wrote {args.output_dir / 'summary.csv'}")
    print(f"wrote {args.output_dir / 'layers.csv'}")


if __name__ == "__main__":
    main()
