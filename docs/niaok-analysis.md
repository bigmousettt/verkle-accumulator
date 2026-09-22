# Non-interactive LaBRADOR analysis: stage one

## Scope

This stage analyzes one Fiat--Shamir LaBRADOR proof of the coordinate-opening
relation. It covers the relation norm, Johnson--Lindenstrauss relaxation,
challenge distribution, recursive commitment openings, and every internal
M-SIS estimate produced by the concrete proof trace.

It deliberately excludes:

- binding of the two-level vector commitment itself;
- knMLWE hiding of the outer commitment;
- zero knowledge; and
- composition of several coordinate-opening proofs along a Verkle path.

Those are separate application-level arguments and must not be inferred from
the output of this stage.

## Reproduction

```sh
make -s analyze-niaok
```

The target first generates and verifies one deterministic real proof for each
of P1, P2, and P3. It then writes:

| File | Meaning |
|---|---|
| `report.md` | Human-readable checks, recursive bounds, and open conditions |
| `summary.csv` | One row per profile |
| `layers.csv` | One row per concrete recursive proof layer |
| `trace-P*.json` | Machine-readable dimensions and norms read from the proof object |
| `raw-P*.log` | Complete prover output retained for audit |

The trace binary rejects the run unless relation verification, proof
generation, and proof verification all succeed. Thus the analysis is tied to
the parameters that the executable actually used rather than to a separately
maintained parameter table.

## Concrete proof-system parameters

The generated LaBRADOR build copy uses the degree-64, two-splitting candidate
from *Aggregating Falcon Signatures with LaBRADOR*:

| Parameter | Value |
|---|---:|
| Ring degree | 64 |
| Challenge support weight `w` | 43 |
| Maximum magnitude `gamma` | 2 |
| Squared-norm rejection bound `T2` | 86 |
| Operator-norm rejection bound `T_op` | 43 |
| JL constants `(C1,C2)` | `(120,30)` |
| JL rows | `2 lambda = 256` |
| Extraction slack used in code | 2.066 |

For `lambda=128`, the required JL slack is
`sqrt(lambda/C2) = 2.065591...`, so the implementation value rounds upward.
The code also applies the relaxed-opening factors from the Aggregate Falcon
analysis: an inner extracted opening is bounded using

```text
8 * T_op * (1 + B + ... + B^(f-1)) * sigma * beta'
```

and an outer opening by `2 * sigma * beta'`. Here `B` is the decomposition
base, `f` is the number of decomposition parts, and `beta'` is read from the
actual recursive layer.

## Estimator interpretation

The Python Core-SVP calculation is a direct transcription of the model in the
Aggregate Falcon supplementary `SIS_hardness.sage` script. Its output is a
concrete attack-cost estimate, not a mathematical proof of M-SIS hardness.

The report also includes a clearly labeled diagnostic knowledge-error value.
It follows the reference analysis's `Q=0` convention. For the rejection-
sampled challenge set, the script first counts the exact set surviving the
squared-norm filter. It then applies a Rademacher--Hoeffding bound to the
independent coefficient signs and a union bound over the 32 complex
embeddings. This gives a conservative lower bound on the operator-filter
acceptance fraction and therefore on the accepted-set cardinality. The
diagnostic then *models* the two-splitting well-spreadness parameter as
`B = 1/|C|`, matching the value obtained when every relevant fiber contains
at most one challenge. Cardinality alone does not prove this fiber condition,
so the reported knowledge-error value is intentionally not a final
theorem-backed bound.

## Publication boundary

The following statements are currently supported:

- the P1/P2/P3 relation dimensions and norms are obtained from verified real
  proofs;
- all three relations satisfy the configured JL admissibility inequality;
- every recursive M-SIS instance and its estimator input is exported;
- the post-rejection challenge set has a conservative cardinality lower
  bound, and the report exposes the additional well-spreadness assumption
  used by its diagnostic; and
- the executable challenge and extraction constants match the analyzed
  degree-64 candidate.

Do not yet state that the complete accumulator has 128-bit security. For the
proof system, the well-spreadness condition must be proved for the exact
rejection-sampled challenge set, the chosen random-oracle query budget must be
stated, and the additive loss across recursive layers means nominal 128-bit
component targets do not automatically yield 128 effective bits. VC binding
and hiding are intentionally deferred to the next stage.

## References

- [Aggregating Falcon Signatures with LaBRADOR](https://eprint.iacr.org/2024/311)
- [Aggregate Falcon supplementary scripts](https://github.com/dfaranha/aggregate-falcon)
