# P1/P2/P3 benchmark methodology

The benchmark keeps the accumulator construction unchanged. In particular,
an absent position `x` contains `H_leaf(0, x)`, not a shared empty-leaf value.
Consequently, building the current construction is linear in the universe
size and a dense `N_max = 2^32` build is not presented as an executed result.

## Reproducing the experiment

The three binaries are compiled independently, so every translation unit
(including the VAW1 codec) sees the same profile constants.

```sh
make -s test-profiles
make -s benchmark-profiles > benchmark-results.csv
```

For publication measurements, record the CPU model, compiler name/version,
compiler flags, operating system, and the number of repetitions. Disable
unrelated workloads and run each binary multiple times. The current driver
performs one end-to-end run per invocation; an external harness can compute
the median and dispersion without mixing process state between samples.

## Executed versus projected values

For each profile, the complete executed experiment uses `N_exp = L + 1`.
This is the smallest universe that exercises a two-level tree and therefore
executes three real node commitments (two leaf-parent nodes and the root).
It measures:

- `Acc.Setup` / `VT.Setup`;
- `Acc.Eval` / `VT.Build`;
- membership addition through `Acc.Upd` / `VT.Upd`;
- generation, verification, and canonical VAW1 size of a membership witness;
- deletion through `Acc.Upd` / `VT.Upd`;
- generation, verification, and canonical VAW1 size of a non-membership
  witness.

The columns ending in `_target_projected_bytes` refer to `N_max = 2^32`.
They are path-size projections, not dense-build measurements. The projection
uses

```text
64 + (d - 1) * commitment_bytes + d * mean_composite_proof_bytes
```

where 64 is the VAW1 header, each commitment is exactly 6,400 bytes, and the
mean proof length is computed from the exact canonical sizes of the two real
LaBRADOR proofs in the executed depth-two witness. All levels use the same VC
relation dimensions. The target depths are P1 = 4, P2 = 3, and P3 = 2.

Timing projections are deliberately omitted: proof time can be multiplied by
the path length as a rough model, but it is not an executed end-to-end timing
and may miss cache and parallelism effects.
