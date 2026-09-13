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

For a publication run, the bundled harness performs ten independent
repetitions by default and records the CPU, compiler, operating system, and Git
commit next to the CSV:

```sh
./scripts/run_benchmarks.sh 10
```

Disable unrelated workloads while collecting the final results. Report at
least the median and a dispersion measure for every timing column.

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

## Size conventions

The CSV exposes the following distinct size measures so that comparisons do
not mix serialization and implementation memory:

- `public_matrix_ring_elements` is the number of elements of `R_q` in
  `A`, `B`, and `E`;
- `public_matrix_explicit_bytes` stores every matrix coefficient as one
  32-bit canonical residue, namely
  `(n0*m*delta0 + n1*n0*delta1*r + n1*mu) * ell * 4`;
- `setup_seed_bytes` is 32 bytes. Given the agreed profile and hash domains,
  this is sufficient for `VT.Setup` to regenerate all three matrices;
- `public_parameters_expanded_ram_bytes` is the actual C payload for the
  expanded CRT matrices, the public-parameter object, and cached empty values.
  It excludes allocator metadata;
- `accumulator_value_bytes` is the canonical root commitment size;
- `experiment_state_payload_bytes` counts the allocated C payload of the
  fully materialized state at `N_exp`, excluding allocator metadata;
- `member_wire_bytes` and `nonmember_wire_bytes` are exact complete VAW1
  serializations, not LaBRADOR's floating-point estimates.

For public-parameter comparisons, report both the explicit-matrix and seeded
figures and state which convention the compared scheme uses. The expanded RAM
figure is an implementation-memory measurement and must not be presented as
communication size.

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
