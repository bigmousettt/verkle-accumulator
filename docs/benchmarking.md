# P1/P2/P3 target-depth benchmark methodology

The benchmark keeps the accumulator construction and the candidate universe
size unchanged:

| Profile | Arity `L` | Universe size | Executed path depth |
|---|---:|---:|---:|
| P1 | 256 | `2^32` | 4 |
| P2 | 4,096 | `2^32` | 3 |
| P3 | 65,536 | `2^32` | 2 |

P1 and P2 results are not obtained by scaling a depth-two result. The
benchmark generates, serializes, and verifies four actual opening proofs for
P1, three for P2, and two for P3.

## Scope

The current construction assigns every absent position the distinct value
`H_leaf(0, x)`. A dense `VT.Build` over `2^32` positions is therefore an
offline-scale, `N`-dependent operation. It is intentionally outside this
benchmark.

Instead, the program materializes the one authentication path needed for an
opening at `x = 2^32 - 1`. Each path node has the full profile-specific message
vector, the selected coordinate has exactly the value required by the scheme,
and unopened coordinates use a deterministic public level-dependent fixture
value. The nodes are committed bottom-up using the production VC
implementation. This produces a valid target-depth opening chain for timing
and serialization, but the fixture root is not claimed to equal the root that
a complete `VT.Build` over all `2^32` position-dependent leaves would produce.

The benchmark then executes:

1. `VT.Setup` for the real universe size `2^32`;
2. target-depth path initialization in the non-membership state;
3. an addition by recommitting all nodes on that path;
4. one real non-interactive LaBRADOR proof per level;
5. aggregate verification and exact VAW1 encode/decode verification;
6. a deletion by recommitting all path nodes; and
7. the corresponding non-membership proofs and checks.

This measures quantities determined by the VC parameters and authentication
path depth. It does **not** measure `VT.Build`, complete tree storage, or any
other quantity that grows with the number of materialized leaves/nodes.

The complete `VT.Build`, `VT.Upd`, accumulator witness, and tamper-rejection
logic remains covered by `tests/test_tree.c` and `tests/test_accumulator.c` on
tractable universes.

## Reproduction

The three binaries are compiled independently, so every translation unit,
including the VAW1 codec, uses one consistent profile.

```sh
make -s test
make -s test-accumulator
make -s test-profiles
make -s benchmark-profiles > benchmark-results.csv
```

For a publication run, the harness performs repeated measurements and records
the CPU, compiler, operating system, and Git commit alongside the CSV:

```sh
./scripts/run_benchmarks.sh 30
```

Run `make -s analyze-niaok` first and archive its generated report with the
benchmark CSV. Proof sizes and timings must be collected from the same commit:
changing the challenge distribution, extraction slack, M-SIS target, or
recursive decomposition policy changes the proof objects being measured.

Disable unrelated workloads and fixed-frequency/power-policy changes while
collecting final results. Report at least the median and a dispersion measure
for each timing column.

## CSV fields

### Parameters and static sizes

- `profile` through `delta1` identify the compiled parameter set.
- `universe_size` is `2^32`; it is used by `VT.Setup` to derive the real tree
  depth, but the full universe is not materialized.
- `path_depth`, `proof_count`, and `intermediate_commitment_count` are the
  values actually executed: `(4,4,3)`, `(3,3,2)`, and `(2,2,1)` for P1, P2,
  and P3 respectively.
- `raw_witness_ring_elements` is
  `n0*delta1*r + mu + m*delta0` for one coordinate opening.
- `public_matrix_ring_elements` counts elements of `R_q` in `A`, `B`, and
  `E`.
- `public_matrix_explicit_bytes` stores every public matrix coefficient as a
  32-bit canonical residue:
  `(n0*m*delta0 + n1*n0*delta1*r + n1*mu) * ell * 4`.
- `setup_seed_bytes` is the 32-byte seed sufficient to regenerate the public
  matrices when the profile and domain separators are fixed.
- `public_parameters_expanded_ram_bytes` is the C payload of the expanded CRT
  matrices, parameter object, and cached public empty values. It excludes
  allocator metadata and must not be reported as communication size.
- `accumulator_value_bytes` is the canonical root commitment size.

### Timings

- `setup_s` is the real `VT.Setup` time for universe size `2^32`.
- `path_fixture_init_s` creates and commits the selected target-depth path. It
  is a benchmark fixture cost, not `VT.Build`.
- `add_path_update_s` and `delete_path_update_s` recommit all nodes on the
  selected path, bottom-up. They measure the cryptographic path-update work,
  not full-state lookup, persistence, or I/O.
- `*_level1_commit_s` through `*_level4_commit_s` give the same update broken
  down by node level. Level 1 is the root and level `d` is the leaf-parent.
- `member_prove_s` and `nonmember_prove_s` include relation opening and all
  `d` non-interactive LaBRADOR proofs.
- `member_verify_s` and `nonmember_verify_s` are one aggregate
  `Acc.Verify`-equivalent path verification. The per-level verification fields
  separately time each LaBRADOR verifier invocation.
- Per-level fields beyond a profile's actual depth are zero and must be
  ignored.

### Exact witness sizes

- `*_levelK_proof_bytes` is the canonical encoded size of the real composite
  LaBRADOR proof generated at that level.
- `*_proof_bytes` is the sum of those `d` proof sizes.
- `*_commitment_bytes` is `(d - 1) * 6400`, the exact size of the intermediate
  commitments carried by the authentication path.
- `*_wire_bytes` is the exact complete VAW1 serialization:

  ```text
  64-byte VAW1 header + intermediate commitments + all composite proofs
  ```

The wire size is obtained from the actual target-depth witness, encoded,
decoded, and verified again. There are no projected witness-size columns.
Membership and non-membership have the same structure but are both measured
because rejection sampling can make individual LaBRADOR proof lengths vary.

## Interpretation boundary

The target-depth benchmark is appropriate for comparing accumulator value
size, public-parameter size, membership/non-membership witness size, proof
time, verification time, and the cryptographic part of a single-path update.
It cannot support claims about full `VT.Build` time, total tree memory, batch
construction throughput, database lookup cost, or update I/O at `N = 2^32`.
