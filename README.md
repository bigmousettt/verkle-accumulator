# Verkle accumulator

Experimental implementation of the P1/P2/P3 Verkle-node vector commitments
and their non-interactive LaBRADOR coordinate-opening relation. P2 remains the
default build profile.

The current milestones implement:

- `R_q = Z_q[X]/(X^64 + 1)`, with `q = 2^32 - 99`;
- compile-time benchmark profiles:

  | profile | `L` | `m` | `r` | `n0` | `n1` | `mu` | depth at `2^32` |
  |---|---:|---:|---:|---:|---:|---:|---:|
  | P1 | 256 | 16 | 2 | 18 | 25 | 53 | 4 |
  | P2 | 4096 | 64 | 8 | 18 | 25 | 53 | 3 |
  | P3 | 65536 | 256 | 32 | 18 | 25 | 53 | 2 |
- seed-expanded `A`, `B`, and `E` matrices;
- two-level commitment `u = B * hat(t) + E * randomness`;
- a coordinate-opening relation enforcing 25 outer, 18 inner, and 8
  constant-coefficient equations;
- Fiat-Shamir batching of the 43 full-ring equations into one relation, so
  LaBRADOR receives one full-ring and eight constant-coefficient constraints;
- the upstream composite non-interactive LaBRADOR prover and verifier.
- the paper's `VT.Setup`, `VT.Build`, and `VT.Upd` algorithms over the P2
  vector commitment;
- deterministic base-4096 paths for the universe `X = [N]`;
- domain-separated `H_leaf` and `H_node` hashes into
  `V = Z_q^8`, using SHAKE128 with rejection sampling;
- bottom-up tree construction and transactional path-only updates;
- the paper state layout `st_VT = (Node, Leaf)`, with cached node messages,
  commitments, and VC prover states.
- the accumulator-layer `Acc.Setup`, `Acc.Eval`, `Acc.Upd`, `Acc.Wit`, and
  `Acc.Verify` algorithms;
- membership and non-membership witnesses containing exactly `d-1`
  intermediate commitments and `d` non-interactive LaBRADOR opening proofs.
- a canonical, versioned accumulator-witness wire format with strict decoding
  bounds and file persistence helpers.

LaBRADOR is pinned as an Apache-2.0 Git submodule under
`third_party/labrador`.

## Requirements

- Linux or WSL2 on x86-64;
- a C compiler with C2x support;
- AVX-512F, AVX-512BW, AVX-512DQ and AVX-512VL;
- `make`.
- `patch` (used to apply a small compatibility fix in the build directory).

```sh
git clone --recurse-submodules https://github.com/bigmousettt/verkle-accumulator
cd verkle-accumulator
make test
```

`tests/test_tree.c` instantiates a depth-two tree, checks leaf and internal-node
openings, adds and deletes elements, confirms that only the affected path is
recommitted, and rejects an illegal repeated addition.

The implementation uses a logically full fixed-depth tree and materializes
only nodes whose subtree intersects `X = [N]`. Coordinates outside `X` use the
public level-dependent values `epsilon_t`. Every in-range empty leaf remains
the position-dependent value `H_leaf(0, x)`; the benchmark does not replace
these values with a common empty leaf. This keeps all paths at exactly
`d = ceil(log_L(N))` levels while avoiding Ethereum's stem/suffix semantics.
The build algorithm remains linear in `N`: constructing a complete tree for
`N = 2^32` is an offline-scale operation, so tests and profiling should use
smaller `N` before adding persistent/out-of-core node storage.

Run the full non-interactive proof (substantially slower) with:

```sh
make prove
```

Run the end-to-end depth-two accumulator test with:

```sh
make test-accumulator
```

This generates and verifies both a membership and a non-membership witness.
It is intentionally separate from `make test` because it invokes four complete
non-interactive LaBRADOR proofs.

The in-memory proof object remains the upstream `composite` structure. The
`acc_witness_encode` and `acc_witness_decode` APIs convert the complete path
witness to and from the portable `VAW1` format; `acc_witness_write_file` and
`acc_witness_read_file` provide persistence. P1/P2/P3 benchmarking is
available through:

```sh
make -s benchmark-profiles > benchmark-results.csv
```

Each profile executes a complete depth-two experiment at `N = L + 1`, covering
setup, build, addition, deletion, and both witness types. It also reports a
separately labelled path-size projection at `N_max = 2^32`, using the exact
canonical byte length of the real proofs produced by that profile. It does not
claim to execute a dense build over `2^32` position-dependent leaves. See
[`docs/benchmarking.md`](docs/benchmarking.md) for the methodology.

For a publication run with ten repetitions plus CPU, compiler, OS, and commit
metadata, use:

```sh
./scripts/run_benchmarks.sh 10
```

The byte-level format is documented in
[`docs/witness-wire-format.md`](docs/witness-wire-format.md).

The build leaves the pinned submodule unchanged. Before applying either patch,
it normalizes the generated copy to LF line endings; this keeps the build
working when a Windows Git configuration checks the submodule out with CRLF
line endings. It applies
`patches/labrador-mixed-constraints.patch` to a generated source copy because
the upstream mixed-constraint loops do not advance correctly when full-ring
and constant-coefficient relations appear in the same statement.
It also applies `patches/labrador-zero-length-vla.patch` to avoid invoking an
upstream conversion helper with a zero-length variable-length array.

## Security status

This is research prototype code, not production cryptography. The parameters
are candidate benchmark parameters and still require concrete MSIS/knMLWE
estimation. The upstream composite protocol is non-interactive through its
Fiat-Shamir transcript, but its final opening is not a zero-knowledge layer.
Do not use this code where witness privacy or production security is required.
