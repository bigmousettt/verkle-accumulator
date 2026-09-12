# Verkle accumulator

Experimental implementation of the P2 Verkle-node vector commitment and its
non-interactive LaBRADOR coordinate-opening relation.

The current milestone implements:

- `R_q = Z_q[X]/(X^64 + 1)`, with `q = 2^32 - 99`;
- P2 parameters `(kappa, arity, m, r, n0, n1, mu) =
  (8, 4096, 64, 8, 18, 25, 53)`;
- seed-expanded `A`, `B`, and `E` matrices;
- two-level commitment `u = B * hat(t) + E * randomness`;
- a coordinate-opening relation enforcing 25 outer, 18 inner, and 8
  constant-coefficient equations;
- Fiat-Shamir batching of the 43 full-ring equations into one relation, so
  LaBRADOR receives one full-ring and eight constant-coefficient constraints;
- the upstream composite non-interactive LaBRADOR prover and verifier.

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

Run the full non-interactive proof (substantially slower) with:

```sh
make prove
```

The proof object is currently the upstream in-memory `composite` structure.
Canonical wire serialization and the full accumulator tree are subsequent
milestones.

The build leaves the pinned submodule unchanged. It applies
`patches/labrador-mixed-constraints.patch` to a generated source copy because
the upstream mixed-constraint loops do not advance correctly when full-ring
and constant-coefficient relations appear in the same statement.

## Security status

This is research prototype code, not production cryptography. The parameters
are candidate benchmark parameters and still require concrete MSIS/knMLWE
estimation. The upstream composite protocol is non-interactive through its
Fiat-Shamir transcript, but its final opening is not a zero-knowledge layer.
Do not use this code where witness privacy or production security is required.
