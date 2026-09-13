# Accumulator witness wire format (`VAW1`)

`VAW1` is the canonical byte representation of an `acc_witness`. All integer
fields are little-endian, reserved fields must be zero, and no native pointers,
`size_t` values, padding bytes, or floating-point estimates are serialized.

## Header

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | ASCII magic `VAW1` |
| 4 | 2 | format version (`1`) |
| 6 | 2 | flags (`0`) |
| 8 | 4 | ring degree |
| 12 | 4 | `log2(q)` storage width |
| 16 | 8 | modulus `q` |
| 24 | 4 | VC arity |
| 28 | 4 | logical-coordinate width `kappa` |
| 32 | 4 | inner rank |
| 36 | 4 | outer rank |
| 40 | 4 | tree depth `d` |
| 44 | 4 | intermediate commitment count (`d-1`) |
| 48 | 4 | opening proof count (`d`) |
| 52 | 4 | reserved (`0`) |
| 56 | 8 | total encoded length |

The header is followed by the `d-1` intermediate commitments and then the `d`
LaBRADOR composite proofs. A commitment is encoded as 25 ring elements, each
containing 64 canonical 32-bit coefficients in `[0,q)`.

## Composite proof

A composite proof starts with its 32-bit round count and a zero 32-bit reserved
field. Each round contains:

1. the input multiplicity and tail flag;
2. the ten `comparams` integers;
3. the JL nonce and norm bound;
4. each input rank/decomposition pair;
5. 256 signed 32-bit JL projection entries;
6. the `u1`, `u2`, and lifting ring elements.

The final opening witness contains its multiplicity, zero reserved field,
rank/norm pairs, and signed 16-bit coefficients for every degree-64 polynomial.
The decoder recomputes every final-vector norm and rejects a mismatch.

## Decoder requirements

The decoder rejects unknown versions, parameter mismatches, nonzero reserved
fields, noncanonical field elements, inconsistent LaBRADOR shapes, excessive
allocation dimensions, truncated input, and trailing data. A decoded witness
must still pass `acc_verify`; successful parsing alone never authenticates it.
