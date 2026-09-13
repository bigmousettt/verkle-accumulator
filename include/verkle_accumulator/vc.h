#ifndef VERKLE_ACCUMULATOR_VC_H
#define VERKLE_ACCUMULATOR_VC_H

#include <stddef.h>
#include <stdint.h>

#include "chihuahua.h"
#include "pack.h"

/* VA_ARITY is not named L because LaBRADOR uses L for its CRT limbs. */
enum {
  VA_RING_DEGREE = N,
  VA_KAPPA = 8,
  VA_ARITY = 4096,
  VA_BLOCKS = 8,
  VA_INNER_WIDTH = 64,
  VA_INNER_RANK = 18,
  VA_OUTER_RANK = 25,
  VA_RANDOMNESS_LEN = 53,
  VA_INNER_BASE_LOG = 4,
  VA_INNER_DIGITS = 8,
  VA_OUTER_BASE_LOG = 7,
  VA_OUTER_DIGITS = 5,
  VA_S_BLOCK_LEN = VA_INNER_WIDTH * VA_INNER_DIGITS,
  VA_HAT_T_LEN = VA_BLOCKS * VA_INNER_RANK * VA_OUTER_DIGITS,
  VA_RAW_CONSTRAINTS = VA_OUTER_RANK + VA_INNER_RANK + VA_KAPPA,
  VA_CONSTRAINTS = 1 + VA_KAPPA
};

#define VA_Q UINT64_C(4294967197)
#define VA_MESSAGE_SCALARS ((size_t)VA_ARITY * VA_KAPPA)
#define VA_COMMITMENT_BYTES \
  ((size_t)VA_OUTER_RANK * VA_RING_DEGREE * QBYTES)

typedef struct {
  uint8_t a_seed[16];
  uint8_t b_seed[16];
  uint8_t e_seed[16];
  polx *a;
  polx *b;
  polx *e;
} va_context;

typedef struct { polx u[VA_OUTER_RANK]; } va_commitment;

typedef struct {
  poly *s;
  poly *hat_t;
  poly *randomness;
} va_prover_state;

typedef struct {
  uint32_t value[VA_KAPPA];
  prncplstmnt statement;
  witness witness;
} va_opening_relation;

void va_default_seeds(uint8_t a[16], uint8_t b[16], uint8_t e[16]);
int va_context_init(va_context *ctx, const uint8_t a[16],
                    const uint8_t b[16], const uint8_t e[16]);
void va_context_clear(va_context *ctx);
int va_commit(const va_context *ctx, const uint32_t message[VA_MESSAGE_SCALARS],
              const uint8_t randomness_seed[16], va_commitment *vc_commitment,
              va_prover_state *state);
void va_prover_state_clear(va_prover_state *state);
int va_statement_init(prncplstmnt *principal, const va_context *ctx,
                      const va_commitment *vc_commitment, size_t coordinate,
                      const uint32_t value[VA_KAPPA]);
int va_open(va_opening_relation *opening, const va_context *ctx,
            const va_commitment *vc_commitment, const va_prover_state *state,
            const uint32_t message[VA_MESSAGE_SCALARS], size_t coordinate);
void va_opening_relation_clear(va_opening_relation *opening);
int va_relation_verify(const va_opening_relation *opening);
int va_prove(composite *composite_proof, const va_opening_relation *opening);
int va_verify(const composite *composite_proof, const prncplstmnt *principal);
void va_commitment_encode(uint8_t out[VA_COMMITMENT_BYTES],
                          const va_commitment *vc_commitment);
int va_commitment_decode(va_commitment *vc_commitment,
                         const uint8_t in[VA_COMMITMENT_BYTES]);
int va_commitment_equal(const va_commitment *left,
                        const va_commitment *right);

#endif
