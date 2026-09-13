#ifndef VERKLE_ACCUMULATOR_ACCUMULATOR_H
#define VERKLE_ACCUMULATOR_ACCUMULATOR_H

#include <stddef.h>
#include <stdint.h>

#include "verkle_accumulator/tree.h"

enum {
  ACC_NONMEMBERSHIP = 0,
  ACC_MEMBERSHIP = 1
};

typedef va_commitment acc_value;

typedef struct {
  size_t branching_factor;
  vt_public_parameters tree;
} acc_public_parameters;

/* st_Acc = (S, st_VT). S is represented as a membership bitset. */
typedef struct {
  uint8_t *set;
  size_t set_bytes;
  uint64_t set_size;
  vt_state tree;
} acc_state;

/* wit = ((C_{p_t})_{t in [d-1]}, (pi_t)_{t in [d]}). */
typedef struct {
  size_t depth;
  size_t intermediate_count;
  size_t proof_count;
  va_commitment *intermediate_commitments;
  composite *opening_proofs;
} acc_witness;

int acc_setup(acc_public_parameters *pp, uint64_t universe_size,
              const uint8_t setup_seed[VT_SEED_BYTES]);
void acc_public_parameters_clear(acc_public_parameters *pp);

int acc_eval(const acc_public_parameters *pp, const uint64_t *set,
             size_t set_len, const uint8_t build_seed[VT_SEED_BYTES],
             acc_value *acc, acc_state *state);

int acc_upd(const acc_public_parameters *pp, const acc_value *acc,
            acc_state *state, uint64_t x, uint8_t op,
            acc_value *new_acc);

int acc_wit(const acc_public_parameters *pp, const acc_value *acc,
            const acc_state *state, uint64_t x,
            acc_witness *proof_bundle);

int acc_verify(const acc_public_parameters *pp, const acc_value *acc,
               uint64_t x, const acc_witness *proof_bundle, uint8_t type);

int acc_contains(const acc_state *state, uint64_t x);
double acc_witness_estimated_kib(const acc_witness *proof_bundle);
void acc_witness_clear(acc_witness *proof_bundle);
void acc_state_clear(acc_state *state);

#endif
