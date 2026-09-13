#ifndef VERKLE_ACCUMULATOR_TREE_H
#define VERKLE_ACCUMULATOR_TREE_H

#include <stddef.h>
#include <stdint.h>

#include "verkle_accumulator/vc.h"

enum {
  VT_SEED_BYTES = 32,
  VT_ADD = 1,
  VT_DELETE = 0
};

typedef enum {
  VT_OK = 0,
  VT_ERR_ARGUMENT = 1,
  VT_ERR_RANGE = 2,
  VT_ERR_MEMORY = 3,
  VT_ERR_DUPLICATE = 4,
  VT_ERR_ILLEGAL_UPDATE = 5,
  VT_ERR_VC = 6,
  VT_ERR_OVERFLOW = 7
} vt_result;

typedef struct { uint32_t scalar[VA_KAPPA]; } vt_value;

/* Leaf[alpha] = (mu_alpha, x_alpha, v_alpha). */
typedef struct {
  uint8_t membership;
  uint64_t x;
  vt_value value;
} vt_leaf;

/* Node[p] = (v_p, C_p, st_p). */
typedef struct {
  uint32_t *values;
  va_commitment commitment;
  va_prover_state vc_state;
} vt_node;

typedef struct {
  uint64_t universe_size;
  size_t depth;
  uint8_t setup_seed[VT_SEED_BYTES];
  vt_value *empty_values;
  va_context vc;
} vt_public_parameters;

/* st_VT = (Node, Leaf), with Node stored by tree depth. */
typedef struct {
  uint64_t universe_size;
  size_t depth;
  uint64_t epoch;
  uint8_t build_seed[VT_SEED_BYTES];
  vt_leaf *leaves;
  size_t *node_counts;
  vt_node **nodes;
} vt_state;

int vt_setup(vt_public_parameters *pp, uint64_t universe_size,
             const uint8_t setup_seed[VT_SEED_BYTES]);
void vt_public_parameters_clear(vt_public_parameters *pp);

int vt_build(const vt_public_parameters *pp, const uint64_t *set,
             size_t set_len, const uint8_t build_seed[VT_SEED_BYTES],
             va_commitment *root, vt_state *state);

int vt_upd(const vt_public_parameters *pp, uint64_t x,
           const va_commitment *root, vt_state *state, uint8_t op,
           va_commitment *new_root);

void vt_state_clear(vt_state *state);

int vt_path(const vt_public_parameters *pp, uint64_t x,
            uint16_t *digits, size_t digits_len);
void vt_hash_leaf(vt_value *out, uint8_t membership, uint64_t x);
void vt_hash_node(vt_value *out, size_t level,
                  const va_commitment *node_commitment);

const vt_leaf *vt_get_leaf(const vt_state *state, uint64_t x);
const vt_node *vt_get_node(const vt_state *state, size_t level,
                           size_t index);
int vt_open_node(va_opening_relation *opening,
                 const vt_public_parameters *pp, const vt_state *state,
                 size_t level, size_t node_index, size_t coordinate);

#endif
