#include "verkle_accumulator/accumulator.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *acc_aligned_calloc(size_t count, size_t size) {
  size_t bytes;
  void *allocation;

  if (count != 0 && size > SIZE_MAX / count)
    return NULL;
  bytes = count * size;
  if (bytes > SIZE_MAX - 63U)
    return NULL;
  allocation = aligned_alloc(64, (bytes + 63U) & ~(size_t)63U);
  if (allocation != NULL)
    memset(allocation, 0, bytes);
  return allocation;
}

static int bitset_size(uint64_t universe_size, size_t *bytes) {
  uint64_t result;
  if (bytes == NULL || universe_size > UINT64_MAX - 7U)
    return VT_ERR_OVERFLOW;
  result = (universe_size + 7U) / 8U;
  if (result > SIZE_MAX)
    return VT_ERR_OVERFLOW;
  *bytes = (size_t)result;
  return VT_OK;
}

static int set_get(const acc_state *state, uint64_t x) {
  return (state->set[x >> 3U] >> (x & 7U)) & 1U;
}

static void set_put(acc_state *state, uint64_t x, uint8_t value) {
  const uint8_t mask = (uint8_t)(1U << (x & 7U));
  if (value != 0)
    state->set[x >> 3U] |= mask;
  else
    state->set[x >> 3U] &= (uint8_t)~mask;
}

int acc_setup(acc_public_parameters *pp, uint64_t universe_size,
              const uint8_t setup_seed[VT_SEED_BYTES]) {
  int ret;
  if (pp == NULL || setup_seed == NULL)
    return VT_ERR_ARGUMENT;
  memset(pp, 0, sizeof(*pp));
  pp->branching_factor = VA_ARITY;
  ret = vt_setup(&pp->tree, universe_size, setup_seed);
  if (ret != VT_OK)
    memset(pp, 0, sizeof(*pp));
  return ret;
}

void acc_public_parameters_clear(acc_public_parameters *pp) {
  if (pp == NULL)
    return;
  vt_public_parameters_clear(&pp->tree);
  memset(pp, 0, sizeof(*pp));
}

void acc_state_clear(acc_state *state) {
  if (state == NULL)
    return;
  free(state->set);
  vt_state_clear(&state->tree);
  memset(state, 0, sizeof(*state));
}

int acc_eval(const acc_public_parameters *pp, const uint64_t *set,
             size_t set_len, const uint8_t build_seed[VT_SEED_BYTES],
             acc_value *acc, acc_state *state) {
  size_t i;
  int ret;

  if (pp == NULL || build_seed == NULL || acc == NULL || state == NULL ||
      (set_len != 0 && set == NULL))
    return VT_ERR_ARGUMENT;
  memset(state, 0, sizeof(*state));
  ret = bitset_size(pp->tree.universe_size, &state->set_bytes);
  if (ret != VT_OK)
    return ret;
  state->set = calloc(state->set_bytes, 1);
  if (state->set == NULL) {
    acc_state_clear(state);
    return VT_ERR_MEMORY;
  }
  ret = vt_build(&pp->tree, set, set_len, build_seed, acc, &state->tree);
  if (ret != VT_OK) {
    acc_state_clear(state);
    return ret;
  }
  for (i = 0; i < set_len; ++i)
    set_put(state, set[i], 1);
  state->set_size = set_len;
  return VT_OK;
}

int acc_contains(const acc_state *state, uint64_t x) {
  if (state == NULL || state->set == NULL || x >= state->tree.universe_size)
    return 0;
  return set_get(state, x);
}

int acc_upd(const acc_public_parameters *pp, const acc_value *acc,
            acc_state *state, uint64_t x, uint8_t op,
            acc_value *new_acc) {
  int ret;

  if (pp == NULL || acc == NULL || state == NULL || new_acc == NULL ||
      state->set == NULL || (op != ACC_NONMEMBERSHIP && op != ACC_MEMBERSHIP))
    return VT_ERR_ARGUMENT;
  if (x >= pp->tree.universe_size)
    return VT_ERR_RANGE;
  if (set_get(state, x) == op)
    return VT_ERR_ILLEGAL_UPDATE;
  ret = vt_upd(&pp->tree, x, acc, &state->tree, op, new_acc);
  if (ret != VT_OK)
    return ret;
  set_put(state, x, op);
  if (op == ACC_MEMBERSHIP)
    ++state->set_size;
  else
    --state->set_size;
  return VT_OK;
}

void acc_witness_clear(acc_witness *proof_bundle) {
  size_t level;

  if (proof_bundle == NULL)
    return;
  if (proof_bundle->opening_proofs != NULL)
    for (level = 0; level < proof_bundle->proof_count; ++level)
      free_composite(&proof_bundle->opening_proofs[level]);
  free(proof_bundle->opening_proofs);
  free(proof_bundle->intermediate_commitments);
  memset(proof_bundle, 0, sizeof(*proof_bundle));
}

static size_t path_node_index(const uint16_t *path, size_t level) {
  size_t index = 0, i;
  for (i = 0; i < level; ++i)
    index = index * VA_ARITY + path[i];
  return index;
}

int acc_wit(const acc_public_parameters *pp, const acc_value *acc,
            const acc_state *state, uint64_t x, acc_witness *proof_bundle) {
  uint16_t *path = NULL;
  va_opening_relation opening = {0};
  size_t level;
  int ret = VT_OK;

  if (pp == NULL || acc == NULL || state == NULL || proof_bundle == NULL ||
      state->tree.nodes == NULL || x >= pp->tree.universe_size ||
      state->tree.depth != pp->tree.depth ||
      !va_commitment_equal(acc, &state->tree.nodes[0][0].commitment))
    return VT_ERR_ARGUMENT;
  memset(proof_bundle, 0, sizeof(*proof_bundle));
  proof_bundle->depth = pp->tree.depth;
  proof_bundle->intermediate_count = proof_bundle->depth - 1U;
  proof_bundle->proof_count = proof_bundle->depth;
  path = calloc(proof_bundle->depth, sizeof(*path));
  proof_bundle->opening_proofs = calloc(
      proof_bundle->proof_count, sizeof(*proof_bundle->opening_proofs));
  if (proof_bundle->intermediate_count != 0) {
    proof_bundle->intermediate_commitments = acc_aligned_calloc(
        proof_bundle->intermediate_count,
        sizeof(*proof_bundle->intermediate_commitments));
  }
  if (path == NULL || proof_bundle->opening_proofs == NULL ||
      (proof_bundle->intermediate_count != 0 &&
       proof_bundle->intermediate_commitments == NULL)) {
    ret = VT_ERR_MEMORY;
    goto err;
  }
  ret = vt_path(&pp->tree, x, path, proof_bundle->depth);
  if (ret != VT_OK)
    goto err;

  for (level = 0; level < proof_bundle->depth; ++level) {
    const size_t node_index = path_node_index(path, level);
    const vt_node *node = vt_get_node(&state->tree, level, node_index);
    if (node == NULL) {
      ret = VT_ERR_ARGUMENT;
      goto err;
    }
    if (level != 0)
      proof_bundle->intermediate_commitments[level - 1U] = node->commitment;
    ret = vt_open_node(&opening, &pp->tree, &state->tree, level, node_index,
                       path[level]);
    if (ret != VT_OK)
      goto err;
    if (va_prove(&proof_bundle->opening_proofs[level], &opening) != 0) {
      ret = VT_ERR_VC;
      goto err;
    }
    va_opening_relation_clear(&opening);
  }
  free(path);
  return VT_OK;

err:
  va_opening_relation_clear(&opening);
  free(path);
  acc_witness_clear(proof_bundle);
  return ret;
}

static int composite_shape_valid(const composite *composite_proof) {
  size_t i;
  if (composite_proof == NULL || composite_proof->l == 0 ||
      composite_proof->l > 16 || composite_proof->owt.n == NULL)
    return 0;
  for (i = 0; i < composite_proof->l; ++i)
    if (composite_proof->pi[i] == NULL)
      return 0;
  return 1;
}

int acc_verify(const acc_public_parameters *pp, const acc_value *acc,
               uint64_t x, const acc_witness *proof_bundle, uint8_t type) {
  uint16_t *path = NULL;
  prncplstmnt principal = {0};
  const va_commitment *current;
  vt_value expected;
  size_t level;
  int ret = VT_ERR_VC;

  if (pp == NULL || acc == NULL || proof_bundle == NULL ||
      proof_bundle->opening_proofs == NULL || x >= pp->tree.universe_size ||
      proof_bundle->depth != pp->tree.depth ||
      proof_bundle->proof_count != pp->tree.depth ||
      proof_bundle->intermediate_count != pp->tree.depth - 1U ||
      (proof_bundle->intermediate_count != 0 &&
       proof_bundle->intermediate_commitments == NULL) ||
      (type != ACC_NONMEMBERSHIP && type != ACC_MEMBERSHIP))
    return VT_ERR_ARGUMENT;
  for (level = 0; level < proof_bundle->proof_count; ++level)
    if (!composite_shape_valid(&proof_bundle->opening_proofs[level]))
      return VT_ERR_ARGUMENT;
  path = calloc(proof_bundle->depth, sizeof(*path));
  if (path == NULL)
    return VT_ERR_MEMORY;
  if (vt_path(&pp->tree, x, path, proof_bundle->depth) != VT_OK) {
    ret = VT_ERR_RANGE;
    goto end;
  }

  current = acc;
  for (level = 0; level + 1U < proof_bundle->depth; ++level) {
    const va_commitment *child =
        &proof_bundle->intermediate_commitments[level];
    vt_hash_node(&expected, level + 1U, child);
    if (va_statement_init(&principal, &pp->tree.vc, current, path[level],
                          expected.scalar) != 0)
      goto end;
    {
      const int verify_ret =
          va_verify(&proof_bundle->opening_proofs[level], &principal);
      if (verify_ret != 0) {
        if (getenv("VA_BENCH_DIAGNOSTICS") != NULL)
          fprintf(stderr,
                  "%s accumulator verification failed at level %zu/%zu "
                  "(LaBRADOR status %d)\n",
                  VA_PROFILE_NAME, level + 1U, proof_bundle->depth,
                  verify_ret);
        goto end;
      }
    }
    free_prncplstmnt(&principal);
    memset(&principal, 0, sizeof(principal));
    current = child;
  }

  vt_hash_leaf(&expected, type, x);
  if (va_statement_init(&principal, &pp->tree.vc, current,
                        path[proof_bundle->depth - 1U], expected.scalar) != 0)
    goto end;
  {
    const size_t leaf_level = proof_bundle->depth - 1U;
    const int verify_ret =
        va_verify(&proof_bundle->opening_proofs[leaf_level], &principal);
    if (verify_ret != 0) {
      if (getenv("VA_BENCH_DIAGNOSTICS") != NULL)
        fprintf(stderr,
                "%s accumulator verification failed at level %zu/%zu "
                "(LaBRADOR status %d)\n",
                VA_PROFILE_NAME, leaf_level + 1U, proof_bundle->depth,
                verify_ret);
      goto end;
    }
  }
  ret = VT_OK;

end:
  free_prncplstmnt(&principal);
  free(path);
  return ret;
}

double acc_witness_estimated_kib(const acc_witness *proof_bundle) {
  double size;
  size_t level;

  if (proof_bundle == NULL || proof_bundle->opening_proofs == NULL)
    return 0.0;
  size = proof_bundle->intermediate_count != 0
             ? (double)proof_bundle->intermediate_count *
                   VA_COMMITMENT_BYTES / 1024.0
             : 0.0;
  for (level = 0; level < proof_bundle->proof_count; ++level)
    size += proof_bundle->opening_proofs[level].size;
  return size;
}
