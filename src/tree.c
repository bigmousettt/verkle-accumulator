#include "verkle_accumulator/tree.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "fips202.h"

static void *aligned_calloc(size_t count, size_t size) {
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

static void put_u64_le(uint8_t out[8], uint64_t value) {
  size_t i;
  for (i = 0; i < 8; ++i)
    out[i] = (uint8_t)(value >> (8U * i));
}

static uint32_t get_u32_le(const uint8_t in[4]) {
  return (uint32_t)in[0] | ((uint32_t)in[1] << 8U) |
         ((uint32_t)in[2] << 16U) | ((uint32_t)in[3] << 24U);
}

static void squeeze_value(vt_value *out, shake128incctx *hash) {
  size_t i = 0;
  uint8_t candidate[4];

  shake128_inc_finalize(hash);
  while (i < VA_KAPPA) {
    uint32_t value;
    shake128_inc_squeeze(candidate, sizeof(candidate), hash);
    value = get_u32_le(candidate);
    if ((uint64_t)value < VA_Q)
      out->scalar[i++] = value;
  }
}

static void derive_seed(uint8_t *out, size_t out_len, const char *domain,
                        const uint8_t *seed, size_t seed_len) {
  shake128incctx hash;
  shake128_inc_init(&hash);
  shake128_inc_absorb(&hash, (const uint8_t *)domain, strlen(domain));
  shake128_inc_absorb(&hash, seed, seed_len);
  shake128_inc_finalize(&hash);
  shake128_inc_squeeze(out, out_len, &hash);
}

void vt_hash_leaf(vt_value *out, uint8_t membership, uint64_t x) {
  static const uint8_t domain[] = "VA-H-leaf-v1";
  uint8_t encoded_x[8];
  shake128incctx hash;

  if (out == NULL)
    return;
  put_u64_le(encoded_x, x);
  shake128_inc_init(&hash);
  shake128_inc_absorb(&hash, domain, sizeof(domain) - 1U);
  shake128_inc_absorb(&hash, &membership, 1);
  shake128_inc_absorb(&hash, encoded_x, sizeof(encoded_x));
  squeeze_value(out, &hash);
}

void vt_hash_node(vt_value *out, size_t level,
                  const va_commitment *node_commitment) {
  static const uint8_t domain[] = "VA-H-node-v1";
  uint8_t encoded_level[8];
  uint8_t encoded_commitment[VA_COMMITMENT_BYTES];
  shake128incctx hash;

  if (out == NULL || node_commitment == NULL)
    return;
  put_u64_le(encoded_level, (uint64_t)level);
  va_commitment_encode(encoded_commitment, node_commitment);
  shake128_inc_init(&hash);
  shake128_inc_absorb(&hash, domain, sizeof(domain) - 1U);
  shake128_inc_absorb(&hash, encoded_level, sizeof(encoded_level));
  shake128_inc_absorb(&hash, encoded_commitment,
                      sizeof(encoded_commitment));
  squeeze_value(out, &hash);
}

static void hash_empty(vt_value *out, size_t level) {
  static const uint8_t domain[] = "VA-VT-empty-v1";
  uint8_t encoded_level[8];
  shake128incctx hash;

  put_u64_le(encoded_level, (uint64_t)level);
  shake128_inc_init(&hash);
  shake128_inc_absorb(&hash, domain, sizeof(domain) - 1U);
  shake128_inc_absorb(&hash, encoded_level, sizeof(encoded_level));
  squeeze_value(out, &hash);
}

static int compute_depth(uint64_t universe_size, size_t *depth) {
  uint64_t capacity = 1;
  size_t d = 0;

  if (universe_size < 2 || depth == NULL)
    return VT_ERR_ARGUMENT;
  while (capacity < universe_size) {
    if (capacity > UINT64_MAX / VA_ARITY)
      return VT_ERR_OVERFLOW;
    capacity *= VA_ARITY;
    ++d;
  }
  *depth = d;
  return VT_OK;
}

int vt_setup(vt_public_parameters *pp, uint64_t universe_size,
             const uint8_t setup_seed[VT_SEED_BYTES]) {
  uint8_t a[16], b[16], e[16];
  size_t level;
  int ret;

  if (pp == NULL || setup_seed == NULL)
    return VT_ERR_ARGUMENT;
  memset(pp, 0, sizeof(*pp));
  ret = compute_depth(universe_size, &pp->depth);
  if (ret != VT_OK)
    return ret;
  pp->universe_size = universe_size;
  memcpy(pp->setup_seed, setup_seed, VT_SEED_BYTES);
  pp->empty_values = calloc(pp->depth + 1U, sizeof(*pp->empty_values));
  if (pp->empty_values == NULL) {
    vt_public_parameters_clear(pp);
    return VT_ERR_MEMORY;
  }
  for (level = 0; level <= pp->depth; ++level)
    hash_empty(&pp->empty_values[level], level);
  derive_seed(a, sizeof(a), "VA-VT-setup-A-v1", setup_seed, VT_SEED_BYTES);
  derive_seed(b, sizeof(b), "VA-VT-setup-B-v1", setup_seed, VT_SEED_BYTES);
  derive_seed(e, sizeof(e), "VA-VT-setup-E-v1", setup_seed, VT_SEED_BYTES);
  if (va_context_init(&pp->vc, a, b, e) != 0) {
    vt_public_parameters_clear(pp);
    return VT_ERR_VC;
  }
  return VT_OK;
}

void vt_public_parameters_clear(vt_public_parameters *pp) {
  if (pp == NULL)
    return;
  va_context_clear(&pp->vc);
  free(pp->empty_values);
  memset(pp, 0, sizeof(*pp));
}

static size_t ceil_div_u64(uint64_t numerator, uint64_t denominator) {
  return (size_t)(numerator / denominator +
                  (numerator % denominator != 0));
}

static int init_node_counts(const vt_public_parameters *pp, vt_state *state) {
  size_t level;
  uint64_t subtree_capacity = VA_ARITY;

  state->node_counts = calloc(pp->depth, sizeof(*state->node_counts));
  state->nodes = calloc(pp->depth, sizeof(*state->nodes));
  if (state->node_counts == NULL || state->nodes == NULL)
    return VT_ERR_MEMORY;
  for (level = pp->depth; level-- > 0;) {
    state->node_counts[level] =
        ceil_div_u64(pp->universe_size, subtree_capacity);
    if (level != 0) {
      if (subtree_capacity > UINT64_MAX / VA_ARITY)
        return VT_ERR_OVERFLOW;
      subtree_capacity *= VA_ARITY;
    }
  }
  return state->node_counts[0] == 1 ? VT_OK : VT_ERR_OVERFLOW;
}

static void node_clear(vt_node *node) {
  if (node == NULL)
    return;
  free(node->values);
  va_prover_state_clear(&node->vc_state);
  memset(node, 0, sizeof(*node));
}

void vt_state_clear(vt_state *state) {
  size_t level, index;

  if (state == NULL)
    return;
  if (state->nodes != NULL) {
    for (level = 0; level < state->depth; ++level) {
      if (state->nodes[level] != NULL && state->node_counts != NULL)
        for (index = 0; index < state->node_counts[level]; ++index)
          node_clear(&state->nodes[level][index]);
      free(state->nodes[level]);
    }
  }
  free(state->nodes);
  free(state->node_counts);
  free(state->leaves);
  memset(state, 0, sizeof(*state));
}

static void set_message_value(uint32_t *message, size_t coordinate,
                              const vt_value *value) {
  memcpy(&message[coordinate * VA_KAPPA], value->scalar,
         VA_KAPPA * sizeof(*message));
}

static void derive_node_seed(uint8_t out[16], const uint8_t build_seed[32],
                             uint64_t epoch, size_t level, size_t index) {
  static const uint8_t domain[] = "VA-VT-node-randomness-v1";
  uint8_t encoded[24];
  shake128incctx hash;

  put_u64_le(&encoded[0], epoch);
  put_u64_le(&encoded[8], (uint64_t)level);
  put_u64_le(&encoded[16], (uint64_t)index);
  shake128_inc_init(&hash);
  shake128_inc_absorb(&hash, domain, sizeof(domain) - 1U);
  shake128_inc_absorb(&hash, build_seed, VT_SEED_BYTES);
  shake128_inc_absorb(&hash, encoded, sizeof(encoded));
  shake128_inc_finalize(&hash);
  shake128_inc_squeeze(out, 16, &hash);
}

static int commit_node(const vt_public_parameters *pp,
                       const uint8_t build_seed[32], uint64_t epoch,
                       size_t level, size_t index, vt_node *node) {
  uint8_t randomness_seed[16];
  derive_node_seed(randomness_seed, build_seed, epoch, level, index);
  if (va_commit(&pp->vc, node->values, randomness_seed, &node->commitment,
                &node->vc_state) != 0)
    return VT_ERR_VC;
  return VT_OK;
}

static int allocate_nodes(vt_state *state) {
  size_t level, index;

  for (level = 0; level < state->depth; ++level) {
    if (state->node_counts[level] > SIZE_MAX / sizeof(*state->nodes[level]))
      return VT_ERR_OVERFLOW;
    state->nodes[level] = aligned_calloc(state->node_counts[level],
                                         sizeof(*state->nodes[level]));
    if (state->nodes[level] == NULL)
      return VT_ERR_MEMORY;
    for (index = 0; index < state->node_counts[level]; ++index) {
      state->nodes[level][index].values =
          calloc(VA_MESSAGE_SCALARS, sizeof(uint32_t));
      if (state->nodes[level][index].values == NULL)
        return VT_ERR_MEMORY;
    }
  }
  return VT_OK;
}

int vt_build(const vt_public_parameters *pp, const uint64_t *set,
             size_t set_len, const uint8_t build_seed[VT_SEED_BYTES],
             va_commitment *root, vt_state *state) {
  size_t i, level, index, coordinate;
  int ret;

  if (pp == NULL || build_seed == NULL || root == NULL || state == NULL ||
      pp->empty_values == NULL || (set_len != 0 && set == NULL))
    return VT_ERR_ARGUMENT;
  if (pp->universe_size > SIZE_MAX / sizeof(*state->leaves))
    return VT_ERR_OVERFLOW;
  memset(state, 0, sizeof(*state));
  state->universe_size = pp->universe_size;
  state->depth = pp->depth;
  memcpy(state->build_seed, build_seed, VT_SEED_BYTES);
  state->leaves = calloc((size_t)pp->universe_size, sizeof(*state->leaves));
  if (state->leaves == NULL) {
    ret = VT_ERR_MEMORY;
    goto err;
  }
  ret = init_node_counts(pp, state);
  if (ret != VT_OK)
    goto err;
  ret = allocate_nodes(state);
  if (ret != VT_OK)
    goto err;

  for (i = 0; i < (size_t)pp->universe_size; ++i) {
    state->leaves[i].x = i;
    vt_hash_leaf(&state->leaves[i].value, 0, i);
  }
  for (i = 0; i < set_len; ++i) {
    if (set[i] >= pp->universe_size) {
      ret = VT_ERR_RANGE;
      goto err;
    }
    if (state->leaves[set[i]].membership != 0) {
      ret = VT_ERR_DUPLICATE;
      goto err;
    }
    state->leaves[set[i]].membership = 1;
    vt_hash_leaf(&state->leaves[set[i]].value, 1, set[i]);
  }

  for (level = state->depth; level-- > 0;) {
    for (index = 0; index < state->node_counts[level]; ++index) {
      vt_node *node = &state->nodes[level][index];
      for (coordinate = 0; coordinate < VA_ARITY; ++coordinate) {
        const uint64_t child = (uint64_t)index * VA_ARITY + coordinate;
        vt_value value;
        if (level + 1U == state->depth) {
          if (child < state->universe_size)
            value = state->leaves[child].value;
          else
            value = pp->empty_values[level + 1U];
        } else if (child < state->node_counts[level + 1U]) {
          vt_hash_node(&value, level + 1U,
                       &state->nodes[level + 1U][child].commitment);
        } else {
          value = pp->empty_values[level + 1U];
        }
        set_message_value(node->values, coordinate, &value);
      }
      ret = commit_node(pp, state->build_seed, 0, level, index, node);
      if (ret != VT_OK)
        goto err;
    }
  }
  *root = state->nodes[0][0].commitment;
  return VT_OK;

err:
  vt_state_clear(state);
  return ret;
}

int vt_path(const vt_public_parameters *pp, uint64_t x,
            uint16_t *digits, size_t digits_len) {
  size_t level;

  if (pp == NULL || digits == NULL || digits_len < pp->depth)
    return VT_ERR_ARGUMENT;
  if (x >= pp->universe_size)
    return VT_ERR_RANGE;
  for (level = pp->depth; level-- > 0;) {
    digits[level] = (uint16_t)(x % VA_ARITY);
    x /= VA_ARITY;
  }
  return VT_OK;
}

static size_t path_node_index(const uint16_t *digits, size_t level) {
  size_t index = 0, i;
  for (i = 0; i < level; ++i)
    index = index * VA_ARITY + digits[i];
  return index;
}

int vt_upd(const vt_public_parameters *pp, uint64_t x,
           const va_commitment *root, vt_state *state, uint8_t op,
           va_commitment *new_root) {
  uint16_t *digits = NULL;
  vt_node *updates = NULL;
  vt_value child_value;
  uint64_t next_epoch;
  size_t level;
  int ret = VT_OK;

  if (pp == NULL || root == NULL || state == NULL || new_root == NULL ||
      state->nodes == NULL || pp->depth != state->depth ||
      pp->universe_size != state->universe_size || (op != 0 && op != 1))
    return VT_ERR_ARGUMENT;
  if (x >= state->universe_size)
    return VT_ERR_RANGE;
  if (!va_commitment_equal(root, &state->nodes[0][0].commitment))
    return VT_ERR_ARGUMENT;
  if (state->leaves[x].membership == op)
    return VT_ERR_ILLEGAL_UPDATE;
  if (state->epoch == UINT64_MAX)
    return VT_ERR_OVERFLOW;
  next_epoch = state->epoch + 1U;
  digits = calloc(state->depth, sizeof(*digits));
  updates = aligned_calloc(state->depth, sizeof(*updates));
  if (digits == NULL || updates == NULL) {
    ret = VT_ERR_MEMORY;
    goto end;
  }
  ret = vt_path(pp, x, digits, state->depth);
  if (ret != VT_OK)
    goto end;
  vt_hash_leaf(&child_value, op, x);

  for (level = state->depth; level-- > 0;) {
    const size_t node_index = path_node_index(digits, level);
    const vt_node *old_node = &state->nodes[level][node_index];
    updates[level].values = malloc(VA_MESSAGE_SCALARS * sizeof(uint32_t));
    if (updates[level].values == NULL) {
      ret = VT_ERR_MEMORY;
      goto end;
    }
    memcpy(updates[level].values, old_node->values,
           VA_MESSAGE_SCALARS * sizeof(uint32_t));
    set_message_value(updates[level].values, digits[level], &child_value);
    ret = commit_node(pp, state->build_seed, next_epoch, level, node_index,
                      &updates[level]);
    if (ret != VT_OK)
      goto end;
    vt_hash_node(&child_value, level, &updates[level].commitment);
  }

  for (level = 0; level < state->depth; ++level) {
    const size_t node_index = path_node_index(digits, level);
    node_clear(&state->nodes[level][node_index]);
    state->nodes[level][node_index] = updates[level];
    memset(&updates[level], 0, sizeof(updates[level]));
  }
  state->leaves[x].membership = op;
  vt_hash_leaf(&state->leaves[x].value, op, x);
  state->epoch = next_epoch;
  *new_root = state->nodes[0][0].commitment;

end:
  if (updates != NULL)
    for (level = 0; level < state->depth; ++level)
      node_clear(&updates[level]);
  free(updates);
  free(digits);
  return ret;
}

const vt_leaf *vt_get_leaf(const vt_state *state, uint64_t x) {
  if (state == NULL || state->leaves == NULL || x >= state->universe_size)
    return NULL;
  return &state->leaves[x];
}

const vt_node *vt_get_node(const vt_state *state, size_t level,
                           size_t index) {
  if (state == NULL || state->nodes == NULL || level >= state->depth ||
      index >= state->node_counts[level])
    return NULL;
  return &state->nodes[level][index];
}

int vt_open_node(va_opening_relation *opening,
                 const vt_public_parameters *pp, const vt_state *state,
                 size_t level, size_t node_index, size_t coordinate) {
  const vt_node *node = vt_get_node(state, level, node_index);
  if (opening == NULL || pp == NULL || node == NULL ||
      coordinate >= VA_ARITY)
    return VT_ERR_ARGUMENT;
  return va_open(opening, &pp->vc, &node->commitment, &node->vc_state,
                 node->values, coordinate) == 0
             ? VT_OK
             : VT_ERR_VC;
}
