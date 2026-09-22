#define _POSIX_C_SOURCE 200809L

#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fips202.h"
#include "verkle_accumulator/accumulator.h"

enum {
  BENCH_MAX_DEPTH = 4,
  VAW1_HEADER_BYTES = 64
};

typedef struct {
  size_t depth;
  uint64_t epoch;
  uint64_t x;
  uint16_t path[BENCH_MAX_DEPTH];
  vt_node *nodes;
} path_fixture;

typedef struct {
  double prove_s;
  double verify_s;
  double level_prove_s[BENCH_MAX_DEPTH];
  double level_verify_s[BENCH_MAX_DEPTH];
  size_t level_proof_bytes[BENCH_MAX_DEPTH];
  size_t proof_bytes;
  size_t commitment_bytes;
  size_t wire_bytes;
} witness_metrics;

static int checked_add(size_t left, size_t right, size_t *result) {
  if (result == NULL || left > SIZE_MAX - right)
    return 0;
  *result = left + right;
  return 1;
}

static int checked_mul(size_t left, size_t right, size_t *result) {
  if (result == NULL || (left != 0 && right > SIZE_MAX / left))
    return 0;
  *result = left * right;
  return 1;
}

static void *aligned_calloc(size_t count, size_t size) {
  size_t bytes, rounded;
  void *allocation;

  if (!checked_mul(count, size, &bytes) || bytes == 0 ||
      !checked_add(bytes, 63U, &rounded))
    return NULL;
  rounded &= ~(size_t)63U;
  allocation = aligned_alloc(64, rounded);
  if (allocation != NULL)
    memset(allocation, 0, bytes);
  return allocation;
}

static double now_seconds(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
    return 0.0;
  return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
}

static void put_u64_le(uint8_t out[8], uint64_t value) {
  size_t i;
  for (i = 0; i < 8; ++i)
    out[i] = (uint8_t)(value >> (8U * i));
}

static void set_message_value(uint32_t *message, size_t coordinate,
                              const vt_value *value) {
  memcpy(&message[coordinate * VA_KAPPA], value->scalar,
         VA_KAPPA * sizeof(*message));
}

/* Match the production tree's domain-separated per-node randomness model. */
static void fixture_randomness_seed(
    uint8_t out[16], const uint8_t setup_seed[VT_SEED_BYTES], uint64_t epoch,
    size_t level) {
  static const uint8_t domain[] = "VA-benchmark-path-randomness-v1";
  uint8_t encoded[16];
  shake128incctx hash;

  put_u64_le(&encoded[0], epoch);
  put_u64_le(&encoded[8], (uint64_t)level);
  shake128_inc_init(&hash);
  shake128_inc_absorb(&hash, domain, sizeof(domain) - 1U);
  shake128_inc_absorb(&hash, setup_seed, VT_SEED_BYTES);
  shake128_inc_absorb(&hash, encoded, sizeof(encoded));
  shake128_inc_finalize(&hash);
  shake128_inc_squeeze(out, 16, &hash);
}

static int replace_node_commitment(const acc_public_parameters *pp,
                                   path_fixture *fixture, size_t level) {
  uint8_t randomness_seed[16];
  va_commitment next_commitment;
  va_prover_state state = {0};
  vt_node *node;

  if (pp == NULL || fixture == NULL || fixture->nodes == NULL ||
      level >= fixture->depth)
    return VT_ERR_ARGUMENT;
  node = &fixture->nodes[level];
  fixture_randomness_seed(randomness_seed, pp->tree.setup_seed,
                          fixture->epoch, level);
  if (va_commit(&pp->tree.vc, node->values, randomness_seed, &next_commitment,
                &state) != 0)
    return VT_ERR_VC;
  va_prover_state_clear(&node->vc_state);
  node->vc_state = state;
  node->commitment = next_commitment;
  return VT_OK;
}

static void path_fixture_clear(path_fixture *fixture) {
  size_t level;
  if (fixture == NULL)
    return;
  if (fixture->nodes != NULL) {
    for (level = 0; level < fixture->depth; ++level) {
      free(fixture->nodes[level].values);
      va_prover_state_clear(&fixture->nodes[level].vc_state);
    }
  }
  free(fixture->nodes);
  memset(fixture, 0, sizeof(*fixture));
}

/*
 * Materialize exactly one authentication path at the target depth. Unopened
 * coordinates use a deterministic public level value as benchmark-only
 * filler. The selected leaf remains position-dependent: H_leaf(type, x).
 */
static int path_fixture_init(path_fixture *fixture,
                             const acc_public_parameters *pp, uint64_t x,
                             uint8_t type, acc_value *root) {
  vt_value child;
  size_t level, coordinate;
  int ret = VT_OK;

  if (fixture == NULL || pp == NULL || root == NULL ||
      pp->tree.depth == 0 || pp->tree.depth > BENCH_MAX_DEPTH ||
      x >= pp->tree.universe_size)
    return VT_ERR_ARGUMENT;
  memset(fixture, 0, sizeof(*fixture));
  fixture->depth = pp->tree.depth;
  fixture->x = x;
  fixture->nodes = aligned_calloc(fixture->depth, sizeof(*fixture->nodes));
  if (fixture->nodes == NULL)
    return VT_ERR_MEMORY;
  ret = vt_path(&pp->tree, x, fixture->path, fixture->depth);
  if (ret != VT_OK)
    goto err;

  for (level = 0; level < fixture->depth; ++level) {
    fixture->nodes[level].values =
        calloc(VA_MESSAGE_SCALARS, sizeof(uint32_t));
    if (fixture->nodes[level].values == NULL) {
      ret = VT_ERR_MEMORY;
      goto err;
    }
    for (coordinate = 0; coordinate < VA_ARITY; ++coordinate)
      set_message_value(fixture->nodes[level].values, coordinate,
                        &pp->tree.empty_values[level + 1U]);
  }

  vt_hash_leaf(&child, type, x);
  for (level = fixture->depth; level-- > 0;) {
    set_message_value(fixture->nodes[level].values, fixture->path[level],
                      &child);
    ret = replace_node_commitment(pp, fixture, level);
    if (ret != VT_OK)
      goto err;
    if (level != 0)
      vt_hash_node(&child, level, &fixture->nodes[level].commitment);
  }
  *root = fixture->nodes[0].commitment;
  return VT_OK;

err:
  path_fixture_clear(fixture);
  return ret;
}

/* Recommit the real target-depth path, from the leaf parent to the root. */
static int path_fixture_update(path_fixture *fixture,
                               const acc_public_parameters *pp, uint8_t type,
                               acc_value *root,
                               double level_commit_s[BENCH_MAX_DEPTH]) {
  vt_value child;
  size_t level;

  if (fixture == NULL || pp == NULL || root == NULL ||
      level_commit_s == NULL || fixture->nodes == NULL)
    return VT_ERR_ARGUMENT;
  memset(level_commit_s, 0,
         BENCH_MAX_DEPTH * sizeof(*level_commit_s));
  ++fixture->epoch;
  vt_hash_leaf(&child, type, fixture->x);
  for (level = fixture->depth; level-- > 0;) {
    double start;
    int ret;
    set_message_value(fixture->nodes[level].values, fixture->path[level],
                      &child);
    start = now_seconds();
    ret = replace_node_commitment(pp, fixture, level);
    level_commit_s[level] = now_seconds() - start;
    if (ret != VT_OK)
      return ret;
    if (level != 0)
      vt_hash_node(&child, level, &fixture->nodes[level].commitment);
  }
  *root = fixture->nodes[0].commitment;
  return VT_OK;
}

static int witness_generate(const acc_public_parameters *pp,
                            const path_fixture *fixture,
                            acc_witness *proof_bundle,
                            witness_metrics *metrics) {
  va_opening_relation opening = {0};
  const int diagnostics = getenv("VA_BENCH_DIAGNOSTICS") != NULL;
  size_t level;
  double total_start;
  int ret = VT_OK;

  if (pp == NULL || fixture == NULL || proof_bundle == NULL ||
      metrics == NULL || fixture->nodes == NULL)
    return VT_ERR_ARGUMENT;
  memset(proof_bundle, 0, sizeof(*proof_bundle));
  memset(metrics, 0, sizeof(*metrics));
  proof_bundle->depth = fixture->depth;
  proof_bundle->intermediate_count = fixture->depth - 1U;
  proof_bundle->proof_count = fixture->depth;
  proof_bundle->opening_proofs =
      calloc(fixture->depth, sizeof(*proof_bundle->opening_proofs));
  if (fixture->depth > 1U)
    proof_bundle->intermediate_commitments = aligned_calloc(
        fixture->depth - 1U,
        sizeof(*proof_bundle->intermediate_commitments));
  if (proof_bundle->opening_proofs == NULL ||
      (fixture->depth > 1U &&
       proof_bundle->intermediate_commitments == NULL)) {
    ret = VT_ERR_MEMORY;
    goto err;
  }

  total_start = now_seconds();
  for (level = 0; level < fixture->depth; ++level) {
    double start = now_seconds();
    const vt_node *node = &fixture->nodes[level];
    if (level != 0)
      proof_bundle->intermediate_commitments[level - 1U] = node->commitment;
    if (va_open(&opening, &pp->tree.vc, &node->commitment, &node->vc_state,
                node->values, fixture->path[level]) != 0) {
      ret = VT_ERR_VC;
      goto err;
    }
    if (va_prove(&proof_bundle->opening_proofs[level], &opening) != 0) {
      if (diagnostics)
        fprintf(stderr, "%s proof generation failed at level %zu\n",
                VA_PROFILE_NAME, level + 1U);
      ret = VT_ERR_VC;
      goto err;
    }
    if (diagnostics) {
      const int verify_ret =
          va_verify(&proof_bundle->opening_proofs[level], &opening.statement);
      fprintf(stderr,
              "%s generated level %zu/%zu: layers=%zu, comkey=%zu, "
              "statement=%02x%02x%02x%02x%02x, immediate_verify=%s (%d)\n",
              VA_PROFILE_NAME, level + 1U, fixture->depth,
              proof_bundle->opening_proofs[level].l, comkey_len,
              opening.statement.h[0], opening.statement.h[1],
              opening.statement.h[2], opening.statement.h[3],
              opening.statement.h[4],
              verify_ret == 0 ? "ok" : "FAILED", verify_ret);
      if (verify_ret != 0) {
        ret = VT_ERR_VC;
        goto err;
      }
    }
    metrics->level_prove_s[level] = now_seconds() - start;
    va_opening_relation_clear(&opening);
  }
  if (diagnostics) {
    /*
     * Rebuild each original per-node statement in reverse order.  This
     * separates proof corruption/shared-state failures from a mismatch
     * between the path value stored in the node and the value reconstructed
     * by Acc.Verify from the child commitment.
     */
    for (level = fixture->depth; level-- > 0;) {
      const vt_node *node = &fixture->nodes[level];
      const uint32_t *actual =
          &node->values[(size_t)fixture->path[level] * VA_KAPPA];
      prncplstmnt principal = {0};
      vt_value expected;
      int path_value_matches;
      int verify_ret;

      if (level + 1U < fixture->depth) {
        vt_hash_node(&expected, level + 1U,
                     &fixture->nodes[level + 1U].commitment);
        path_value_matches =
            memcmp(actual, expected.scalar, sizeof(expected.scalar)) == 0;
      } else {
        vt_value member_leaf, nonmember_leaf;
        vt_hash_leaf(&member_leaf, ACC_MEMBERSHIP, fixture->x);
        vt_hash_leaf(&nonmember_leaf, ACC_NONMEMBERSHIP, fixture->x);
        path_value_matches =
            memcmp(actual, member_leaf.scalar, sizeof(member_leaf.scalar)) == 0 ||
            memcmp(actual, nonmember_leaf.scalar,
                   sizeof(nonmember_leaf.scalar)) == 0;
      }

      if (va_statement_init(&principal, &pp->tree.vc, &node->commitment,
                            fixture->path[level], actual) != 0) {
        fprintf(stderr,
                "%s reverse check level %zu/%zu: statement_init=FAILED, "
                "path_value_match=%s\n",
                VA_PROFILE_NAME, level + 1U, fixture->depth,
                path_value_matches ? "yes" : "NO");
        continue;
      }
      verify_ret =
          va_verify(&proof_bundle->opening_proofs[level], &principal);
      fprintf(stderr,
              "%s reverse check level %zu/%zu: original_statement=%s (%d), "
              "statement=%02x%02x%02x%02x%02x, path_value_match=%s\n",
              VA_PROFILE_NAME, level + 1U, fixture->depth,
              verify_ret == 0 ? "ok" : "FAILED", verify_ret,
              principal.h[0], principal.h[1], principal.h[2], principal.h[3],
              principal.h[4],
              path_value_matches ? "yes" : "NO");
      free_prncplstmnt(&principal);
    }
  }
  metrics->prove_s = now_seconds() - total_start;
  return VT_OK;

err:
  va_opening_relation_clear(&opening);
  acc_witness_clear(proof_bundle);
  return ret;
}

static int witness_verify_levels(const acc_public_parameters *pp,
                                 const acc_value *root, uint64_t x,
                                 const acc_witness *proof_bundle,
                                 uint8_t type,
                                 double level_verify_s[BENCH_MAX_DEPTH]) {
  const va_commitment *current = root;
  size_t level;

  memset(level_verify_s, 0,
         BENCH_MAX_DEPTH * sizeof(*level_verify_s));
  for (level = 0; level < proof_bundle->depth; ++level) {
    prncplstmnt principal = {0};
    vt_value expected;
    uint16_t path[BENCH_MAX_DEPTH];
    double start;

    if (vt_path(&pp->tree, x, path, proof_bundle->depth) != VT_OK)
      return VT_ERR_RANGE;
    if (level + 1U < proof_bundle->depth) {
      const va_commitment *child =
          &proof_bundle->intermediate_commitments[level];
      vt_hash_node(&expected, level + 1U, child);
    } else {
      vt_hash_leaf(&expected, type, x);
    }
    if (va_statement_init(&principal, &pp->tree.vc, current, path[level],
                          expected.scalar) != 0) {
      free_prncplstmnt(&principal);
      return VT_ERR_VC;
    }
    start = now_seconds();
    if (va_verify(&proof_bundle->opening_proofs[level], &principal) != 0) {
      if (getenv("VA_BENCH_DIAGNOSTICS") != NULL)
        fprintf(stderr, "%s path verification failed at level %zu/%zu\n",
                VA_PROFILE_NAME, level + 1U, proof_bundle->depth);
      free_prncplstmnt(&principal);
      return VT_ERR_VC;
    }
    level_verify_s[level] = now_seconds() - start;
    free_prncplstmnt(&principal);
    if (level + 1U < proof_bundle->depth)
      current = &proof_bundle->intermediate_commitments[level];
  }
  return VT_OK;
}

static int witness_measure_and_check(const acc_public_parameters *pp,
                                     const acc_value *root, uint64_t x,
                                     const acc_witness *proof_bundle,
                                     uint8_t type,
                                     witness_metrics *metrics) {
  acc_witness decoded = {0};
  uint8_t *encoded = NULL;
  size_t level, written = 0, expected_wire;
  double start;
  int ret = VT_OK;

  start = now_seconds();
  if (acc_verify(pp, root, x, proof_bundle, type) != VT_OK) {
    ret = VT_ERR_VC;
    goto end;
  }
  metrics->verify_s = now_seconds() - start;
  if (witness_verify_levels(pp, root, x, proof_bundle, type,
                            metrics->level_verify_s) != VT_OK) {
    ret = VT_ERR_VC;
    goto end;
  }

  for (level = 0; level < proof_bundle->proof_count; ++level) {
    size_t current;
    if (acc_composite_encoded_size(&proof_bundle->opening_proofs[level],
                                   &current) != VT_OK ||
        !checked_add(metrics->proof_bytes, current,
                     &metrics->proof_bytes)) {
      ret = VT_ERR_OVERFLOW;
      goto end;
    }
    metrics->level_proof_bytes[level] = current;
  }
  if (!checked_mul(proof_bundle->intermediate_count, VA_COMMITMENT_BYTES,
                   &metrics->commitment_bytes) ||
      !checked_add(VAW1_HEADER_BYTES, metrics->commitment_bytes,
                   &expected_wire) ||
      !checked_add(expected_wire, metrics->proof_bytes, &expected_wire) ||
      acc_witness_encoded_size(proof_bundle, &metrics->wire_bytes) != VT_OK ||
      expected_wire != metrics->wire_bytes) {
    ret = VT_ERR_OVERFLOW;
    goto end;
  }

  encoded = malloc(metrics->wire_bytes);
  if (encoded == NULL) {
    ret = VT_ERR_MEMORY;
    goto end;
  }
  if (acc_witness_encode(encoded, metrics->wire_bytes, &written,
                         proof_bundle) != VT_OK ||
      written != metrics->wire_bytes ||
      acc_witness_decode(pp, &decoded, encoded, written) != VT_OK ||
      acc_verify(pp, root, x, &decoded, type) != VT_OK) {
    ret = VT_ERR_VC;
    goto end;
  }

end:
  free(encoded);
  acc_witness_clear(&decoded);
  return ret;
}

static size_t public_matrix_ring_elements(void) {
  return (size_t)VA_INNER_RANK * VA_S_BLOCK_LEN +
         (size_t)VA_OUTER_RANK * VA_HAT_T_LEN +
         (size_t)VA_OUTER_RANK * VA_RANDOMNESS_LEN;
}

static void print_level_headers(const char *prefix, const char *suffix) {
  size_t level;
  for (level = 0; level < BENCH_MAX_DEPTH; ++level)
    printf(",%s_level%zu_%s", prefix, level + 1U, suffix);
}

static void print_level_doubles(const double values[BENCH_MAX_DEPTH]) {
  size_t level;
  for (level = 0; level < BENCH_MAX_DEPTH; ++level)
    printf(",%.9f", values[level]);
}

static void print_level_sizes(const size_t values[BENCH_MAX_DEPTH]) {
  size_t level;
  for (level = 0; level < BENCH_MAX_DEPTH; ++level)
    printf(",%zu", values[level]);
}

static void print_header(void) {
  printf("profile,q,ell,kappa,L,m,r,n0,n1,mu,b0,delta0,b1,delta1,"
         "universe_size,path_depth,proof_count,"
         "intermediate_commitment_count,raw_witness_ring_elements,"
         "public_matrix_ring_elements,public_matrix_explicit_bytes,"
         "setup_seed_bytes,public_parameters_expanded_ram_bytes,"
         "accumulator_value_bytes,setup_s,path_fixture_init_s,"
         "add_path_update_s");
  print_level_headers("add", "commit_s");
  printf(",member_prove_s,member_verify_s,member_proof_bytes,"
         "member_commitment_bytes,member_wire_bytes");
  print_level_headers("member", "prove_s");
  print_level_headers("member", "verify_s");
  print_level_headers("member", "proof_bytes");
  printf(",delete_path_update_s");
  print_level_headers("delete", "commit_s");
  printf(",nonmember_prove_s,nonmember_verify_s,nonmember_proof_bytes,"
         "nonmember_commitment_bytes,nonmember_wire_bytes");
  print_level_headers("nonmember", "prove_s");
  print_level_headers("nonmember", "verify_s");
  print_level_headers("nonmember", "proof_bytes");
  putchar('\n');
}

int main(int argc, char **argv) {
  static const uint8_t setup_seed[VT_SEED_BYTES] =
      "VA-benchmark-setup-seed-v1";
  const uint64_t universe_size = UINT64_C(1) << 32U;
  const uint64_t x = universe_size - 1U;
  acc_public_parameters pp = {0};
  path_fixture fixture = {0};
  acc_value root = {0};
  acc_witness member = {0}, nonmember = {0};
  witness_metrics member_metrics = {0}, nonmember_metrics = {0};
  double add_level_commit_s[BENCH_MAX_DEPTH] = {0};
  double delete_level_commit_s[BENCH_MAX_DEPTH] = {0};
  double start, setup_s, fixture_init_s, add_s, delete_s;
  size_t matrix_elements, explicit_matrix_bytes, expanded_pp_ram;
  int stdout_copy = -1, null_output = -1;
  int print_csv_header = 1;
  int ret = EXIT_FAILURE;

  if (argc == 2 && strcmp(argv[1], "--no-header") == 0)
    print_csv_header = 0;
  else if (argc != 1) {
    fprintf(stderr, "usage: benchmark_%s [--no-header]\n", VA_PROFILE_NAME);
    return EXIT_FAILURE;
  }

  /* Upstream LaBRADOR writes diagnostics to stdout; keep stdout valid CSV. */
  fflush(stdout);
  stdout_copy = dup(STDOUT_FILENO);
  null_output = open("/dev/null", O_WRONLY);
  if (stdout_copy < 0 || null_output < 0 ||
      dup2(null_output, STDOUT_FILENO) < 0)
    goto end;

  start = now_seconds();
  if (acc_setup(&pp, universe_size, setup_seed) != VT_OK)
    goto end;
  setup_s = now_seconds() - start;
  if (pp.tree.depth != VA_TARGET_DEPTH) {
    fprintf(stderr, "%s expected depth %d, got %zu\n", VA_PROFILE_NAME,
            VA_TARGET_DEPTH, pp.tree.depth);
    goto end;
  }

  matrix_elements = public_matrix_ring_elements();
  if (!checked_mul(matrix_elements, VA_RING_DEGREE * QBYTES,
                   &explicit_matrix_bytes) ||
      !checked_mul(matrix_elements, sizeof(polx), &expanded_pp_ram) ||
      !checked_add(expanded_pp_ram, sizeof(pp), &expanded_pp_ram) ||
      !checked_add(expanded_pp_ram,
                   (pp.tree.depth + 1U) * sizeof(vt_value),
                   &expanded_pp_ram))
    goto end;

  start = now_seconds();
  if (path_fixture_init(&fixture, &pp, x, ACC_NONMEMBERSHIP, &root) !=
      VT_OK)
    goto end;
  fixture_init_s = now_seconds() - start;

  start = now_seconds();
  if (path_fixture_update(&fixture, &pp, ACC_MEMBERSHIP, &root,
                          add_level_commit_s) != VT_OK)
    goto end;
  add_s = now_seconds() - start;
  if (witness_generate(&pp, &fixture, &member, &member_metrics) != VT_OK ||
      witness_measure_and_check(&pp, &root, x, &member, ACC_MEMBERSHIP,
                                &member_metrics) != VT_OK)
    goto end;

  start = now_seconds();
  if (path_fixture_update(&fixture, &pp, ACC_NONMEMBERSHIP, &root,
                          delete_level_commit_s) != VT_OK)
    goto end;
  delete_s = now_seconds() - start;
  if (witness_generate(&pp, &fixture, &nonmember,
                       &nonmember_metrics) != VT_OK ||
      witness_measure_and_check(&pp, &root, x, &nonmember,
                                ACC_NONMEMBERSHIP,
                                &nonmember_metrics) != VT_OK)
    goto end;

  fflush(stdout);
  if (dup2(stdout_copy, STDOUT_FILENO) < 0)
    goto end;
  close(stdout_copy);
  stdout_copy = -1;
  close(null_output);
  null_output = -1;

  if (print_csv_header)
    print_header();
  printf("%s,%" PRIu64 ",%d,%d,%d,%d,%d,%d,%d,%d,"
         "%" PRIu64 ",%d,%" PRIu64 ",%d,"
         "%" PRIu64 ",%zu,%zu,%zu,%zu,%zu,%zu,%d,%zu,%zu,"
         "%.9f,%.9f,%.9f",
         VA_PROFILE_NAME, VA_Q, VA_RING_DEGREE, VA_KAPPA, VA_ARITY,
         VA_INNER_WIDTH, VA_BLOCKS, VA_INNER_RANK, VA_OUTER_RANK,
         VA_RANDOMNESS_LEN, UINT64_C(1) << VA_INNER_BASE_LOG,
         VA_INNER_DIGITS, UINT64_C(1) << VA_OUTER_BASE_LOG,
         VA_OUTER_DIGITS, universe_size, pp.tree.depth,
         member.proof_count, member.intermediate_count,
         (size_t)VA_HAT_T_LEN + VA_RANDOMNESS_LEN + VA_S_BLOCK_LEN,
         matrix_elements, explicit_matrix_bytes, VT_SEED_BYTES,
         expanded_pp_ram, (size_t)VA_COMMITMENT_BYTES, setup_s,
         fixture_init_s, add_s);
  print_level_doubles(add_level_commit_s);
  printf(",%.9f,%.9f,%zu,%zu,%zu", member_metrics.prove_s,
         member_metrics.verify_s, member_metrics.proof_bytes,
         member_metrics.commitment_bytes, member_metrics.wire_bytes);
  print_level_doubles(member_metrics.level_prove_s);
  print_level_doubles(member_metrics.level_verify_s);
  print_level_sizes(member_metrics.level_proof_bytes);
  printf(",%.9f", delete_s);
  print_level_doubles(delete_level_commit_s);
  printf(",%.9f,%.9f,%zu,%zu,%zu", nonmember_metrics.prove_s,
         nonmember_metrics.verify_s, nonmember_metrics.proof_bytes,
         nonmember_metrics.commitment_bytes, nonmember_metrics.wire_bytes);
  print_level_doubles(nonmember_metrics.level_prove_s);
  print_level_doubles(nonmember_metrics.level_verify_s);
  print_level_sizes(nonmember_metrics.level_proof_bytes);
  putchar('\n');
  ret = EXIT_SUCCESS;

end:
  if (stdout_copy >= 0) {
    fflush(stdout);
    (void)dup2(stdout_copy, STDOUT_FILENO);
    close(stdout_copy);
  }
  if (null_output >= 0)
    close(null_output);
  if (ret != EXIT_SUCCESS)
    fprintf(stderr, "%s benchmark failed\n", VA_PROFILE_NAME);
  acc_witness_clear(&nonmember);
  acc_witness_clear(&member);
  path_fixture_clear(&fixture);
  acc_public_parameters_clear(&pp);
  return ret;
}
