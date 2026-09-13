#define _POSIX_C_SOURCE 200809L

#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "verkle_accumulator/accumulator.h"

enum { VAW1_HEADER_BYTES = 64 };

static double now_seconds(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
    return 0.0;
  return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
}

static int proof_bytes(const acc_witness *proof_bundle, size_t *total) {
  size_t result = 0, level;
  if (proof_bundle == NULL || total == NULL)
    return VT_ERR_ARGUMENT;
  for (level = 0; level < proof_bundle->proof_count; ++level) {
    size_t current;
    if (acc_composite_encoded_size(&proof_bundle->opening_proofs[level],
                                   &current) != VT_OK ||
        result > SIZE_MAX - current)
      return VT_ERR_OVERFLOW;
    result += current;
  }
  *total = result;
  return VT_OK;
}

static int mean_proof_bytes(const acc_witness *proof_bundle, size_t *mean) {
  size_t total;
  if (proof_bundle == NULL || mean == NULL || proof_bundle->proof_count == 0 ||
      proof_bytes(proof_bundle, &total) != VT_OK)
    return VT_ERR_ARGUMENT;
  *mean = (total + proof_bundle->proof_count / 2U) /
          proof_bundle->proof_count;
  return VT_OK;
}

/*
 * This is a path-length projection, not a build at 2^32 leaves. Every level
 * uses the same VC relation, so the mean exact VAW1 composite-proof length
 * from the fully executed depth-two experiment is the relevant byte unit.
 */
static int projected_witness_bytes(const acc_witness *measured,
                                   size_t target_depth, size_t *projected) {
  size_t mean_proof, commitments, proofs;
  if (measured == NULL || projected == NULL || measured->proof_count == 0 ||
      target_depth == 0 || mean_proof_bytes(measured, &mean_proof) != VT_OK)
    return VT_ERR_ARGUMENT;
  if (target_depth - 1U > SIZE_MAX / VA_COMMITMENT_BYTES)
    return VT_ERR_OVERFLOW;
  commitments = (target_depth - 1U) * VA_COMMITMENT_BYTES;
  if (target_depth > SIZE_MAX / mean_proof)
    return VT_ERR_OVERFLOW;
  proofs = target_depth * mean_proof;
  if (VAW1_HEADER_BYTES > SIZE_MAX - commitments ||
      VAW1_HEADER_BYTES + commitments > SIZE_MAX - proofs)
    return VT_ERR_OVERFLOW;
  *projected = VAW1_HEADER_BYTES + commitments + proofs;
  return VT_OK;
}

static void print_header(void) {
  puts("profile,q,ell,kappa,L,m,r,n0,n1,mu,b0,delta0,b1,delta1,"
       "raw_witness_ring_elements,commitment_bytes,target_N,target_depth,"
       "experiment_N,experiment_depth,setup_s,build_s,add_s,member_prove_s,"
       "member_verify_s,member_mean_proof_bytes,member_wire_bytes,"
       "member_target_projected_bytes,delete_s,nonmember_prove_s,"
       "nonmember_verify_s,nonmember_mean_proof_bytes,nonmember_wire_bytes,"
       "nonmember_target_projected_bytes");
}

int main(int argc, char **argv) {
  static const uint8_t setup_seed[VT_SEED_BYTES] =
      "VA-benchmark-setup-seed-v1";
  static const uint8_t build_seed[VT_SEED_BYTES] =
      "VA-benchmark-build-seed-v1";
  static const uint64_t initial_set[] = {1};
  const uint64_t target_n = UINT64_C(1) << 32U;
  const uint64_t experiment_n = (uint64_t)VA_ARITY + 1U;
  const uint64_t x = (uint64_t)VA_ARITY;
  acc_public_parameters pp = {0};
  acc_state state = {0};
  acc_value acc = {0}, updated = {0};
  acc_witness member = {0}, nonmember = {0};
  size_t member_wire = 0, nonmember_wire = 0;
  size_t member_projected = 0, nonmember_projected = 0;
  size_t member_mean_proof = 0, nonmember_mean_proof = 0;
  double start, setup_s, build_s, add_s, member_prove_s, member_verify_s;
  double delete_s, nonmember_prove_s, nonmember_verify_s;
  int stdout_copy = -1, null_output = -1;
  int print_csv_header = 1;
  int ret = EXIT_FAILURE;

  if (argc == 2 && strcmp(argv[1], "--no-header") == 0)
    print_csv_header = 0;
  else if (argc != 1) {
    fprintf(stderr, "usage: benchmark_%s [--no-header]\n", VA_PROFILE_NAME);
    return EXIT_FAILURE;
  }

  /*
   * Upstream LaBRADOR emits diagnostic prose on stdout. Suppress it so this
   * program's stdout is a directly usable CSV stream.
   */
  fflush(stdout);
  stdout_copy = dup(STDOUT_FILENO);
  null_output = open("/dev/null", O_WRONLY);
  if (stdout_copy < 0 || null_output < 0 ||
      dup2(null_output, STDOUT_FILENO) < 0)
    goto end;

  start = now_seconds();
  if (acc_setup(&pp, experiment_n, setup_seed) != VT_OK)
    goto end;
  setup_s = now_seconds() - start;
  if (pp.tree.depth != 2U) {
    fputs("benchmark experiment must have depth two\n", stderr);
    goto end;
  }

  start = now_seconds();
  if (acc_eval(&pp, initial_set, 1, build_seed, &acc, &state) != VT_OK)
    goto end;
  build_s = now_seconds() - start;

  start = now_seconds();
  if (acc_upd(&pp, &acc, &state, x, ACC_MEMBERSHIP, &updated) != VT_OK)
    goto end;
  add_s = now_seconds() - start;
  acc = updated;

  start = now_seconds();
  if (acc_wit(&pp, &acc, &state, x, &member) != VT_OK)
    goto end;
  member_prove_s = now_seconds() - start;
  start = now_seconds();
  if (acc_verify(&pp, &acc, x, &member, ACC_MEMBERSHIP) != VT_OK)
    goto end;
  member_verify_s = now_seconds() - start;
  if (acc_witness_encoded_size(&member, &member_wire) != VT_OK ||
      mean_proof_bytes(&member, &member_mean_proof) != VT_OK ||
      projected_witness_bytes(&member, VA_TARGET_DEPTH, &member_projected) !=
          VT_OK)
    goto end;

  start = now_seconds();
  if (acc_upd(&pp, &acc, &state, x, ACC_NONMEMBERSHIP, &updated) != VT_OK)
    goto end;
  delete_s = now_seconds() - start;
  acc = updated;

  start = now_seconds();
  if (acc_wit(&pp, &acc, &state, x, &nonmember) != VT_OK)
    goto end;
  nonmember_prove_s = now_seconds() - start;
  start = now_seconds();
  if (acc_verify(&pp, &acc, x, &nonmember, ACC_NONMEMBERSHIP) != VT_OK)
    goto end;
  nonmember_verify_s = now_seconds() - start;
  if (acc_witness_encoded_size(&nonmember, &nonmember_wire) != VT_OK ||
      mean_proof_bytes(&nonmember, &nonmember_mean_proof) != VT_OK ||
      projected_witness_bytes(&nonmember, VA_TARGET_DEPTH,
                              &nonmember_projected) != VT_OK)
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
  printf("%s,%" PRIu64 ",%d,%d,%d,%d,%d,%d,%d,%d,%" PRIu64
         ",%d,%" PRIu64 ",%d,%d,%zu,%" PRIu64 ",%d,%" PRIu64
         ",%zu,%.9f,%.9f,%.9f,%.9f,%.9f,%zu,%zu,%zu,%.9f,%.9f,%.9f,"
         "%zu,%zu,%zu\n",
         VA_PROFILE_NAME, VA_Q, VA_RING_DEGREE, VA_KAPPA, VA_ARITY,
         VA_INNER_WIDTH, VA_BLOCKS, VA_INNER_RANK, VA_OUTER_RANK,
         VA_RANDOMNESS_LEN, UINT64_C(1) << VA_INNER_BASE_LOG,
         VA_INNER_DIGITS, UINT64_C(1) << VA_OUTER_BASE_LOG, VA_OUTER_DIGITS,
         VA_HAT_T_LEN + VA_RANDOMNESS_LEN + VA_S_BLOCK_LEN,
         VA_COMMITMENT_BYTES, target_n, VA_TARGET_DEPTH, experiment_n,
         pp.tree.depth, setup_s, build_s, add_s, member_prove_s,
         member_verify_s, member_mean_proof, member_wire, member_projected,
         delete_s, nonmember_prove_s, nonmember_verify_s,
         nonmember_mean_proof, nonmember_wire, nonmember_projected);
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
  acc_state_clear(&state);
  acc_public_parameters_clear(&pp);
  return ret;
}
