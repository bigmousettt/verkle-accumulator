#include "verkle_accumulator/vc.h"

#include <stdlib.h>
#include <string.h>

#include "fips202.h"
#include "polz.h"

enum {
  VA_WITNESS_HAT_T = 0,
  VA_WITNESS_RANDOMNESS = 1,
  VA_WITNESS_S = 2
};

static void *va_aligned_calloc(size_t count, size_t size) {
  const size_t bytes = count * size;
  void *p = aligned_alloc(64, (bytes + 63U) & ~(size_t)63U);
  if (p != NULL)
    memset(p, 0, bytes);
  return p;
}

void va_default_seeds(uint8_t a[16], uint8_t b[16], uint8_t e[16]) {
  static const uint8_t a0[16] = "VA-" VA_PROFILE_NAME "-inner-A";
  static const uint8_t b0[16] = "VA-" VA_PROFILE_NAME "-outer-B";
  static const uint8_t e0[16] = "VA-" VA_PROFILE_NAME "-random-E";
  memcpy(a, a0, 16);
  memcpy(b, b0, 16);
  memcpy(e, e0, 16);
}

int va_context_init(va_context *ctx, const uint8_t a[16],
                    const uint8_t b[16], const uint8_t e[16]) {
  const size_t alen = (size_t)VA_INNER_RANK * VA_S_BLOCK_LEN;
  const size_t blen = (size_t)VA_OUTER_RANK * VA_HAT_T_LEN;
  const size_t elen = (size_t)VA_OUTER_RANK * VA_RANDOMNESS_LEN;

  if (ctx == NULL || a == NULL || b == NULL || e == NULL)
    return 1;
  memset(ctx, 0, sizeof(*ctx));
  memcpy(ctx->a_seed, a, 16);
  memcpy(ctx->b_seed, b, 16);
  memcpy(ctx->e_seed, e, 16);
  ctx->a = va_aligned_calloc(alen, sizeof(polx));
  ctx->b = va_aligned_calloc(blen, sizeof(polx));
  ctx->e = va_aligned_calloc(elen, sizeof(polx));
  if (ctx->a == NULL || ctx->b == NULL || ctx->e == NULL) {
    va_context_clear(ctx);
    return 2;
  }
  polxvec_almostuniform(ctx->a, alen, ctx->a_seed, 0);
  polxvec_almostuniform(ctx->b, blen, ctx->b_seed, 0);
  polxvec_almostuniform(ctx->e, elen, ctx->e_seed, 0);
  return 0;
}

void va_context_clear(va_context *ctx) {
  if (ctx == NULL)
    return;
  free(ctx->a);
  free(ctx->b);
  free(ctx->e);
  memset(ctx, 0, sizeof(*ctx));
}

static void matrix_vector_mul(polx *out, const polx *matrix, size_t rows,
                              size_t cols, const polx *vector) {
  size_t row;
  for (row = 0; row < rows; ++row)
    polxvec_sprod(&out[row], &matrix[row * cols], vector, cols);
}

static void add_matrix_vector_mul(polx *out, const polx *matrix, size_t rows,
                                  size_t cols, const polx *vector) {
  size_t row;
  for (row = 0; row < rows; ++row)
    polxvec_sprod_add(&out[row], &matrix[row * cols], vector, cols);
}

int va_commit(const va_context *ctx, const uint32_t message[VA_MESSAGE_SCALARS],
              const uint8_t randomness_seed[16], va_commitment *vc_commitment,
              va_prover_state *state) {
  const size_t message_rings = (size_t)VA_BLOCKS * VA_INNER_WIDTH;
  int64_t *raw = NULL;
  polx *message_x = NULL;
  polx *s_x = NULL;
  polx t[VA_INNER_RANK];
  polx hat_t_x[VA_HAT_T_LEN];
  polx randomness_x[VA_RANDOMNESS_LEN];
  size_t i, block;
  int ret = 0;

  if (ctx == NULL || message == NULL || randomness_seed == NULL ||
      vc_commitment == NULL || state == NULL)
    return 1;
  memset(state, 0, sizeof(*state));
  raw = calloc(VA_MESSAGE_SCALARS, sizeof(*raw));
  message_x = va_aligned_calloc(message_rings, sizeof(*message_x));
  s_x = va_aligned_calloc((size_t)VA_BLOCKS * VA_S_BLOCK_LEN, sizeof(*s_x));
  state->s = va_aligned_calloc((size_t)VA_BLOCKS * VA_S_BLOCK_LEN,
                               sizeof(*state->s));
  state->hat_t = va_aligned_calloc(VA_HAT_T_LEN, sizeof(*state->hat_t));
  state->randomness = va_aligned_calloc(VA_RANDOMNESS_LEN,
                                        sizeof(*state->randomness));
  if (raw == NULL || message_x == NULL || s_x == NULL || state->s == NULL ||
      state->hat_t == NULL || state->randomness == NULL) {
    ret = 2;
    goto end;
  }
  for (i = 0; i < VA_MESSAGE_SCALARS; ++i) {
    if ((uint64_t)message[i] >= VA_Q) {
      ret = 3;
      goto end;
    }
    raw[i] = message[i];
  }
  polxvec_fromint64vec(message_x, message_rings, 1, raw);

  for (block = 0; block < VA_BLOCKS; ++block) {
    const size_t soff = block * VA_S_BLOCK_LEN;
    const size_t hoff = block * VA_INNER_RANK * VA_OUTER_DIGITS;
    polxvec_decompose(&state->s[soff],
                      &message_x[block * VA_INNER_WIDTH], VA_INNER_WIDTH,
                      VA_INNER_DIGITS, VA_INNER_BASE_LOG);
    polxvec_frompolyvec(&s_x[soff], &state->s[soff], VA_S_BLOCK_LEN);
    matrix_vector_mul(t, ctx->a, VA_INNER_RANK, VA_S_BLOCK_LEN, &s_x[soff]);
    polxvec_refresh(t, VA_INNER_RANK);
    polxvec_decompose(&state->hat_t[hoff], t, VA_INNER_RANK,
                      VA_OUTER_DIGITS, VA_OUTER_BASE_LOG);
  }

  polxvec_frompolyvec(hat_t_x, state->hat_t, VA_HAT_T_LEN);
  polyvec_ternary(state->randomness, VA_RANDOMNESS_LEN, randomness_seed, 0);
  polxvec_frompolyvec(randomness_x, state->randomness, VA_RANDOMNESS_LEN);
  matrix_vector_mul(vc_commitment->u, ctx->b, VA_OUTER_RANK, VA_HAT_T_LEN,
                    hat_t_x);
  polxvec_refresh(vc_commitment->u, VA_OUTER_RANK);
  add_matrix_vector_mul(vc_commitment->u, ctx->e, VA_OUTER_RANK,
                        VA_RANDOMNESS_LEN, randomness_x);
  polxvec_refresh(vc_commitment->u, VA_OUTER_RANK);

end:
  free(raw);
  free(message_x);
  free(s_x);
  if (ret != 0)
    va_prover_state_clear(state);
  return ret;
}

void va_prover_state_clear(va_prover_state *state) {
  if (state == NULL)
    return;
  free(state->s);
  free(state->hat_t);
  free(state->randomness);
  memset(state, 0, sizeof(*state));
}

static void polx_to_raw(int64_t out[N], const polx *in) {
  zz coefficient;
  size_t i, j;
  for (i = 0; i < N; ++i) {
    int64_t value = 0;
    polx_getcoeff(&coefficient, in, (int)i);
    for (j = 0; j < L; ++j)
      value += (int64_t)coefficient.limbs[j] << (14U * j);
    out[i] = value;
  }
}

static int set_full_constraint(prncplstmnt *st, size_t ci, size_t nz,
                               const size_t idx[], const size_t lengths[],
                               const polx *coeffs[], const polx *rhs) {
  size_t i, j, total = 0, off = 0;
  int64_t *phi;
  int64_t b[N];
  int ret;
  for (i = 0; i < nz; ++i)
    total += lengths[i];
  phi = calloc(total * N, sizeof(*phi));
  if (phi == NULL)
    return 1;
  for (i = 0; i < nz; ++i) {
    for (j = 0; j < lengths[i]; ++j)
      polx_to_raw(&phi[(off + j) * N], &coeffs[i][j]);
    off += lengths[i];
  }
  if (rhs != NULL)
    polx_to_raw(b, rhs);
  else
    memset(b, 0, sizeof(b));
  ret = set_prncplstmnt_lincnst_raw(st, ci, nz, idx, lengths, 1, phi, b);
  free(phi);
  return ret;
}

static int set_constant_constraint(prncplstmnt *st, size_t ci, size_t idx,
                                   size_t length, const polx *coeffs,
                                   uint32_t rhs) {
  const size_t indices[1] = {idx};
  const size_t lengths[1] = {length};
  const polx *vectors[1] = {coeffs};
  polx b;
  int ret;
  polx_monomial(&b, rhs, 0);
  ret = set_full_constraint(st, ci, 1, indices, lengths, vectors, &b);
  if (ret == 0) {
    /* Upstream's raw helper rejects deg=0 through its length check, while
     * the internal relation, prover and verifier explicitly support it. */
    st->cnst[ci].deg = 0;
  }
  return ret;
}

static void derive_batch_seed(uint8_t seed[16], const va_context *ctx,
                              const va_commitment *vc_commitment,
                              size_t coordinate,
                              const uint32_t value[VA_KAPPA]) {
  static const uint8_t domain[] =
      "VA-" VA_PROFILE_NAME "-full-relation-v1";
  enum { DOMAIN_BYTES = sizeof(domain) - 1U };
  uint8_t transcript[DOMAIN_BYTES + 3 * 16 + 8 + VA_KAPPA * 4 +
                     VA_OUTER_RANK * N * QBYTES];
  size_t off = 0, i, j;
  polz z;

  memcpy(&transcript[off], domain, DOMAIN_BYTES);
  off += DOMAIN_BYTES;
  memcpy(&transcript[off], ctx->a_seed, 16);
  off += 16;
  memcpy(&transcript[off], ctx->b_seed, 16);
  off += 16;
  memcpy(&transcript[off], ctx->e_seed, 16);
  off += 16;
  for (j = 0; j < 8; ++j)
    transcript[off++] = (uint8_t)(coordinate >> (8U * j));
  for (i = 0; i < VA_KAPPA; ++i)
    for (j = 0; j < 4; ++j)
      transcript[off++] = (uint8_t)(value[i] >> (8U * j));
  for (i = 0; i < VA_OUTER_RANK; ++i) {
    polz_frompolx(&z, &vc_commitment->u[i]);
    polz_bitpack(&transcript[off], &z);
    off += N * QBYTES;
  }
  shake128(seed, 16, transcript, off);
}

int va_statement_init(prncplstmnt *principal, const va_context *ctx,
                      const va_commitment *vc_commitment, size_t coordinate,
                      const uint32_t value[VA_KAPPA]) {
  const size_t witness_lengths[3] = {
      VA_HAT_T_LEN, VA_RANDOMNESS_LEN, VA_S_BLOCK_LEN};
  const uint64_t betasq =
      (uint64_t)VA_HAT_T_LEN * N * 64U * 64U +
      (uint64_t)VA_S_BLOCK_LEN * N * 8U * 8U +
      (uint64_t)VA_RANDOMNESS_LEN * N;
  const size_t block = coordinate / (VA_INNER_WIDTH * N / VA_KAPPA);
  const size_t local = coordinate % (VA_INNER_WIDTH * N / VA_KAPPA);
  const size_t message_ring = (local * VA_KAPPA) / N;
  const size_t first_coeff = (local * VA_KAPPA) % N;
  size_t ci = 0, row, digit, h;
  int ret;

  if (principal == NULL || ctx == NULL || vc_commitment == NULL || value == NULL ||
      coordinate >= VA_ARITY)
    return 1;
  memset(principal, 0, sizeof(*principal));
  for (h = 0; h < VA_KAPPA; ++h)
    if ((uint64_t)value[h] >= VA_Q)
      return 2;
  ret = init_prncplstmnt_raw(principal, 3, witness_lengths, betasq,
                             VA_CONSTRAINTS, 0);
  if (ret != 0)
    return 3;

  {
    const size_t idx[3] = {VA_WITNESS_HAT_T, VA_WITNESS_RANDOMNESS,
                           VA_WITNESS_S};
    const size_t lengths[3] = {VA_HAT_T_LEN, VA_RANDOMNESS_LEN,
                               VA_S_BLOCK_LEN};
    polx *hat_coeffs = va_aligned_calloc(VA_HAT_T_LEN, sizeof(*hat_coeffs));
    polx *randomness_coeffs =
        va_aligned_calloc(VA_RANDOMNESS_LEN, sizeof(*randomness_coeffs));
    polx *s_coeffs = va_aligned_calloc(VA_S_BLOCK_LEN, sizeof(*s_coeffs));
    polx challenges[VA_OUTER_RANK + VA_INNER_RANK];
    polx rhs;
    polx gadget;
    uint8_t batch_seed[16];
    const polx *coeffs[3];

    if (hat_coeffs == NULL || randomness_coeffs == NULL || s_coeffs == NULL) {
      free(hat_coeffs);
      free(randomness_coeffs);
      free(s_coeffs);
      ret = 4;
      goto err;
    }
    polxvec_setzero(&rhs, 1);
    derive_batch_seed(batch_seed, ctx, vc_commitment, coordinate, value);
    polxvec_almostuniform(challenges, VA_OUTER_RANK + VA_INNER_RANK,
                          batch_seed, 0);

    for (row = 0; row < VA_OUTER_RANK; ++row) {
      polxvec_polx_mul_add(hat_coeffs, &challenges[row],
                          &ctx->b[row * VA_HAT_T_LEN], VA_HAT_T_LEN);
      polxvec_polx_mul_add(randomness_coeffs, &challenges[row],
                          &ctx->e[row * VA_RANDOMNESS_LEN],
                          VA_RANDOMNESS_LEN);
      polx_mul_add(&rhs, &challenges[row], &vc_commitment->u[row]);
    }
    for (row = 0; row < VA_INNER_RANK; ++row) {
      const polx *challenge = &challenges[VA_OUTER_RANK + row];
      polxvec_polx_mul_add(s_coeffs, challenge,
                          &ctx->a[row * VA_S_BLOCK_LEN], VA_S_BLOCK_LEN);
      for (digit = 0; digit < VA_OUTER_DIGITS; ++digit) {
        const size_t pos = block * VA_INNER_RANK * VA_OUTER_DIGITS +
                           digit * VA_INNER_RANK + row;
        polx_monomial(&gadget,
                      -((int64_t)1 << (digit * VA_OUTER_BASE_LOG)), 0);
        polx_mul_add(&hat_coeffs[pos], challenge, &gadget);
      }
    }
    coeffs[0] = hat_coeffs;
    coeffs[1] = randomness_coeffs;
    coeffs[2] = s_coeffs;
    ret = set_full_constraint(principal, ci++, 3, idx, lengths, coeffs, &rhs);
    free(hat_coeffs);
    free(randomness_coeffs);
    free(s_coeffs);
    if (ret != 0)
      goto err;
  }

  for (h = 0; h < VA_KAPPA; ++h, ++ci) {
    const size_t coeff_index = first_coeff + h;
    polx *coeffs = va_aligned_calloc(VA_S_BLOCK_LEN, sizeof(*coeffs));
    if (coeffs == NULL) {
      ret = 5;
      goto err;
    }
    for (digit = 0; digit < VA_INNER_DIGITS; ++digit) {
      const size_t pos = digit * VA_INNER_WIDTH + message_ring;
      const int64_t scale = (int64_t)1 << (digit * VA_INNER_BASE_LOG);
      if (coeff_index == 0)
        polx_monomial(&coeffs[pos], scale, 0);
      else
        polx_monomial(&coeffs[pos], -scale, N - (int)coeff_index);
    }
    ret = set_constant_constraint(principal, ci, VA_WITNESS_S,
                                  VA_S_BLOCK_LEN, coeffs, value[h]);
    free(coeffs);
    if (ret != 0)
      goto err;
  }
  return 0;

err:
  free_prncplstmnt(principal);
  return 10 + ret;
}

int va_open(va_opening_relation *opening, const va_context *ctx,
            const va_commitment *vc_commitment, const va_prover_state *state,
            const uint32_t message[VA_MESSAGE_SCALARS], size_t coordinate) {
  const size_t witness_lengths[3] = {
      VA_HAT_T_LEN, VA_RANDOMNESS_LEN, VA_S_BLOCK_LEN};
  const size_t block = coordinate / (VA_INNER_WIDTH * N / VA_KAPPA);
  size_t h;
  int ret;
  if (opening == NULL || state == NULL || message == NULL ||
      state->s == NULL || state->hat_t == NULL || state->randomness == NULL ||
      coordinate >= VA_ARITY)
    return 1;
  memset(opening, 0, sizeof(*opening));
  for (h = 0; h < VA_KAPPA; ++h)
    opening->value[h] = message[coordinate * VA_KAPPA + h];
  ret = va_statement_init(&opening->statement, ctx, vc_commitment, coordinate,
                          opening->value);
  if (ret != 0)
    return 2;
  init_witness_raw(&opening->witness, 3, witness_lengths);
  polyvec_copy(opening->witness.s[VA_WITNESS_HAT_T], state->hat_t,
               VA_HAT_T_LEN);
  polyvec_copy(opening->witness.s[VA_WITNESS_RANDOMNESS], state->randomness,
               VA_RANDOMNESS_LEN);
  polyvec_copy(opening->witness.s[VA_WITNESS_S],
               &state->s[block * VA_S_BLOCK_LEN], VA_S_BLOCK_LEN);
  for (h = 0; h < 3; ++h)
    opening->witness.normsq[h] =
        polyvec_sprodz(opening->witness.s[h], opening->witness.s[h],
                       opening->witness.n[h]);
  return 0;
}

void va_opening_relation_clear(va_opening_relation *opening) {
  if (opening == NULL)
    return;
  free_prncplstmnt(&opening->statement);
  free_witness(&opening->witness);
  memset(opening, 0, sizeof(*opening));
}

int va_relation_verify(const va_opening_relation *opening) {
  return opening == NULL ? 1
                         : principle_verify(&opening->statement,
                                            &opening->witness);
}

int va_prove(composite *composite_proof, const va_opening_relation *opening) {
  if (composite_proof == NULL || opening == NULL)
    return 1;
  memset(composite_proof, 0, sizeof(*composite_proof));
  return composite_prove_principle(composite_proof, &opening->statement,
                                   &opening->witness);
}

int va_verify(const composite *composite_proof, const prncplstmnt *principal) {
  return composite_proof == NULL || principal == NULL
             ? 1
             : composite_verify_principle(composite_proof, principal);
}

void va_commitment_encode(uint8_t out[VA_COMMITMENT_BYTES],
                          const va_commitment *vc_commitment) {
  size_t row;
  polz z;

  if (out == NULL || vc_commitment == NULL)
    return;
  for (row = 0; row < VA_OUTER_RANK; ++row) {
    polz_frompolx(&z, &vc_commitment->u[row]);
    polz_bitpack(&out[row * VA_RING_DEGREE * QBYTES], &z);
  }
}

int va_commitment_decode(va_commitment *vc_commitment,
                         const uint8_t in[VA_COMMITMENT_BYTES]) {
  __attribute__((aligned(64))) uint8_t packed[VA_RING_DEGREE * QBYTES];
  polz z;
  size_t coefficient, row;

  if (vc_commitment == NULL || in == NULL)
    return 1;
  for (row = 0; row < VA_OUTER_RANK; ++row) {
    const uint8_t *encoded = &in[row * VA_RING_DEGREE * QBYTES];
    for (coefficient = 0; coefficient < VA_RING_DEGREE; ++coefficient) {
      const uint8_t *p = &encoded[coefficient * QBYTES];
      const uint64_t value = (uint64_t)p[0] | (uint64_t)p[1] << 8U |
                             (uint64_t)p[2] << 16U |
                             (uint64_t)p[3] << 24U;
      if (value >= VA_Q)
        return 2;
    }
    memcpy(packed, encoded, sizeof(packed));
    polz_bitunpack(&z, packed);
    polz_topolx(&vc_commitment->u[row], &z);
  }
  return 0;
}

int va_commitment_equal(const va_commitment *left,
                        const va_commitment *right) {
  uint8_t left_bytes[VA_COMMITMENT_BYTES];
  uint8_t right_bytes[VA_COMMITMENT_BYTES];

  if (left == NULL || right == NULL)
    return 0;
  va_commitment_encode(left_bytes, left);
  va_commitment_encode(right_bytes, right);
  return memcmp(left_bytes, right_bytes, sizeof(left_bytes)) == 0;
}
