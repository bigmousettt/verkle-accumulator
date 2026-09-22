#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#include "jlproj.h"
#include "poly.h"
#include "verkle_accumulator/vc.h"

static int challenge_sampler_self_test(void) {
  static const uint8_t seed[16] = "challenge-check";
  poly challenges[32];
  size_t i, j;

  polyvec_challenge(challenges, 32, seed, 0);
  for (i = 0; i < 32; ++i) {
    unsigned int nonzero = 0;
    unsigned int normsq = 0;

    for (j = 0; j < VA_RING_DEGREE; ++j) {
      const int coefficient = challenges[i].vec->c[j];
      const unsigned int magnitude =
          (unsigned int)(coefficient < 0 ? -coefficient : coefficient);

      if (magnitude != 0)
        ++nonzero;
      if (magnitude > CHALLENGE_GAMMA)
        return -1;
      normsq += magnitude * magnitude;
    }
    if (nonzero != CHALLENGE_WEIGHT || normsq > CHALLENGE_NORMSQ ||
        poly_opnorm(&challenges[i]) > T)
      return -1;
  }
  return 0;
}

static void print_size_array(const size_t *values, size_t length) {
  size_t i;

  putchar('[');
  for (i = 0; i < length; ++i) {
    if (i != 0)
      putchar(',');
    printf("%zu", values[i]);
  }
  putchar(']');
}

static uint64_t witness_normsq(const witness *value) {
  uint64_t result = 0;
  size_t i;

  for (i = 0; i < value->r; ++i)
    result += value->normsq[i];
  return result;
}

static void print_trace(const va_opening_relation *opening,
                        const composite *composite_proof) {
  size_t i;

  puts("NIAOK_TRACE_BEGIN");
  printf("{");
  printf("\"profile\":\"%s\",", VA_PROFILE_NAME);
  printf("\"q\":%" PRIu64 ",", VA_Q);
  printf("\"ring_degree\":%d,", VA_RING_DEGREE);
  printf("\"arity\":%d,", VA_ARITY);
  printf("\"m\":%d,", VA_INNER_WIDTH);
  printf("\"r\":%d,", VA_BLOCKS);
  printf("\"n0\":%d,", VA_INNER_RANK);
  printf("\"n1\":%d,", VA_OUTER_RANK);
  printf("\"mu\":%d,", VA_RANDOMNESS_LEN);
  printf("\"delta0\":%d,", VA_INNER_DIGITS);
  printf("\"delta1\":%d,", VA_OUTER_DIGITS);
  printf("\"challenge_weight\":%d,", CHALLENGE_WEIGHT);
  printf("\"challenge_gamma\":%d,", CHALLENGE_GAMMA);
  printf("\"challenge_normsq\":%d,", CHALLENGE_NORMSQ);
  printf("\"challenge_opnorm\":%d,", T);
  printf("\"implementation_slack\":%.10g,", (double)SLACK);
  printf("\"challenge_sampler_self_test\":true,");
  printf("\"statement_betasq\":%" PRIu64 ",", opening->statement.betasq);
  printf("\"actual_witness_normsq\":%" PRIu64 ",",
         witness_normsq(&opening->witness));
  printf("\"initial_witness_lengths\":");
  print_size_array(opening->witness.n, opening->witness.r);
  printf(",\"composite_layers\":%zu,", composite_proof->l);
  printf("\"estimated_size_kib\":%.10g,", composite_proof->size);
  printf("\"layers\":[");
  for (i = 0; i < composite_proof->l; ++i) {
    const proof *layer = composite_proof->pi[i];
    const comparams *params = layer->cpp;

    if (i != 0)
      putchar(',');
    printf("{");
    printf("\"index\":%zu,", i);
    printf("\"tail\":%d,", layer->tail);
    printf("\"witness_multiplicity\":%zu,", layer->r);
    printf("\"witness_ranks\":");
    print_size_array(layer->n, layer->r);
    printf(",\"witness_decomposition\":");
    print_size_array(layer->nu, layer->r);
    printf(",\"f\":%zu,", params->f);
    printf("\"fu\":%zu,", params->fu);
    printf("\"fg\":%zu,", params->fg);
    printf("\"b_log2\":%zu,", params->b);
    printf("\"bu_log2\":%zu,", params->bu);
    printf("\"bg_log2\":%zu,", params->bg);
    printf("\"kappa\":%zu,", params->kappa);
    printf("\"kappa1\":%zu,", params->kappa1);
    printf("\"u1len\":%zu,", params->u1len);
    printf("\"u2len\":%zu,", params->u2len);
    printf("\"jl_nonce\":%zu,", layer->jlnonce);
    printf("\"projection_normsq\":%" PRIu64 ",",
           jlproj_normsq(layer->p));
    printf("\"output_normsq\":%" PRIu64, layer->normsq);
    printf("}");
  }
  printf("],\"final_witness_lengths\":");
  print_size_array(composite_proof->owt.n, composite_proof->owt.r);
  printf(",\"final_witness_normsq\":%" PRIu64,
         witness_normsq(&composite_proof->owt));
  printf("}\n");
  puts("NIAOK_TRACE_END");
}

int main(void) {
  uint8_t a[16], b[16], e[16];
  static const uint8_t randomness_seed[16] = "niaok-analysis";
  uint32_t *message = NULL;
  va_context context = {0};
  va_commitment vc_commitment;
  va_prover_state state = {0};
  va_opening_relation opening = {0};
  prncplstmnt verifier_statement = {0};
  composite composite_proof = {0};
  const size_t coordinate = VA_ARITY / 2U + 3U;
  size_t i;
  int result = EXIT_FAILURE;

  message = malloc(VA_MESSAGE_SCALARS * sizeof(*message));
  if (message == NULL)
    goto end;
  for (i = 0; i < VA_MESSAGE_SCALARS; ++i)
    message[i] = (uint32_t)((UINT64_C(2654435761) * (i + 1U)) % VA_Q);

  va_default_seeds(a, b, e);
  if (challenge_sampler_self_test() != 0 ||
      va_context_init(&context, a, b, e) != 0 ||
      va_commit(&context, message, randomness_seed, &vc_commitment, &state) != 0 ||
      va_open(&opening, &context, &vc_commitment, &state, message, coordinate) !=
          0 ||
      va_relation_verify(&opening) != 0 ||
      va_prove(&composite_proof, &opening) != 0 ||
      va_statement_init(&verifier_statement, &context, &vc_commitment, coordinate,
                        opening.value) != 0 ||
      va_verify(&composite_proof, &verifier_statement) != 0)
    goto end;

  print_trace(&opening, &composite_proof);
  result = EXIT_SUCCESS;

end:
  free_composite(&composite_proof);
  free_prncplstmnt(&verifier_statement);
  va_opening_relation_clear(&opening);
  va_prover_state_clear(&state);
  va_context_clear(&context);
  free(message);
  return result;
}
