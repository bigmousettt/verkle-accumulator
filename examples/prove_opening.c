#include <stdio.h>
#include <stdlib.h>

#include "verkle_accumulator/vc.h"

int main(void) {
  uint8_t a[16], b[16], e[16];
  static const uint8_t randomness_seed[16] = "opening-random";
  uint32_t *message = malloc(VA_MESSAGE_SCALARS * sizeof(*message));
  va_context ctx = {0};
  va_commitment vc_commitment;
  va_prover_state state = {0};
  va_opening_relation opening = {0};
  prncplstmnt verifier_statement = {0};
  composite composite_proof = {0};
  const size_t coordinate = VA_ARITY / 2U + 3U;
  size_t i;
  int ret = EXIT_FAILURE;

  if (message == NULL)
    goto end;
  for (i = 0; i < VA_MESSAGE_SCALARS; ++i)
    message[i] = (uint32_t)((17 * i + 42) % VA_Q);
  va_default_seeds(a, b, e);
  if (va_context_init(&ctx, a, b, e) != 0 ||
      va_commit(&ctx, message, randomness_seed, &vc_commitment, &state) != 0 ||
      va_open(&opening, &ctx, &vc_commitment, &state, message, coordinate) !=
          0 ||
      va_relation_verify(&opening) != 0)
    goto end;

  puts("Generating a non-interactive composite LaBRADOR proof...");
  if (va_prove(&composite_proof, &opening) != 0 ||
      va_statement_init(&verifier_statement, &ctx, &vc_commitment, coordinate,
                        opening.value) != 0 ||
      va_verify(&composite_proof, &verifier_statement) != 0)
    goto end;
  printf("%s proof verified; estimated encoded size: %.2f KiB\n",
         VA_PROFILE_NAME, composite_proof.size);
  ret = EXIT_SUCCESS;

end:
  free_composite(&composite_proof);
  free_prncplstmnt(&verifier_statement);
  va_opening_relation_clear(&opening);
  va_prover_state_clear(&state);
  va_context_clear(&ctx);
  free(message);
  return ret;
}
