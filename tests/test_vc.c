#include <stdio.h>
#include <stdlib.h>

#include "verkle_accumulator/vc.h"

static void fill_message(uint32_t message[VA_MESSAGE_SCALARS]) {
  size_t i;
  for (i = 0; i < VA_MESSAGE_SCALARS; ++i)
    message[i] = (uint32_t)((UINT64_C(2654435761) * (i + 1)) % VA_Q);
}

int main(void) {
  uint8_t a[16], b[16], e[16];
  static const uint8_t randomness_seed[16] = "opening-random";
  uint32_t *message = NULL;
  va_context ctx = {0};
  va_commitment vc_commitment;
  va_prover_state state = {0};
  va_opening_relation opening = {0};
  static const size_t coordinates[] = {0, 7, 8, 511, 512, 1703, 4095};
  size_t i;
  int ret = EXIT_FAILURE;

  message = malloc(VA_MESSAGE_SCALARS * sizeof(*message));
  if (message == NULL)
    goto end;
  fill_message(message);
  va_default_seeds(a, b, e);
  if (va_context_init(&ctx, a, b, e) != 0 ||
      va_commit(&ctx, message, randomness_seed, &vc_commitment, &state) != 0)
    goto end;

  for (i = 0; i < sizeof(coordinates) / sizeof(coordinates[0]); ++i) {
    if (va_open(&opening, &ctx, &vc_commitment, &state, message,
                coordinates[i]) != 0 ||
        va_relation_verify(&opening) != 0)
      goto end;
    va_opening_relation_clear(&opening);
  }

  if (va_open(&opening, &ctx, &vc_commitment, &state, message, 1703) != 0)
    goto end;
  opening.witness.s[2][0].vec->c[0] ^= 1;
  if (va_relation_verify(&opening) == 0) {
    fputs("tampered witness was accepted\n", stderr);
    goto end;
  }
  va_opening_relation_clear(&opening);

  puts("P2 relation: boundary openings accepted; tampering rejected");
  ret = EXIT_SUCCESS;

end:
  va_opening_relation_clear(&opening);
  va_prover_state_clear(&state);
  va_context_clear(&ctx);
  free(message);
  return ret;
}
