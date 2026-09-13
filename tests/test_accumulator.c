#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "verkle_accumulator/accumulator.h"

int main(void) {
  static const uint8_t setup_seed[VT_SEED_BYTES] = "ACC-setup-seed-for-tests-v1";
  static const uint8_t build_seed[VT_SEED_BYTES] = "ACC-build-seed-for-tests-v1";
  static const uint64_t initial_set[] = {1, 4096};
  acc_public_parameters pp = {0};
  acc_state state = {0};
  acc_value acc, new_acc;
  acc_witness member_witness = {0};
  acc_witness nonmember_witness = {0};
  acc_witness decoded_witness = {0};
  acc_witness loaded_witness = {0};
  uint8_t *encoded = NULL;
  uint8_t *encoded_again = NULL;
  size_t encoded_size = 0, written = 0, rewritten = 0;
  static const char witness_path[] = "build/test-member.vaw";
  int ret = EXIT_FAILURE;

  if (acc_setup(&pp, 4097, setup_seed) != VT_OK || pp.tree.depth != 2)
    goto end;
  if (acc_eval(&pp, initial_set,
               sizeof(initial_set) / sizeof(initial_set[0]), build_seed,
               &acc, &state) != VT_OK || state.set_size != 2 ||
      !acc_contains(&state, 4096))
    goto end;

  puts("Generating a depth-two membership witness...");
  if (acc_wit(&pp, &acc, &state, 4096, &member_witness) != VT_OK ||
      member_witness.depth != 2 || member_witness.proof_count != 2 ||
      member_witness.intermediate_count != 1 ||
      acc_verify(&pp, &acc, 4096, &member_witness, ACC_MEMBERSHIP) != VT_OK ||
      acc_verify(&pp, &acc, 4096, &member_witness, ACC_NONMEMBERSHIP) == VT_OK)
    goto end;
  printf("Membership witness estimated size: %.2f KiB\n",
         acc_witness_estimated_kib(&member_witness));

  if (acc_witness_encoded_size(&member_witness, &encoded_size) != VT_OK)
    goto end;
  encoded = malloc(encoded_size);
  encoded_again = malloc(encoded_size);
  if (encoded == NULL || encoded_again == NULL ||
      acc_witness_encode(encoded, encoded_size, &written, &member_witness) !=
          VT_OK ||
      written != encoded_size ||
      acc_witness_decode(&pp, &decoded_witness, encoded, encoded_size) !=
          VT_OK ||
      acc_verify(&pp, &acc, 4096, &decoded_witness, ACC_MEMBERSHIP) != VT_OK ||
      acc_witness_encode(encoded_again, encoded_size, &rewritten,
                         &decoded_witness) != VT_OK ||
      rewritten != encoded_size ||
      memcmp(encoded, encoded_again, encoded_size) != 0 ||
      acc_witness_encode(encoded_again, encoded_size - 1U, &rewritten,
                         &decoded_witness) != VT_ERR_OVERFLOW)
    goto end;
  printf("Membership witness canonical wire size: %.2f KiB\n",
         (double)encoded_size / 1024.0);

  if (acc_witness_write_file(witness_path, &member_witness) != VT_OK ||
      acc_witness_read_file(&pp, witness_path, &loaded_witness) != VT_OK ||
      acc_verify(&pp, &acc, 4096, &loaded_witness, ACC_MEMBERSHIP) != VT_OK)
    goto end;
  acc_witness_clear(&loaded_witness);
  if (acc_witness_decode(&pp, &loaded_witness, encoded, encoded_size - 1U) !=
      ACC_ERR_FORMAT)
    goto end;
  encoded[0] ^= 1U;
  if (acc_witness_decode(&pp, &loaded_witness, encoded, encoded_size) !=
      ACC_ERR_FORMAT)
    goto end;
  encoded[0] ^= 1U;
  encoded[encoded_size - 1U] ^= 1U;
  if (acc_witness_decode(&pp, &loaded_witness, encoded, encoded_size) !=
      ACC_ERR_FORMAT)
    goto end;
  encoded[encoded_size - 1U] ^= 1U;
  memset(&encoded[64], 0xff, QBYTES);
  if (acc_witness_decode(&pp, &loaded_witness, encoded, encoded_size) !=
      ACC_ERR_FORMAT)
    goto end;
  va_commitment_encode(&encoded[64],
                       &member_witness.intermediate_commitments[0]);

  {
    const va_commitment saved = member_witness.intermediate_commitments[0];
    member_witness.intermediate_commitments[0] = acc;
    if (acc_verify(&pp, &acc, 4096, &member_witness, ACC_MEMBERSHIP) == VT_OK)
      goto end;
    member_witness.intermediate_commitments[0] = saved;
  }

  if (acc_upd(&pp, &acc, &state, 4096, ACC_NONMEMBERSHIP, &new_acc) != VT_OK ||
      acc_contains(&state, 4096) || state.set_size != 1)
    goto end;
  acc = new_acc;
  if (acc_verify(&pp, &acc, 4096, &member_witness, ACC_MEMBERSHIP) == VT_OK)
    goto end;

  puts("Generating a depth-two non-membership witness...");
  if (acc_wit(&pp, &acc, &state, 4096, &nonmember_witness) != VT_OK ||
      nonmember_witness.depth != 2 || nonmember_witness.proof_count != 2 ||
      nonmember_witness.intermediate_count != 1 ||
      acc_verify(&pp, &acc, 4096, &nonmember_witness,
                 ACC_NONMEMBERSHIP) != VT_OK ||
      acc_verify(&pp, &acc, 4096, &nonmember_witness, ACC_MEMBERSHIP) == VT_OK)
    goto end;
  printf("Non-membership witness estimated size: %.2f KiB\n",
         acc_witness_estimated_kib(&nonmember_witness));

  puts("Accumulator membership and non-membership tests passed");
  ret = EXIT_SUCCESS;

end:
  remove(witness_path);
  free(encoded_again);
  free(encoded);
  acc_witness_clear(&loaded_witness);
  acc_witness_clear(&decoded_witness);
  acc_witness_clear(&nonmember_witness);
  acc_witness_clear(&member_witness);
  acc_state_clear(&state);
  acc_public_parameters_clear(&pp);
  return ret;
}
