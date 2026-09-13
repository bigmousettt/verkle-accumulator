#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "verkle_accumulator/tree.h"

static int value_equal(const vt_value *left, const vt_value *right) {
  return memcmp(left, right, sizeof(*left)) == 0;
}

int main(void) {
  static const uint8_t setup_seed[VT_SEED_BYTES] = "VT-setup-seed-for-tests-v1";
  static const uint8_t build_seed[VT_SEED_BYTES] = "VT-build-seed-for-tests-v1";
  static const uint64_t initial_set[] = {0, 4095, 4096};
  vt_public_parameters pp = {0};
  vt_state state = {0};
  va_commitment root, updated_root, old_right_node;
  va_opening_relation opening = {0};
  vt_value expected, opened;
  uint16_t path[2];
  int ret = EXIT_FAILURE;

  if (vt_setup(&pp, 4097, setup_seed) != VT_OK || pp.depth != 2)
    goto end;
  if (vt_path(&pp, 4096, path, 2) != VT_OK || path[0] != 1 || path[1] != 0)
    goto end;
  if (vt_build(&pp, initial_set,
               sizeof(initial_set) / sizeof(initial_set[0]), build_seed,
               &root, &state) != VT_OK)
    goto end;
  if (state.node_counts[0] != 1 || state.node_counts[1] != 2 ||
      vt_get_leaf(&state, 0)->membership != 1 ||
      vt_get_leaf(&state, 1)->membership != 0 ||
      vt_get_leaf(&state, 4096)->membership != 1)
    goto end;

  vt_hash_leaf(&expected, 1, 4096);
  if (!value_equal(&expected, &vt_get_leaf(&state, 4096)->value))
    goto end;
  if (vt_open_node(&opening, &pp, &state, 1, 1, 0) != VT_OK ||
      va_relation_verify(&opening) != 0)
    goto end;
  va_opening_relation_clear(&opening);
  vt_hash_node(&expected, 1, &vt_get_node(&state, 1, 1)->commitment);
  if (vt_open_node(&opening, &pp, &state, 0, 0, 1) != VT_OK ||
      va_relation_verify(&opening) != 0)
    goto end;
  memcpy(opened.scalar, opening.value, sizeof(opened.scalar));
  if (!value_equal(&expected, &opened))
    goto end;
  va_opening_relation_clear(&opening);

  old_right_node = vt_get_node(&state, 1, 1)->commitment;
  if (vt_upd(&pp, 1, &root, &state, VT_ADD, &updated_root) != VT_OK ||
      vt_get_leaf(&state, 1)->membership != 1 ||
      va_commitment_equal(&root, &updated_root) ||
      !va_commitment_equal(&old_right_node,
                           &vt_get_node(&state, 1, 1)->commitment))
    goto end;
  if (vt_open_node(&opening, &pp, &state, 1, 0, 1) != VT_OK ||
      va_relation_verify(&opening) != 0)
    goto end;
  va_opening_relation_clear(&opening);
  root = updated_root;
  if (vt_upd(&pp, 1, &root, &state, VT_ADD, &updated_root) !=
      VT_ERR_ILLEGAL_UPDATE)
    goto end;
  if (vt_upd(&pp, 4096, &root, &state, VT_DELETE, &updated_root) != VT_OK ||
      vt_get_leaf(&state, 4096)->membership != 0 ||
      va_commitment_equal(&root, &updated_root))
    goto end;
  if (vt_open_node(&opening, &pp, &state, 1, 1, 0) != VT_OK ||
      va_relation_verify(&opening) != 0)
    goto end;

  puts("VT.Setup, VT.Build and VT.Upd: all tests passed");
  ret = EXIT_SUCCESS;

end:
  va_opening_relation_clear(&opening);
  vt_state_clear(&state);
  vt_public_parameters_clear(&pp);
  return ret;
}
