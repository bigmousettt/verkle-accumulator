#include "verkle_accumulator/accumulator.h"

#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jlproj.h"

enum {
  ACC_WIRE_VERSION = 1,
  ACC_WIRE_HEADER_BYTES = 64,
  ACC_WIRE_MAX_DEPTH = 64,
  ACC_WIRE_MAX_PROOF_PARTS = 256,
  ACC_WIRE_MAX_POLYNOMIALS = 1 << 20,
  ACC_WIRE_MAX_BYTES = 1 << 29
};

static const uint8_t acc_wire_magic[4] = {'V', 'A', 'W', '1'};

typedef struct {
  uint8_t *data;
  size_t capacity;
  size_t offset;
  int failed;
} wire_writer;

typedef struct {
  const uint8_t *data;
  size_t length;
  size_t offset;
  int failed;
} wire_reader;

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

static void *wire_aligned_calloc(size_t count, size_t size) {
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

static void writer_bytes(wire_writer *writer, const void *source,
                         size_t length) {
  size_t end;
  if (writer->failed || !checked_add(writer->offset, length, &end)) {
    writer->failed = 1;
    return;
  }
  if (writer->data != NULL) {
    if (end > writer->capacity) {
      writer->failed = 1;
      return;
    }
    memcpy(&writer->data[writer->offset], source, length);
  }
  writer->offset = end;
}

static void writer_u8(wire_writer *writer, uint8_t value) {
  writer_bytes(writer, &value, sizeof(value));
}

static void writer_u16(wire_writer *writer, uint16_t value) {
  uint8_t encoded[2] = {(uint8_t)value, (uint8_t)(value >> 8U)};
  writer_bytes(writer, encoded, sizeof(encoded));
}

static void writer_u32(wire_writer *writer, uint32_t value) {
  uint8_t encoded[4];
  size_t i;
  for (i = 0; i < sizeof(encoded); ++i)
    encoded[i] = (uint8_t)(value >> (8U * i));
  writer_bytes(writer, encoded, sizeof(encoded));
}

static void writer_u64(wire_writer *writer, uint64_t value) {
  uint8_t encoded[8];
  size_t i;
  for (i = 0; i < sizeof(encoded); ++i)
    encoded[i] = (uint8_t)(value >> (8U * i));
  writer_bytes(writer, encoded, sizeof(encoded));
}

static void reader_bytes(wire_reader *reader, void *destination,
                         size_t length) {
  size_t end;
  if (reader->failed || !checked_add(reader->offset, length, &end) ||
      end > reader->length) {
    reader->failed = 1;
    return;
  }
  if (destination != NULL)
    memcpy(destination, &reader->data[reader->offset], length);
  reader->offset = end;
}

static uint8_t reader_u8(wire_reader *reader) {
  uint8_t value = 0;
  reader_bytes(reader, &value, sizeof(value));
  return value;
}

static uint16_t reader_u16(wire_reader *reader) {
  uint8_t encoded[2] = {0};
  reader_bytes(reader, encoded, sizeof(encoded));
  return (uint16_t)((uint16_t)encoded[0] | (uint16_t)encoded[1] << 8U);
}

static uint32_t reader_u32(wire_reader *reader) {
  uint8_t encoded[4] = {0};
  uint32_t value = 0;
  size_t i;
  reader_bytes(reader, encoded, sizeof(encoded));
  for (i = 0; i < sizeof(encoded); ++i)
    value |= (uint32_t)encoded[i] << (8U * i);
  return value;
}

static uint64_t reader_u64(wire_reader *reader) {
  uint8_t encoded[8] = {0};
  uint64_t value = 0;
  size_t i;
  reader_bytes(reader, encoded, sizeof(encoded));
  for (i = 0; i < sizeof(encoded); ++i)
    value |= (uint64_t)encoded[i] << (8U * i);
  return value;
}

static int size_to_u32(size_t value, uint32_t *result) {
  if (value > UINT32_MAX || result == NULL)
    return 0;
  *result = (uint32_t)value;
  return 1;
}

static int size_to_u64(size_t value, uint64_t *result) {
  if (result == NULL || (uintmax_t)value > UINT64_MAX)
    return 0;
  *result = (uint64_t)value;
  return 1;
}

static int u64_to_size(uint64_t value, size_t *result) {
  if (result == NULL || value > SIZE_MAX)
    return 0;
  *result = (size_t)value;
  return 1;
}

static int polz_bytes_canonical(const uint8_t packed[N * QBYTES]) {
  size_t coefficient;
  for (coefficient = 0; coefficient < N; ++coefficient) {
    const uint8_t *p = &packed[coefficient * QBYTES];
    const uint64_t value = (uint64_t)p[0] | (uint64_t)p[1] << 8U |
                           (uint64_t)p[2] << 16U |
                           (uint64_t)p[3] << 24U;
    if (value >= VA_Q)
      return 0;
  }
  return 1;
}

static void writer_polz(wire_writer *writer, const polz *value) {
  __attribute__((aligned(64))) uint8_t packed[N * QBYTES];
  if (writer->failed)
    return;
  if (writer->data == NULL) {
    writer_bytes(writer, packed, sizeof(packed));
    return;
  }
  polz_bitpack(packed, value);
  if (!polz_bytes_canonical(packed)) {
    writer->failed = 1;
    return;
  }
  writer_bytes(writer, packed, sizeof(packed));
}

static void reader_polz(wire_reader *reader, polz *value) {
  __attribute__((aligned(64))) uint8_t packed[N * QBYTES];
  reader_bytes(reader, packed, sizeof(packed));
  if (reader->failed || !polz_bytes_canonical(packed)) {
    reader->failed = 1;
    return;
  }
  polz_bitunpack(value, packed);
}

static int proof_output_shape(const proof *item, size_t *witness_parts,
                              size_t *opening_rank, size_t *outer_rank) {
  const comparams *params;
  size_t i, segment = 0, rank = 0, parts = 0, triangular, term;

  if (item == NULL || item->r == 0 || item->r > ACC_WIRE_MAX_PROOF_PARTS ||
      item->n == NULL || item->nu == NULL || item->u1 == NULL ||
      (item->tail != 0 && item->tail != 1))
    return 0;
  params = item->cpp;
  if (params->f == 0 || params->f > 16 || params->fu == 0 ||
      params->fu > 16 || params->fg > 16 || params->b > 63 ||
      params->bu > 63 || params->bg > 63 || params->kappa == 0 ||
      params->kappa > 32 || params->kappa1 > 32 ||
      (params->f - 1U) * params->b > 62 ||
      (params->fu - 1U) * params->bu > 62 ||
      (params->fg != 0 && (params->fg - 1U) * params->bg > 62) ||
      params->u1len > ACC_WIRE_MAX_POLYNOMIALS ||
      params->u2len > ACC_WIRE_MAX_POLYNOMIALS ||
      item->normsq > JLMAXNORMSQ)
    return 0;
  for (i = 0; i < item->r; ++i) {
    if (item->n[i] == 0 || item->n[i] > ACC_WIRE_MAX_POLYNOMIALS ||
        !checked_add(segment, item->n[i], &segment))
      return 0;
    if (item->nu[i] != 0) {
      const size_t current_rank =
          (segment + item->nu[i] - 1U) / item->nu[i];
      if (item->nu[i] > segment ||
          !checked_add(parts, item->nu[i], &parts))
        return 0;
      if (current_rank > rank)
        rank = current_rank;
      segment = 0;
    }
  }
  if (segment != 0 || parts == 0 || parts > ACC_WIRE_MAX_PROOF_PARTS ||
      item->nu[item->r - 1U] == 0 ||
      !checked_add(parts, 1U, &term) ||
      !checked_mul(parts, term, &triangular))
    return 0;
  triangular /= 2U;
  if (item->tail) {
    size_t expected_u1, garbage = params->fg == 0 ? 0 : triangular;
    if (params->kappa1 != 0 || params->fu != 1 || params->fg > 1 ||
        params->u2len != 2U * parts - 1U ||
        !checked_mul(parts, params->kappa, &expected_u1) ||
        !checked_add(expected_u1, garbage, &expected_u1) ||
        params->u1len != expected_u1)
      return 0;
  } else if (params->kappa1 == 0 || params->u1len != params->kappa1 ||
             params->u2len != params->kappa1) {
    return 0;
  }
  if (!checked_mul(parts, params->fu, &term) ||
      !checked_mul(term, params->kappa, &term) ||
      !checked_mul(params->fu + params->fg, triangular, &triangular) ||
      !checked_add(term, triangular, outer_rank))
    return 0;
  *witness_parts = params->f + (item->tail ? 0U : 1U);
  *opening_rank = rank;
  return *witness_parts <= ACC_WIRE_MAX_PROOF_PARTS &&
         rank <= ACC_WIRE_MAX_POLYNOMIALS &&
         *outer_rank <= ACC_WIRE_MAX_POLYNOMIALS;
}

static int projection_valid(const int32_t projection[256]) {
  uint64_t norm = 0;
  size_t i;
  for (i = 0; i < 256; ++i) {
    const int64_t coefficient = projection[i];
    const uint64_t absolute = coefficient < 0
                                  ? (uint64_t)(-coefficient)
                                  : (uint64_t)coefficient;
    uint64_t square;
    if (absolute > JLMAXNORM)
      return 0;
    square = absolute * absolute;
    if (norm > UINT64_MAX - square)
      return 0;
    norm += square;
  }
  return norm <= 256U * JLMAXNORMSQ;
}

static double composite_estimated_kib(const composite *bundle) {
  double size = 0.0;
  size_t i, j;
  for (i = 0; i < bundle->l; ++i) {
    const proof *item = bundle->pi[i];
    uint64_t norm = 0;
    for (j = 0; j < 256; ++j) {
      const int64_t coefficient = item->p[j];
      const uint64_t absolute = coefficient < 0
                                    ? (uint64_t)(-coefficient)
                                    : (uint64_t)coefficient;
      norm += absolute * absolute;
    }
    if (norm != 0)
      size += (log2(sqrt((double)norm)) - 4.0 + 2.05) * 256.0 /
              8192.0;
    size += (double)(item->cpp->u1len + item->cpp->u2len + LIFTS) *
            N * LOGQ / 8192.0;
  }
  for (i = 0; i < bundle->owt.r; ++i) {
    const double average = (double)bundle->owt.normsq[i] /
                           (N * (double)bundle->owt.n[i]);
    if (average != 0.0)
      size += (log2(average) / 2.0 + 2.05) * N *
              bundle->owt.n[i] / 8192.0;
  }
  return size;
}

static int witness_valid(const witness *opening, size_t expected_parts,
                         size_t expected_rank, size_t expected_outer_rank) {
  size_t i, total = 0;
  if (opening == NULL || opening->r != expected_parts || opening->n == NULL ||
      opening->normsq == NULL || opening->s == NULL || opening->s[0] == NULL)
    return 0;
  for (i = 0; i < opening->r; ++i) {
    const size_t expected =
        expected_outer_rank != 0 && i + 1U == opening->r
            ? expected_outer_rank
            : expected_rank;
    int64_t actual_norm;
    if (opening->s[i] == NULL || opening->n[i] == 0 ||
        opening->n[i] > ACC_WIRE_MAX_POLYNOMIALS ||
        opening->n[i] != expected ||
        !checked_add(total, opening->n[i], &total))
      return 0;
    actual_norm =
        polyvec_sprodz(opening->s[i], opening->s[i], opening->n[i]);
    if (actual_norm < 0 || (uint64_t)actual_norm != opening->normsq[i])
      return 0;
  }
  return total <= ACC_WIRE_MAX_POLYNOMIALS;
}

static int composite_valid(const composite *bundle) {
  size_t i, previous_parts = 0, previous_rank = 0, previous_outer = 0;
  if (bundle == NULL || bundle->l == 0 || bundle->l > 16 ||
      bundle->owt.n == NULL)
    return 0;
  for (i = 0; i < bundle->l; ++i) {
    const proof *item = bundle->pi[i];
    size_t parts, rank, outer, j;
    if (item == NULL || !proof_output_shape(item, &parts, &rank, &outer) ||
        !projection_valid(item->p) || item->jlnonce == 0 ||
        item->cpp->fg != 0 || (i + 1U < bundle->l && item->tail))
      return 0;
    if (i == 0) {
      static const size_t first_ranks[3] = {
          VA_HAT_T_LEN, VA_RANDOMNESS_LEN, VA_S_BLOCK_LEN};
      if (item->r != 3)
        return 0;
      for (j = 0; j < 3; ++j)
        if (item->n[j] != first_ranks[j])
          return 0;
    } else {
      if (item->r != previous_parts)
        return 0;
      for (j = 0; j < item->r; ++j) {
        const size_t expected =
            j + 1U == item->r && previous_outer != 0
                ? previous_outer
                : previous_rank;
        if (item->n[j] != expected)
          return 0;
      }
    }
    previous_parts = parts;
    previous_rank = rank;
    previous_outer = item->tail ? 0 : outer;
  }
  return witness_valid(&bundle->owt, previous_parts, previous_rank,
                       previous_outer);
}

static void writer_proof(wire_writer *writer, const proof *item) {
  const comparams *params = item->cpp;
  const size_t parameter_values[10] = {
      params->f,      params->fu,     params->fg,   params->b,
      params->bu,     params->bg,     params->kappa, params->kappa1,
      params->u1len,  params->u2len};
  size_t i;

  writer_u32(writer, (uint32_t)item->r);
  writer_u8(writer, (uint8_t)item->tail);
  writer_u8(writer, 0);
  writer_u16(writer, 0);
  for (i = 0; i < 10; ++i)
    writer_u64(writer, parameter_values[i]);
  writer_u64(writer, item->jlnonce);
  writer_u64(writer, item->normsq);
  for (i = 0; i < item->r; ++i) {
    writer_u64(writer, item->n[i]);
    writer_u64(writer, item->nu[i]);
  }
  for (i = 0; i < 256; ++i)
    writer_u32(writer, (uint32_t)item->p[i]);
  for (i = 0; i < params->u1len + params->u2len + LIFTS; ++i)
    writer_polz(writer, &item->u1[i]);
}

static int reader_proof(wire_reader *reader, proof **result) {
  proof *item = NULL;
  size_t values[10], polz_count, bytes, encoded_bytes, i;
  uint64_t value;

  item = calloc(1, sizeof(*item));
  if (item == NULL)
    return VT_ERR_MEMORY;
  item->r = reader_u32(reader);
  item->tail = reader_u8(reader);
  if (reader_u8(reader) != 0 || reader_u16(reader) != 0 || reader->failed ||
      item->r == 0 || item->r > ACC_WIRE_MAX_PROOF_PARTS)
    goto format;
  for (i = 0; i < 10; ++i) {
    value = reader_u64(reader);
    if (!u64_to_size(value, &values[i]))
      goto format;
  }
  item->cpp->f = values[0];
  item->cpp->fu = values[1];
  item->cpp->fg = values[2];
  item->cpp->b = values[3];
  item->cpp->bu = values[4];
  item->cpp->bg = values[5];
  item->cpp->kappa = values[6];
  item->cpp->kappa1 = values[7];
  item->cpp->u1len = values[8];
  item->cpp->u2len = values[9];
  value = reader_u64(reader);
  if (!u64_to_size(value, &item->jlnonce))
    goto format;
  item->normsq = reader_u64(reader);
  if (!checked_mul(2U * item->r, sizeof(*item->n), &bytes))
    goto format;
  item->n = calloc(1, bytes);
  if (item->n == NULL)
    goto memory;
  item->nu = &item->n[item->r];
  for (i = 0; i < item->r; ++i) {
    if (!u64_to_size(reader_u64(reader), &item->n[i]) ||
        !u64_to_size(reader_u64(reader), &item->nu[i]))
      goto format;
  }
  for (i = 0; i < 256; ++i)
    item->p[i] = (int32_t)reader_u32(reader);
  if (reader->failed || !checked_add(item->cpp->u1len,
                                     item->cpp->u2len, &polz_count) ||
      !checked_add(polz_count, LIFTS, &polz_count) ||
      polz_count > ACC_WIRE_MAX_POLYNOMIALS)
    goto format;
  if (!checked_mul(polz_count, N * QBYTES, &encoded_bytes) ||
      encoded_bytes > reader->length - reader->offset)
    goto format;
  item->u1 = wire_aligned_calloc(polz_count, sizeof(*item->u1));
  if (item->u1 == NULL)
    goto memory;
  item->u2 = &item->u1[item->cpp->u1len];
  item->bb = &item->u2[item->cpp->u2len];
  for (i = 0; i < polz_count; ++i)
    reader_polz(reader, &item->u1[i]);
  if (reader->failed ||
      !proof_output_shape(item, &bytes, &polz_count, &i) ||
      !projection_valid(item->p))
    goto format;
  *result = item;
  return VT_OK;

memory:
  free_proof(item);
  free(item);
  return VT_ERR_MEMORY;
format:
  free_proof(item);
  free(item);
  return ACC_ERR_FORMAT;
}

static void writer_witness(wire_writer *writer, const witness *opening) {
  size_t i, coefficient;
  writer_u32(writer, (uint32_t)opening->r);
  writer_u32(writer, 0);
  for (i = 0; i < opening->r; ++i) {
    writer_u64(writer, opening->n[i]);
    writer_u64(writer, opening->normsq[i]);
  }
  for (i = 0; i < opening->r; ++i)
    for (coefficient = 0; coefficient < opening->n[i] * N; ++coefficient)
      writer_u16(writer, (uint16_t)opening->s[i][coefficient / N]
                                      .vec[0]
                                      .c[coefficient % N]);
}

static int reader_witness(wire_reader *reader, witness *opening) {
  size_t i, coefficient, total = 0, bytes, encoded_bytes;
  uint32_t reserved;

  opening->r = reader_u32(reader);
  reserved = reader_u32(reader);
  if (reader->failed || reserved != 0 || opening->r == 0 ||
      opening->r > ACC_WIRE_MAX_PROOF_PARTS ||
      !checked_mul(opening->r,
                   sizeof(size_t) + sizeof(uint64_t) + sizeof(poly *),
                   &bytes))
    return ACC_ERR_FORMAT;
  opening->n = calloc(1, bytes);
  if (opening->n == NULL)
    return VT_ERR_MEMORY;
  opening->normsq = (uint64_t *)&opening->n[opening->r];
  opening->s = (poly **)&opening->normsq[opening->r];
  for (i = 0; i < opening->r; ++i) {
    if (!u64_to_size(reader_u64(reader), &opening->n[i]))
      goto format;
    opening->normsq[i] = reader_u64(reader);
    if (opening->n[i] == 0 ||
        !checked_add(total, opening->n[i], &total) ||
        total > ACC_WIRE_MAX_POLYNOMIALS)
      goto format;
  }
  if (!checked_mul(total, N * sizeof(int16_t), &encoded_bytes) ||
      encoded_bytes > reader->length - reader->offset)
    goto format;
  opening->s[0] = wire_aligned_calloc(total, sizeof(poly));
  if (opening->s[0] == NULL)
    return VT_ERR_MEMORY;
  for (i = 1; i < opening->r; ++i)
    opening->s[i] = opening->s[i - 1U] + opening->n[i - 1U];
  for (i = 0; i < opening->r; ++i) {
    int64_t actual_norm;
    for (coefficient = 0; coefficient < opening->n[i] * N; ++coefficient)
      opening->s[i][coefficient / N].vec[0].c[coefficient % N] =
          (int16_t)reader_u16(reader);
    actual_norm =
        polyvec_sprodz(opening->s[i], opening->s[i], opening->n[i]);
    if (reader->failed || actual_norm < 0 ||
        (uint64_t)actual_norm != opening->normsq[i])
      goto format;
  }
  return VT_OK;

format:
  return ACC_ERR_FORMAT;
}

static void writer_composite(wire_writer *writer, const composite *bundle) {
  size_t i;
  writer_u32(writer, (uint32_t)bundle->l);
  writer_u32(writer, 0);
  for (i = 0; i < bundle->l; ++i)
    writer_proof(writer, bundle->pi[i]);
  writer_witness(writer, &bundle->owt);
}

int acc_composite_encoded_size(const composite *composite_proof,
                               size_t *size) {
  wire_writer writer = {0};
  if (size == NULL || !composite_valid(composite_proof))
    return VT_ERR_ARGUMENT;
  writer_composite(&writer, composite_proof);
  if (writer.failed || writer.offset > ACC_WIRE_MAX_BYTES)
    return VT_ERR_OVERFLOW;
  *size = writer.offset;
  return VT_OK;
}

static int reader_composite(wire_reader *reader, composite *bundle) {
  size_t i;
  int ret;
  bundle->l = reader_u32(reader);
  if (reader_u32(reader) != 0 || reader->failed || bundle->l == 0 ||
      bundle->l > 16)
    return ACC_ERR_FORMAT;
  for (i = 0; i < bundle->l; ++i) {
    ret = reader_proof(reader, &bundle->pi[i]);
    if (ret != VT_OK)
      return ret;
  }
  ret = reader_witness(reader, &bundle->owt);
  if (ret != VT_OK)
    return ret;
  if (!composite_valid(bundle))
    return ACC_ERR_FORMAT;
  bundle->size = composite_estimated_kib(bundle);
  return VT_OK;
}

static int witness_wire_write(wire_writer *writer,
                              const acc_witness *proof_bundle,
                              uint64_t total_length) {
  uint32_t depth, intermediate_count, proof_count;
  size_t i;

  if (proof_bundle == NULL || proof_bundle->depth == 0 ||
      proof_bundle->depth > ACC_WIRE_MAX_DEPTH ||
      proof_bundle->intermediate_count != proof_bundle->depth - 1U ||
      proof_bundle->proof_count != proof_bundle->depth ||
      proof_bundle->opening_proofs == NULL ||
      (proof_bundle->intermediate_count != 0 &&
       proof_bundle->intermediate_commitments == NULL) ||
      !size_to_u32(proof_bundle->depth, &depth) ||
      !size_to_u32(proof_bundle->intermediate_count, &intermediate_count) ||
      !size_to_u32(proof_bundle->proof_count, &proof_count))
    return VT_ERR_ARGUMENT;
  for (i = 0; i < proof_bundle->proof_count; ++i)
    if (!composite_valid(&proof_bundle->opening_proofs[i]))
      return VT_ERR_ARGUMENT;

  writer_bytes(writer, acc_wire_magic, sizeof(acc_wire_magic));
  writer_u16(writer, ACC_WIRE_VERSION);
  writer_u16(writer, 0);
  writer_u32(writer, N);
  writer_u32(writer, LOGQ);
  writer_u64(writer, VA_Q);
  writer_u32(writer, VA_ARITY);
  writer_u32(writer, VA_KAPPA);
  writer_u32(writer, VA_INNER_RANK);
  writer_u32(writer, VA_OUTER_RANK);
  writer_u32(writer, depth);
  writer_u32(writer, intermediate_count);
  writer_u32(writer, proof_count);
  writer_u32(writer, 0);
  writer_u64(writer, total_length);
  if (writer->offset != ACC_WIRE_HEADER_BYTES)
    return VT_ERR_OVERFLOW;
  for (i = 0; i < proof_bundle->intermediate_count; ++i) {
    uint8_t encoded[VA_COMMITMENT_BYTES];
    if (writer->data != NULL) {
      va_commitment_encode(encoded,
                           &proof_bundle->intermediate_commitments[i]);
      writer_bytes(writer, encoded, sizeof(encoded));
    } else {
      writer_bytes(writer, encoded, sizeof(encoded));
    }
  }
  for (i = 0; i < proof_bundle->proof_count; ++i)
    writer_composite(writer, &proof_bundle->opening_proofs[i]);
  return writer->failed ? VT_ERR_OVERFLOW : VT_OK;
}

int acc_witness_encoded_size(const acc_witness *proof_bundle, size_t *size) {
  wire_writer writer = {0};
  int ret;
  if (size == NULL)
    return VT_ERR_ARGUMENT;
  ret = witness_wire_write(&writer, proof_bundle, 0);
  if (ret != VT_OK)
    return ret;
  if (writer.offset > ACC_WIRE_MAX_BYTES)
    return VT_ERR_OVERFLOW;
  *size = writer.offset;
  return VT_OK;
}

int acc_witness_encode(uint8_t *out, size_t out_len, size_t *written,
                       const acc_witness *proof_bundle) {
  wire_writer counter = {0}, writer;
  uint64_t encoded_length;
  int ret;
  if (out == NULL || written == NULL)
    return VT_ERR_ARGUMENT;
  ret = witness_wire_write(&counter, proof_bundle, 0);
  if (ret != VT_OK)
    return ret;
  if (counter.offset > ACC_WIRE_MAX_BYTES || counter.offset > out_len ||
      !size_to_u64(counter.offset, &encoded_length))
    return VT_ERR_OVERFLOW;
  writer = (wire_writer){.data = out, .capacity = out_len};
  ret = witness_wire_write(&writer, proof_bundle, encoded_length);
  if (ret != VT_OK || writer.offset != counter.offset)
    return ret == VT_OK ? VT_ERR_OVERFLOW : ret;
  *written = writer.offset;
  return VT_OK;
}

int acc_witness_decode(const acc_public_parameters *pp,
                       acc_witness *proof_bundle, const uint8_t *in,
                       size_t in_len) {
  wire_reader reader = {.data = in, .length = in_len};
  uint8_t magic[4];
  uint32_t depth, intermediate_count, proof_count;
  uint64_t total_length;
  size_t i;
  int ret = ACC_ERR_FORMAT;

  if (pp == NULL || proof_bundle == NULL || in == NULL)
    return VT_ERR_ARGUMENT;
  memset(proof_bundle, 0, sizeof(*proof_bundle));
  if (in_len < ACC_WIRE_HEADER_BYTES || in_len > ACC_WIRE_MAX_BYTES)
    return ACC_ERR_FORMAT;
  reader_bytes(&reader, magic, sizeof(magic));
  if (memcmp(magic, acc_wire_magic, sizeof(magic)) != 0 ||
      reader_u16(&reader) != ACC_WIRE_VERSION || reader_u16(&reader) != 0 ||
      reader_u32(&reader) != N || reader_u32(&reader) != LOGQ ||
      reader_u64(&reader) != VA_Q || reader_u32(&reader) != VA_ARITY ||
      reader_u32(&reader) != VA_KAPPA ||
      reader_u32(&reader) != VA_INNER_RANK ||
      reader_u32(&reader) != VA_OUTER_RANK)
    return ACC_ERR_FORMAT;
  depth = reader_u32(&reader);
  intermediate_count = reader_u32(&reader);
  proof_count = reader_u32(&reader);
  if (reader_u32(&reader) != 0)
    return ACC_ERR_FORMAT;
  total_length = reader_u64(&reader);
  if (reader.failed || reader.offset != ACC_WIRE_HEADER_BYTES ||
      total_length != in_len || depth == 0 || depth > ACC_WIRE_MAX_DEPTH ||
      depth != pp->tree.depth || intermediate_count != depth - 1U ||
      proof_count != depth)
    return ACC_ERR_FORMAT;
  proof_bundle->depth = depth;
  proof_bundle->intermediate_count = intermediate_count;
  proof_bundle->proof_count = proof_count;
  if (intermediate_count != 0) {
    proof_bundle->intermediate_commitments = wire_aligned_calloc(
        intermediate_count, sizeof(*proof_bundle->intermediate_commitments));
    if (proof_bundle->intermediate_commitments == NULL) {
      ret = VT_ERR_MEMORY;
      goto error;
    }
  }
  proof_bundle->opening_proofs =
      calloc(proof_count, sizeof(*proof_bundle->opening_proofs));
  if (proof_bundle->opening_proofs == NULL) {
    ret = VT_ERR_MEMORY;
    goto error;
  }
  for (i = 0; i < intermediate_count; ++i) {
    uint8_t encoded[VA_COMMITMENT_BYTES];
    reader_bytes(&reader, encoded, sizeof(encoded));
    if (reader.failed ||
        va_commitment_decode(&proof_bundle->intermediate_commitments[i],
                             encoded) != 0)
      goto error;
  }
  for (i = 0; i < proof_count; ++i) {
    ret = reader_composite(&reader, &proof_bundle->opening_proofs[i]);
    if (ret != VT_OK)
      goto error;
  }
  if (reader.failed || reader.offset != reader.length) {
    ret = ACC_ERR_FORMAT;
    goto error;
  }
  return VT_OK;

error:
  acc_witness_clear(proof_bundle);
  return ret;
}

int acc_witness_write_file(const char *path,
                           const acc_witness *proof_bundle) {
  uint8_t *encoded = NULL;
  FILE *file = NULL;
  size_t size, written;
  int ret;
  if (path == NULL)
    return VT_ERR_ARGUMENT;
  ret = acc_witness_encoded_size(proof_bundle, &size);
  if (ret != VT_OK)
    return ret;
  encoded = malloc(size);
  if (encoded == NULL)
    return VT_ERR_MEMORY;
  ret = acc_witness_encode(encoded, size, &written, proof_bundle);
  if (ret != VT_OK)
    goto end;
  file = fopen(path, "wb");
  if (file == NULL) {
    ret = ACC_ERR_IO;
    goto end;
  }
  if (fwrite(encoded, 1, written, file) != written || fflush(file) != 0) {
    ret = ACC_ERR_IO;
    goto end;
  }
  if (fclose(file) != 0) {
    file = NULL;
    ret = ACC_ERR_IO;
    goto end;
  }
  file = NULL;
  ret = VT_OK;

end:
  if (file != NULL)
    fclose(file);
  free(encoded);
  return ret;
}

int acc_witness_read_file(const acc_public_parameters *pp, const char *path,
                          acc_witness *proof_bundle) {
  uint8_t *encoded = NULL;
  FILE *file = NULL;
  long file_size;
  size_t size;
  int ret = ACC_ERR_IO;
  if (pp == NULL || path == NULL || proof_bundle == NULL)
    return VT_ERR_ARGUMENT;
  file = fopen(path, "rb");
  if (file == NULL)
    return ACC_ERR_IO;
  if (fseek(file, 0, SEEK_END) != 0 || (file_size = ftell(file)) < 0 ||
      file_size > ACC_WIRE_MAX_BYTES || fseek(file, 0, SEEK_SET) != 0)
    goto end;
  size = (size_t)file_size;
  encoded = malloc(size == 0 ? 1U : size);
  if (encoded == NULL) {
    ret = VT_ERR_MEMORY;
    goto end;
  }
  if (fread(encoded, 1, size, file) != size || fgetc(file) != EOF)
    goto end;
  ret = acc_witness_decode(pp, proof_bundle, encoded, size);

end:
  fclose(file);
  free(encoded);
  return ret;
}
