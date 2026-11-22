/*
 * The sample CRC code from RFC 1952, "GZIP file format specification version
 * 4.3", appendix 8. RFC 1952's notice:
 *
 * Copyright (c) 1996 L. Peter Deutsch
 *
 * Permission is granted to copy and distribute this document for any
 * purpose and without charge, including translations into other
 * languages and incorporation into compilations, provided that the
 * copyright notice and this notice are preserved, and that any
 * substantive changes or deletions from the original are clearly
 * marked.
 *
 * Modified: each byte is shifted through the polynomial bit by bit instead of
 * looking it up in a table computed on first use, the CRC is computed in one
 * call instead of updated piece by piece, and it uses fixed-width types.
 */

#include "crc32.h"

#include <assert.h>

// the generator polynomial, with its bits reversed
static constexpr uint32_t POLYNOMIAL = 0xEDB88320;

uint32_t stun_crc32(const_view_t data) {
  assert(data.data);

  uint32_t c = 0xFFFFFFFF;
  for (size_t n = 0; n < data.size; ++n) {
    c ^= data.data[n];
    for (int k = 0; k < 8; ++k) {
      if (c & 1) {
        c = POLYNOMIAL ^ (c >> 1);
      } else {
        c = c >> 1;
      }
    }
  }
  return c ^ 0xFFFFFFFF;
}
