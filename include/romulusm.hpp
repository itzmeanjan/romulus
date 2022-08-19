#pragma once
#include <algorithm>

#include "common.hpp"
#include "skinny.hpp"

// Romulus Authenticated Encryption and Hash Function
namespace romulus {

// Extract N-th message block ( 128 -bit wide ) from concatenated padded
// associated data bytes and padded plain text bytes. Last block of both
// associated data and plain text can be padded, if required.
static void get_auth_block(
    const uint8_t* const __restrict data,  // N -bytes associated data
    const size_t dlen,                     // len(data) = N | >= 0
    const uint8_t* const __restrict text,  // M -bytes plain text
    const size_t ctlen,                    // len(text) = M | >= 0
    const size_t blk_idx,                  // Index of block to extract
    uint8_t* const __restrict blk          // 16 -bytes extracted (padded) block
) {
  std::memset(blk, 0, 16);

  const size_t off = blk_idx << 4;
  const size_t padded_dlen = dlen + (16ul - (dlen & 15ul));
  const size_t padded_ctlen = ctlen + (16ul - (ctlen & 15ul));
  const size_t padded_authlen = padded_dlen + padded_ctlen;

  if (off < padded_dlen) {
    const size_t read = std::min(16ul, dlen - off);

    std::memcpy(blk, data + off, read);

    const uint8_t br[]{blk[15], read};
    blk[15] = br[read < 16ul];
  }

  if ((off >= padded_dlen) && (off < padded_authlen)) {
    const size_t ctoff = off - padded_dlen;
    const size_t read = std::min(16ul, ctlen - ctoff);

    std::memcpy(blk, text + ctoff, read);

    const uint8_t br[]{blk[15], read};
    blk[15] = br[read < 16ul];
  }
}

}  // namespace romulus
