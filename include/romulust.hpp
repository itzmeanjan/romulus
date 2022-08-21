#pragma once
#include <algorithm>

#include "common.hpp"
#include "skinny.hpp"

// Romulus-T Authenticated Encryption with Associated Data
namespace romulust {

// Extract N -th message block ( 256 -bit wide ) from padded message bytes
// which is to be authenticated i.e.
//
// msg = ipad_256(padded associated data bytes ||
//                padded cipher text bytes ||
//                16 -bytes nonce ||
//                7 -bytes LFSR counter)
//
// Note, block index = N, begins at zero.
static void get_auth_block(
    const uint8_t* const __restrict data,    // N -bytes associated data
    const size_t dlen,                       // len(data) = N | >= 0
    const uint8_t* const __restrict cipher,  // M -bytes encrypted text
    const size_t ctlen,                      // len(cipher) = M | >= 0
    const uint8_t* const __restrict nonce,   // 16 -bytes nonce
    const uint8_t* const __restrict lfsr,    // 7 -bytes LFSR counter
    const size_t blk_idx,                    // Index of block to be extracted
    uint8_t* const __restrict blk            // 32 -bytes extracted block
) {
  std::memset(blk, 0, 32);

  const size_t tmp0 = dlen & 15ul;
  const size_t tmp1 = ctlen & 15ul;

  const size_t tmp2 = 16ul - tmp0;
  const size_t tmp3 = 16ul - tmp1;

  const bool flg0 = dlen > 0ul;
  const bool flg1 = ctlen > 0ul;

  const size_t padded_dlen = dlen + tmp2 * flg0;
  const size_t padded_ctlen = ctlen + tmp3 * flg1;

  const size_t tmp4 = padded_dlen + padded_ctlen;
  const size_t tmp5 = tmp4 + 16ul;
  const size_t padded_authlen = tmp5 + 7ul;

  size_t off = blk_idx << 5;
  size_t boff = 0ul;

  if (off < padded_dlen) {
    const size_t read = std::min(32ul, dlen - off);

    std::memcpy(blk + boff, data + off, read);

    const uint8_t br0[]{blk[15], static_cast<uint8_t>(read)};
    const uint8_t br1[]{blk[31], static_cast<uint8_t>(read & 15ul)};

    blk[15] = br0[read < 16ul];
    blk[31] = br1[(read > 16ul) & (read < 32ul)];

    const size_t read_ = std::min(32ul, padded_dlen - off);

    off += read_;
    boff += read_;
  }

  const bool flg2 = off >= padded_dlen;
  const bool flg3 = off < tmp4;

  if ((boff < 32ul) && (flg2 & flg3)) {
    const size_t ctoff = off - padded_dlen;
    const size_t read = std::min(32ul, ctlen - ctoff);

    std::memcpy(blk + boff, cipher + ctoff, read);

    const uint8_t br0[]{blk[15], static_cast<uint8_t>(read)};
    const uint8_t br1[]{blk[31], static_cast<uint8_t>(read & 15ul)};

    blk[15] = br0[read < 16ul];
    blk[31] = br1[(read > 16ul) & (read < 32ul)];

    const size_t read_ = std::min(32ul, padded_ctlen - ctoff);

    off += read_;
    boff += read_;
  }

  const bool flg4 = off >= tmp4;
  const bool flg5 = off < tmp5;

  if ((boff < 32ul) && (flg4 & flg5)) {
    std::memcpy(blk + boff, nonce, 16);

    off += 16ul;
    boff += 16ul;
  }

  const bool flg6 = off >= tmp5;
  const bool flg7 = off < padded_authlen;

  if ((boff < 32ul) & (flg6 & flg7)) {
    std::memcpy(blk + boff, lfsr, 7);

    off += 7ul;
    boff += 7ul;
  }

  const uint8_t br[]{blk[31], static_cast<uint8_t>(boff)};
  blk[31] = br[boff < 32ul];
}

}  // namespace romulust
