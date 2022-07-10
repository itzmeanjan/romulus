#pragma once
#include <algorithm>

#include "common.hpp"
#include "skinny.hpp"

// Romulus Authenticated Encryption and Hash Function
namespace romulus {

inline static void encrypt_romulusn(
    const uint8_t* const __restrict key,    // 128 -bit secret key
    const uint8_t* const __restrict nonce,  // 128 -bit public message nonce
    const uint8_t* const __restrict data,   // N -bytes associated data
    const size_t dlen,                      // len(data) | >= 0
    const uint8_t* const __restrict txt,    // N -bytes plain text
    uint8_t* const __restrict cipher,       // N -bytes encrypted text
    const size_t ctlen,                     // len(txt) = len(cipher) | >= 0
    uint8_t* const __restrict tag           // 128 -bit authentication tag
) {
  uint8_t state[16];
  uint8_t lfsr[7];

  uint8_t enc[16];
  uint8_t tweakey[48];

  uint8_t last_blk[16];

  skinny::state st;

  std::memset(state, 0, 16);
  romulus_common::set_lfsr(lfsr);

  constexpr size_t br0[2] = {0, 1};

  const size_t full_blk_cnt = dlen >> 4;
  const size_t rm_bytes = dlen & 15;

  const bool flg = (dlen == 0) | (rm_bytes > 0);

  const size_t tot_blk_cnt = full_blk_cnt + br0[flg];
  const size_t half_blk_cnt = tot_blk_cnt >> 1;

  size_t off = 0;

  for (size_t i = 0; i < half_blk_cnt; i++) {
    uint8_t right_blk[16];
    std::memset(right_blk, 0, 16);

    const size_t off0 = off;
    const size_t off1 = off + 16ul;

    romulus_common::rho(state, data + off0, enc);
    romulus_common::update_lfsr(lfsr);

    const size_t to_read = std::min(16ul, dlen - off1);
    std::memcpy(right_blk, data + off1, to_read);

    off = off1 + to_read;

    const size_t br1[2] = {right_blk[15], to_read};
    right_blk[15] = br1[to_read < 16];

    romulus_common::encode(key, right_blk, lfsr, 8, tweakey);

    skinny::initialize(&st, state, tweakey);
    skinny::tbc(&st);

    std::memcpy(state, st.is, 16);

    romulus_common::update_lfsr(lfsr);
  }

  const size_t to_read = dlen - off;

  std::memset(last_blk, 0, 16);
  std::memcpy(last_blk, data + off, to_read);

  const size_t br2[2] = {last_blk[15], to_read};
  last_blk[15] = br2[to_read < 16];

  romulus_common::rho(state, last_blk, enc);

  if (tot_blk_cnt > (half_blk_cnt << 1)) {
    romulus_common::update_lfsr(lfsr);
  }

  constexpr size_t br3[2] = {24, 26};
  romulus_common::encode(key, nonce, lfsr, br3[flg], tweakey);

  skinny::initialize(&st, state, tweakey);
  skinny::tbc(&st);

  std::memcpy(state, st.is, 16);
}

}  // namespace romulus
