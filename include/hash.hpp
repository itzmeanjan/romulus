#pragma once
#include "skinny.hpp"

// Romulus Authenticated Encryption and Hash Function
namespace romulus {

// 32 -bytes input message compression function, used in Romulus-H hash
// function, where message is consumed into two 128 -bit states ( i.e. denoted
// by left & right )
//
// See algorithm `CF(...)` in section 2.4.6 of Romulus specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf
inline static void compress(
    uint8_t* const __restrict left,      // 16 -bytes state
    uint8_t* const __restrict right,     // 16 -bytes state
    const uint8_t* const __restrict msg  // 32 -bytes message to be compressed
) {
  uint8_t left_prime[16];
  uint8_t key[48];

  std::memcpy(key, right, 16);
  std::memcpy(key + 16, msg, 32);

  skinny::state st;

  skinny::initialize(&st, left, key);
  skinny::tbc(&st);

  for (size_t i = 0; i < 16; i++) {
    left_prime[i] = st.is[i] ^ left[i];
  }

  left[0] ^= 0b00000001;

  skinny::initialize(&st, left, key);
  skinny::tbc(&st);

  for (size_t i = 0; i < 16; i++) {
    right[i] = st.is[i] ^ left[i];
  }

  std::memcpy(left, left_prime, 16);
}

// Given N -bytes input message this routine computes 32 -bytes digest using
// Romulus-H hash function | N >= 0
//
// See algorithm `Romulus-H(...)` in section 2.4.6 of Romulus specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf
inline static void hash(
    const uint8_t* const __restrict msg,  // input message to be hashed
    const size_t mlen,                    // len(msg) >= 0
    uint8_t* const __restrict dig         // 32 -bytes digest computed
) {
  uint8_t left[16];
  uint8_t right[16];
  uint8_t last_blk[32];

  std::memset(left, 0, sizeof(left));
  std::memset(right, 0, sizeof(right));
  std::memset(last_blk, 0, sizeof(last_blk));

  const size_t blk_cnt = mlen >> 5;
  const size_t rm_bytes = mlen & 31;

  for (size_t i = 0; i < blk_cnt; i++) {
    const size_t off = i << 5;
    compress(left, right, msg + off);
  }

  const size_t off = blk_cnt << 5;

  std::memcpy(last_blk, msg + off, rm_bytes);
  last_blk[31] = rm_bytes;

  left[0] ^= 0b00000010;

  compress(left, right, last_blk);

  std::memcpy(dig, left, 16);
  std::memcpy(dig + 16, right, 16);
}

}  // namespace romulus
