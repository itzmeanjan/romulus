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

    const uint8_t br[]{blk[15], static_cast<uint8_t>(read)};
    blk[15] = br[read < 16ul];
  }

  if ((off >= padded_dlen) && (off < padded_authlen)) {
    const size_t ctoff = off - padded_dlen;
    const size_t read = std::min(16ul, ctlen - ctoff);

    std::memcpy(blk, text + ctoff, read);

    const uint8_t br[]{blk[15], static_cast<uint8_t>(read)};
    blk[15] = br[read < 16ul];
  }
}

// Given 16 -bytes secret key, 16 -bytes nonce, N -bytes associated data and M
// -bytes plain text | N, M >= 0, this routine computes M -bytes encrypted text
// and 16 -bytes authentication tag, using Romulus-M authenticated encryption
// algorithm, which is nonce misuse-resistant.
//
// See encryption algorithm defined in figure 2.7 of Romulus specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf
static void encrypt_romulusm(
    const uint8_t* const __restrict key,    // 128 -bit secret key
    const uint8_t* const __restrict nonce,  // 128 -bit public message nonce
    const uint8_t* const __restrict data,   // N -bytes associated data
    const size_t dlen,                      // len(data) = N | >= 0
    const uint8_t* const __restrict text,   // M -bytes plain text
    uint8_t* const __restrict cipher,       // M -bytes encrypted text
    const size_t ctlen,                     // len(text) = len(cipher) | >= 0
    uint8_t* const __restrict tag           // 128 -bit authentication tag
) {
  uint8_t state[16];
  uint8_t lfsr[7];

  uint8_t enc[16];
  uint8_t tweakey[48];

  skinny::state st;

  std::memset(state, 0, 16);
  romulus_common::set_lfsr(lfsr);

  {
    const size_t ad_blk_cnt = dlen >> 4;
    const size_t ct_blk_cnt = ctlen >> 4;

    const size_t ad_rm_bytes = dlen & 15ul;
    const size_t ct_rm_bytes = ctlen & 15ul;

    const bool flg0 = (dlen == 0) | (ad_rm_bytes > 0);
    const bool flg1 = (ctlen == 0) | (ct_rm_bytes > 0);

    const size_t tot_ad_blk_cnt = ad_blk_cnt + 1ul * flg0;
    const size_t tot_ct_blk_cnt = ct_blk_cnt + 1ul * flg1;

    uint8_t w = 48;

    w ^= 2 * (ad_rm_bytes < 16ul);
    w ^= 1 * (ct_rm_bytes < 16ul);
    w ^= 8 * (1 - (tot_ad_blk_cnt & 1));
    w ^= 4 * (1 - (tot_ct_blk_cnt & 1));

    const size_t tot_blk_cnt = tot_ad_blk_cnt + tot_ct_blk_cnt;
    const size_t half_blk_cnt = tot_blk_cnt >> 1;
    const size_t half_ad_blk_cnt = tot_ad_blk_cnt >> 1;

    uint8_t blk[16]{};
    uint8_t x = 40;

    for (size_t i = 0; i < half_blk_cnt; i++) {
      get_auth_block(data, dlen, text, ctlen, (i << 1) ^ 0ul, blk);

      romulus_common::rho(state, blk, enc);
      romulus_common::update_lfsr(lfsr);

      x ^= 4 * (i == half_ad_blk_cnt);

      get_auth_block(data, dlen, text, ctlen, (i << 1) ^ 1ul, blk);
      romulus_common::encode(key, blk, lfsr, x, tweakey);

      skinny::initialize(&st, state, tweakey);
      skinny::tbc(&st);

      std::memcpy(state, st.is, 16);

      romulus_common::update_lfsr(lfsr);
    }

    const bool flg2 = static_cast<bool>(tot_ad_blk_cnt & 1ul);
    const bool flg3 = static_cast<bool>(tot_ct_blk_cnt & 1ul);

    if (flg2 == flg3) {
      std::memset(blk, 0, 16);
    } else {
      get_auth_block(data, dlen, text, ctlen, tot_blk_cnt - 1, blk);
    }

    romulus_common::rho(state, blk, enc);

    if (tot_blk_cnt > (half_blk_cnt << 1)) {
      romulus_common::update_lfsr(lfsr);
    }

    romulus_common::encode(key, nonce, lfsr, w, tweakey);

    skinny::initialize(&st, state, tweakey);
    skinny::tbc(&st);

    std::memcpy(state, st.is, 16);
  }

  uint8_t tmp[16]{};
  std::memset(tmp, 0, 16);

  romulus_common::rho(state, tmp, tag);

  if (ctlen > 0ul) {
    romulus_common::set_lfsr(lfsr);

    std::memcpy(state, tag, 16);

    const size_t blk_cnt = ctlen >> 4;
    const size_t rm_bytes = ctlen & 15ul;

    const bool flg = (ctlen == 0) | (rm_bytes > 0);
    const size_t tot_blk_cnt = blk_cnt + 1ul * flg;

    size_t off = 0ul;

    for (size_t i = 0; i < tot_blk_cnt - 1; i++) {
      romulus_common::encode(key, nonce, lfsr, 36, tweakey);

      skinny::initialize(&st, state, tweakey);
      skinny::tbc(&st);

      std::memcpy(state, st.is, 16);

      romulus_common::rho(state, text + off, cipher + off);
      romulus_common::update_lfsr(lfsr);

      off += 16;
    }

    const size_t read = ctlen - off;

    uint8_t blk[16]{};

    std::memset(blk, 0, 16);
    std::memcpy(blk, text + off, read);

    const uint8_t br[]{blk[15], static_cast<uint8_t>(read)};
    blk[15] = br[read < 16ul];

    romulus_common::encode(key, nonce, lfsr, 36, tweakey);

    skinny::initialize(&st, state, tweakey);
    skinny::tbc(&st);

    std::memcpy(state, st.is, 16);

    romulus_common::rho(state, blk, enc);
    std::memcpy(cipher + off, enc, read);
  }
}

}  // namespace romulus
