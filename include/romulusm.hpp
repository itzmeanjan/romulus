#pragma once
#include <algorithm>

#include "common.hpp"
#include "skinny.hpp"

// Romulus-M Authenticated Encryption with Associated Data
namespace romulusm {

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

  const size_t tmp0 = dlen & 15ul;
  const size_t tmp1 = ctlen & 15ul;

  const bool flg0 = (dlen == 0) | (tmp0 > 0ul);
  const bool flg1 = (ctlen == 0) | (tmp1 > 0ul);

  const size_t off = blk_idx << 4;

  const size_t padded_dlen = dlen + (16ul - tmp0) * flg0;
  const size_t padded_ctlen = ctlen + (16ul - tmp1) * flg1;

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
static void encrypt(
    const uint8_t* const __restrict key,    // 128 -bit secret key
    const uint8_t* const __restrict nonce,  // 128 -bit public message nonce
    const uint8_t* const __restrict data,   // N -bytes associated data
    const size_t dlen,                      // len(data) = N | >= 0
    const uint8_t* const __restrict text,   // M -bytes plain text
    uint8_t* const __restrict cipher,       // M -bytes encrypted text
    const size_t ctlen,                     // len(text) = len(cipher) | >= 0
    uint8_t* const __restrict tag           // 128 -bit authentication tag
) {
  skinny::state_t st;

  uint8_t lfsr[7];
  uint8_t enc[16];

  std::memset(st.arr, 0, 16);
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

    w ^= 2 * flg0;
    w ^= 1 * flg1;
    w ^= 8 * (1 - (tot_ad_blk_cnt & 1));
    w ^= 4 * (1 - (tot_ct_blk_cnt & 1));

    const size_t tot_blk_cnt = tot_ad_blk_cnt + tot_ct_blk_cnt;
    const size_t half_blk_cnt = tot_blk_cnt >> 1;
    const size_t half_ad_blk_cnt = tot_ad_blk_cnt >> 1;

    uint8_t blk[16]{};
    uint8_t x = 40;

    for (size_t i = 0; i < half_blk_cnt; i++) {
      get_auth_block(data, dlen, text, ctlen, (i << 1) ^ 0ul, blk);

      romulus_common::rho(st.arr, blk, enc);
      romulus_common::update_lfsr(lfsr);

      x ^= 4 * (i == half_ad_blk_cnt);

      get_auth_block(data, dlen, text, ctlen, (i << 1) ^ 1ul, blk);
      romulus_common::encode(key, blk, lfsr, x, st.arr + 16);

      skinny::tbc(&st);
      romulus_common::update_lfsr(lfsr);
    }

    const bool flg2 = static_cast<bool>(tot_ad_blk_cnt & 1ul);
    const bool flg3 = static_cast<bool>(tot_ct_blk_cnt & 1ul);

    if (flg2 == flg3) {
      std::memset(blk, 0, 16);
    } else {
      get_auth_block(data, dlen, text, ctlen, tot_blk_cnt - 1, blk);
    }

    romulus_common::rho(st.arr, blk, enc);

    if (tot_blk_cnt > (half_blk_cnt << 1)) {
      romulus_common::update_lfsr(lfsr);
    }

    romulus_common::encode(key, nonce, lfsr, w, st.arr + 16);

    skinny::tbc(&st);
  }

  uint8_t tmp[16]{};
  std::memset(tmp, 0, 16);

  romulus_common::rho(st.arr, tmp, tag);

  if (ctlen > 0ul) {
    romulus_common::set_lfsr(lfsr);

    std::memcpy(st.arr, tag, 16);

    const size_t blk_cnt = ctlen >> 4;
    const size_t rm_bytes = ctlen & 15ul;

    const bool flg = (ctlen == 0) | (rm_bytes > 0);
    const size_t tot_blk_cnt = blk_cnt + 1ul * flg;

    size_t off = 0ul;

    for (size_t i = 0; i < tot_blk_cnt - 1; i++) {
      romulus_common::encode(key, nonce, lfsr, 36, st.arr + 16);

      skinny::tbc(&st);

      romulus_common::rho(st.arr, text + off, cipher + off);
      romulus_common::update_lfsr(lfsr);

      off += 16;
    }

    const size_t read = ctlen - off;

    uint8_t blk[16]{};

    std::memset(blk, 0, 16);
    std::memcpy(blk, text + off, read);

    const uint8_t br[]{blk[15], static_cast<uint8_t>(read)};
    blk[15] = br[read < 16ul];

    romulus_common::encode(key, nonce, lfsr, 36, st.arr + 16);

    skinny::tbc(&st);

    romulus_common::rho(st.arr, blk, enc);
    std::memcpy(cipher + off, enc, read);
  }
}

// Given 16 -bytes secret key, 16 -bytes nonce, 16 -bytes authentication tag, N
// -bytes associated data and M -bytes encrypted text | N, M >= 0, this routine
// computes M -bytes decrypted text and boolean verification flag, using
// Romulus-M verified decryption algorithm, which is nonce misuse-resistant.
//
// See decryption algorithm defined in figure 2.7 of Romulus specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf
static bool decrypt(
    const uint8_t* const __restrict key,     // 128 -bit secret key
    const uint8_t* const __restrict nonce,   // 128 -bit public message nonce
    const uint8_t* const __restrict tag,     // 128 -bit authentication tag
    const uint8_t* const __restrict data,    // N -bytes associated data
    const size_t dlen,                       // len(data) = N | >= 0
    const uint8_t* const __restrict cipher,  // M -bytes encrypted text
    uint8_t* const __restrict text,          // M -bytes decrypted text
    const size_t ctlen                       // len(text) = len(cipher) | >= 0
) {
  skinny::state_t st;

  uint8_t lfsr[7];
  uint8_t enc[16];

  if (ctlen > 0ul) {
    romulus_common::set_lfsr(lfsr);

    std::memcpy(st.arr, tag, 16);

    const size_t blk_cnt = ctlen >> 4;
    const size_t rm_bytes = ctlen & 15ul;

    const bool flg = (ctlen == 0) | (rm_bytes > 0);
    const size_t tot_blk_cnt = blk_cnt + 1ul * flg;

    size_t off = 0ul;

    for (size_t i = 0; i < tot_blk_cnt - 1; i++) {
      romulus_common::encode(key, nonce, lfsr, 36, st.arr + 16);

      skinny::tbc(&st);

      romulus_common::rho_inv(st.arr, cipher + off, text + off);
      romulus_common::update_lfsr(lfsr);

      off += 16;
    }

    const size_t read = ctlen - off;

    uint8_t blk[16]{};

    std::memset(blk, 0, 16);
    std::memcpy(blk, cipher + off, read);

    const uint8_t br[]{blk[15], static_cast<uint8_t>(read)};
    blk[15] = br[read < 16ul];

    romulus_common::encode(key, nonce, lfsr, 36, st.arr + 16);

    skinny::tbc(&st);

    romulus_common::rho_inv(st.arr, blk, enc);
    std::memcpy(text + off, enc, read);
  }

  {
    std::memset(st.arr, 0, 16);
    romulus_common::set_lfsr(lfsr);

    const size_t ad_blk_cnt = dlen >> 4;
    const size_t ct_blk_cnt = ctlen >> 4;

    const size_t ad_rm_bytes = dlen & 15ul;
    const size_t ct_rm_bytes = ctlen & 15ul;

    const bool flg0 = (dlen == 0) | (ad_rm_bytes > 0);
    const bool flg1 = (ctlen == 0) | (ct_rm_bytes > 0);

    const size_t tot_ad_blk_cnt = ad_blk_cnt + 1ul * flg0;
    const size_t tot_ct_blk_cnt = ct_blk_cnt + 1ul * flg1;

    uint8_t w = 48;

    w ^= 2 * flg0;
    w ^= 1 * flg1;
    w ^= 8 * (1 - (tot_ad_blk_cnt & 1));
    w ^= 4 * (1 - (tot_ct_blk_cnt & 1));

    const size_t tot_blk_cnt = tot_ad_blk_cnt + tot_ct_blk_cnt;
    const size_t half_blk_cnt = tot_blk_cnt >> 1;
    const size_t half_ad_blk_cnt = tot_ad_blk_cnt >> 1;

    uint8_t blk[16]{};
    uint8_t x = 40;

    for (size_t i = 0; i < half_blk_cnt; i++) {
      get_auth_block(data, dlen, text, ctlen, (i << 1) ^ 0ul, blk);

      romulus_common::rho(st.arr, blk, enc);
      romulus_common::update_lfsr(lfsr);

      x ^= 4 * (i == half_ad_blk_cnt);

      get_auth_block(data, dlen, text, ctlen, (i << 1) ^ 1ul, blk);
      romulus_common::encode(key, blk, lfsr, x, st.arr + 16);

      skinny::tbc(&st);
      romulus_common::update_lfsr(lfsr);
    }

    const bool flg2 = static_cast<bool>(tot_ad_blk_cnt & 1ul);
    const bool flg3 = static_cast<bool>(tot_ct_blk_cnt & 1ul);

    if (flg2 == flg3) {
      std::memset(blk, 0, 16);
    } else {
      get_auth_block(data, dlen, text, ctlen, tot_blk_cnt - 1, blk);
    }

    romulus_common::rho(st.arr, blk, enc);

    if (tot_blk_cnt > (half_blk_cnt << 1)) {
      romulus_common::update_lfsr(lfsr);
    }

    romulus_common::encode(key, nonce, lfsr, w, st.arr + 16);

    skinny::tbc(&st);
  }

  uint8_t tmp[16]{};
  uint8_t tag_[16]{};

  std::memset(tmp, 0, 16);
  std::memset(tag_, 0, 16);

  romulus_common::rho(st.arr, tmp, tag_);

  bool flg = false;
  for (size_t i = 0; i < 16; i++) {
    flg |= static_cast<bool>(tag[i] ^ tag_[i]);
  }

  std::memset(text, 0, flg * ctlen);
  return !flg;
}

}  // namespace romulusm
