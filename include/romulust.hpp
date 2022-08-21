#pragma once
#include <algorithm>

#include "common.hpp"
#include "romulush.hpp"
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
    const uint8_t br2[]{blk[31], static_cast<uint8_t>(read)};

    blk[15] = br0[(boff < 16ul) & (read < 16ul)];
    blk[31] = br1[(boff < 16ul) & (read > 16ul) & (read < 32ul)];
    blk[31] = br2[(boff >= 16ul) & (read < 16ul)];

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

  if ((boff < 32ul) && (flg6 & flg7)) {
    std::memcpy(blk + boff, lfsr, 7);

    off += 7ul;
    boff += 7ul;
  }

  const uint8_t br[]{blk[31], static_cast<uint8_t>(boff)};
  blk[31] = br[boff < 32ul];
}

// Given 16 -bytes secret key, 16 -bytes public message nonce, N -bytes
// associated data and M -bytes plain text | N, M >= 0, this routine computes M
// -bytes encrypted text and 16 -bytes authentication tag, using Romulus-T
// authenticated encryption algorithm, which is leakage-resistant.
//
// See encryption algorithm defined in figure 2.9 of Romulus specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf
static void encrypt(
    const uint8_t* const __restrict key,    // 128 -bit secret key
    const uint8_t* const __restrict nonce,  // 128 -bit nonce
    const uint8_t* const __restrict data,   // N -bytes associated data
    const size_t dlen,                      // len(data) = N | >= 0
    const uint8_t* const __restrict text,   // M -bytes plain text
    uint8_t* const __restrict cipher,       // M -bytes cipher text
    const size_t ctlen,                     // len(text) = len(cipher) | >= 0
    uint8_t* const __restrict tag           // 128 -bit authentication tag
) {
  uint8_t state[16];
  uint8_t lfsr[7];
  uint8_t tweakey[48];

  skinny::state st;

  const size_t blk_cnt = ctlen >> 4;
  const size_t rm_bytes = ctlen & 15ul;

  const bool flg = rm_bytes > 0ul;
  const size_t tot_blk_cnt = blk_cnt + 1ul * flg;

  if (ctlen > 0ul) {
    uint8_t blk[16];

    std::memset(blk, 0, 16);
    std::memset(lfsr, 0, 7);

    romulus_common::encode(key, blk, lfsr, 66, tweakey);

    skinny::initialize(&st, nonce, tweakey);
    skinny::tbc(&st);

    std::memcpy(state, st.is, 16);

    romulus_common::set_lfsr(lfsr);

    size_t off = 0ul;

    for (size_t i = 0; i < tot_blk_cnt - 1ul; i++) {
      romulus_common::encode(state, blk, lfsr, 64, tweakey);

      skinny::initialize(&st, nonce, tweakey);
      skinny::tbc(&st);

      for (size_t j = 0; j < 16; j++) {
        cipher[off + j] = text[off + j] ^ st.is[j];
      }

      romulus_common::encode(state, blk, lfsr, 65, tweakey);

      skinny::initialize(&st, nonce, tweakey);
      skinny::tbc(&st);

      std::memcpy(state, st.is, 16);

      off += 16ul;
      romulus_common::update_lfsr(lfsr);
    }

    romulus_common::encode(state, blk, lfsr, 64, tweakey);

    skinny::initialize(&st, nonce, tweakey);
    skinny::tbc(&st);

    const size_t read = ctlen - off;

    for (size_t i = 0; i < read; i++) {
      cipher[off + i] = text[off + i] ^ st.is[i];
    }
  }

  romulus_common::set_lfsr(lfsr);

  for (size_t i = 0; i < tot_blk_cnt; i++) {
    romulus_common::update_lfsr(lfsr);
  }

  {
    uint8_t left[16]{};
    uint8_t right[16]{};
    uint8_t blk[32]{};

    std::memset(left, 0, sizeof(left));
    std::memset(right, 0, sizeof(right));

    const size_t tmp0 = dlen & 15ul;
    const size_t tmp1 = ctlen & 15ul;

    const size_t tmp2 = 16ul - tmp0;
    const size_t tmp3 = 16ul - tmp1;

    const bool flg0 = dlen > 0ul;
    const bool flg1 = ctlen > 0ul;

    const size_t padded_dlen = dlen + tmp2 * flg0;
    const size_t padded_ctlen = ctlen + tmp3 * flg1;
    const size_t padded_authlen = padded_dlen + padded_ctlen + 16ul + 7ul;

    const size_t padded_blk_cnt = padded_authlen >> 5;
    const size_t padded_rm_bytes = padded_authlen & 31ul;

    const bool flg2 = padded_rm_bytes > 0ul;
    const size_t tot_padded_blk_cnt = padded_blk_cnt + 1ul * flg2;

    for (size_t i = 0; i < tot_padded_blk_cnt - 1ul; i++) {
      get_auth_block(data, dlen, cipher, ctlen, nonce, lfsr, i, blk);
      romulush::compress(left, right, blk);
    }

    left[0] ^= 0b00000010;

    const size_t id = tot_padded_blk_cnt - 1ul;

    get_auth_block(data, dlen, cipher, ctlen, nonce, lfsr, id, blk);
    romulush::compress(left, right, blk);

    std::memset(lfsr, 0, 7);

    romulus_common::encode(key, right, lfsr, 68, tweakey);
    skinny::initialize(&st, left, tweakey);
    skinny::tbc(&st);

    std::memcpy(tag, st.is, 16);
  }
}

// Given 16 -bytes secret key, 16 -bytes public message nonce, 16 -bytes
// authentication tag, N -bytes associated data and M -bytes encrypted text | N,
// M >= 0, this routine computes M -bytes decrypted text and boolean
// verification flag, using Romulus-T verified decryption algorithm, which is
// leakage-resistant.
//
// See decryption algorithm defined in figure 2.9 of Romulus specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf
static bool decrypt(const uint8_t* const __restrict key,
                    const uint8_t* const __restrict nonce,
                    const uint8_t* const __restrict tag,
                    const uint8_t* const __restrict data, const size_t dlen,
                    const uint8_t* const __restrict cipher,
                    uint8_t* const __restrict text, const size_t ctlen) {
  uint8_t state[16];
  uint8_t tag_[16];
  uint8_t lfsr[7];
  uint8_t tweakey[48];

  skinny::state st;

  const size_t blk_cnt = ctlen >> 4;
  const size_t rm_bytes = ctlen & 15ul;

  const bool flg0 = rm_bytes > 0ul;
  const size_t tot_blk_cnt = blk_cnt + 1ul * flg0;

  romulus_common::set_lfsr(lfsr);

  for (size_t i = 0; i < tot_blk_cnt; i++) {
    romulus_common::update_lfsr(lfsr);
  }

  {
    uint8_t left[16]{};
    uint8_t right[16]{};
    uint8_t blk[32]{};

    std::memset(left, 0, sizeof(left));
    std::memset(right, 0, sizeof(right));

    const size_t tmp0 = dlen & 15ul;
    const size_t tmp1 = ctlen & 15ul;

    const size_t tmp2 = 16ul - tmp0;
    const size_t tmp3 = 16ul - tmp1;

    const bool flg0 = dlen > 0ul;
    const bool flg1 = ctlen > 0ul;

    const size_t padded_dlen = dlen + tmp2 * flg0;
    const size_t padded_ctlen = ctlen + tmp3 * flg1;
    const size_t padded_authlen = padded_dlen + padded_ctlen + 16ul + 7ul;

    const size_t padded_blk_cnt = padded_authlen >> 5;
    const size_t padded_rm_bytes = padded_authlen & 31ul;

    const bool flg2 = padded_rm_bytes > 0ul;
    const size_t tot_padded_blk_cnt = padded_blk_cnt + 1ul * flg2;

    for (size_t i = 0; i < tot_padded_blk_cnt - 1ul; i++) {
      get_auth_block(data, dlen, cipher, ctlen, nonce, lfsr, i, blk);
      romulush::compress(left, right, blk);
    }

    left[0] ^= 0b00000010;

    const size_t id = tot_padded_blk_cnt - 1ul;

    get_auth_block(data, dlen, cipher, ctlen, nonce, lfsr, id, blk);
    romulush::compress(left, right, blk);

    std::memset(lfsr, 0, 7);

    romulus_common::encode(key, right, lfsr, 68, tweakey);
    skinny::initialize(&st, left, tweakey);
    skinny::tbc(&st);

    std::memcpy(tag_, st.is, 16);
  }

  bool flg1 = false;

  for (size_t i = 0; i < 16; i++) {
    flg1 |= static_cast<bool>(tag[i] ^ tag_[i]);
  }

  if (!flg1 & (ctlen > 0ul)) {
    uint8_t blk[16];

    std::memset(blk, 0, 16);
    std::memset(lfsr, 0, 7);

    romulus_common::encode(key, blk, lfsr, 66, tweakey);

    skinny::initialize(&st, nonce, tweakey);
    skinny::tbc(&st);

    std::memcpy(state, st.is, 16);

    romulus_common::set_lfsr(lfsr);

    size_t off = 0ul;

    for (size_t i = 0; i < tot_blk_cnt - 1ul; i++) {
      romulus_common::encode(state, blk, lfsr, 64, tweakey);

      skinny::initialize(&st, nonce, tweakey);
      skinny::tbc(&st);

      for (size_t j = 0; j < 16; j++) {
        text[off + j] = cipher[off + j] ^ st.is[j];
      }

      romulus_common::encode(state, blk, lfsr, 65, tweakey);

      skinny::initialize(&st, nonce, tweakey);
      skinny::tbc(&st);

      std::memcpy(state, st.is, 16);

      off += 16ul;
      romulus_common::update_lfsr(lfsr);
    }

    romulus_common::encode(state, blk, lfsr, 64, tweakey);

    skinny::initialize(&st, nonce, tweakey);
    skinny::tbc(&st);

    const size_t read = ctlen - off;

    for (size_t i = 0; i < read; i++) {
      text[off + i] = cipher[off + i] ^ st.is[i];
    }
  }

  return !flg1;
}

}  // namespace romulust
