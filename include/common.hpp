#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>

// Common functions required for Romulus-{N, M, T} AEAD
namespace romulus_common {

// Sets 56 -bit linear feedback shift register to its intial value i.e.
// `1 % F_56(x)`, in little endian order | F_56(x) = x^56 + x^7 + x^4 + x^2 + 1
//
// See section 2.4.1 of Romulus specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf
inline static void set_lfsr(uint8_t* const lfsr) {
  std::memset(lfsr + 1, 0, 6);
  lfsr[0] = 1;
}

// Single step updation of 56 -bit linear feedback shift register using
// x_(i+1) = 2 * x_i % F_56(x) | F_56(x) = x^56 + x^7 + x^4 + x^2 + 1
//
// See updation formula in top of page 12 of Romulus specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf
inline static void update_lfsr(uint8_t* const lfsr) {
  const uint8_t z55 = lfsr[0] >> 7;

  lfsr[0] = (lfsr[0] << 1) | (lfsr[1] >> 7);
  lfsr[1] = (lfsr[1] << 1) | (lfsr[2] >> 7);
  lfsr[2] = (lfsr[2] << 1) | (lfsr[3] >> 7);
  lfsr[3] = (lfsr[3] << 1) | (lfsr[4] >> 7);
  lfsr[4] = (lfsr[4] << 1) | (lfsr[5] >> 7);
  lfsr[5] = (lfsr[5] << 1) | (lfsr[6] >> 7);

  const uint8_t tmp = (z55 << 7) | (z55 << 4) | (z55 << 2) | z55;

  lfsr[6] = (lfsr[6] << 1) ^ tmp;
}

// Tweakey encoding for Romulus-{N, M, T}, which computes 384 -bit tweakey, to
// be used as input to Skinny-128-384+ TBC
//
// See page 13 of Romulus specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf
inline static void encode(
    const uint8_t* const __restrict key,      // 128 -bit key
    const uint8_t* const __restrict tweak,    // 128 -bit twaek
    const uint8_t* const __restrict counter,  // 56 -bit LFSR counter
    const uint8_t d_sep,                      // 8 -bit domain seperator
    uint8_t* const __restrict tweakey         // 384 -bit tweakey ( computed )
) {
  std::memcpy(tweakey, counter, 7);
  std::memcpy(tweakey + 7, &d_sep, 1);
  std::memset(tweakey + 8, 0, 8);
  std::memcpy(tweakey + 16, tweak, 16);
  std::memcpy(tweakey + 32, key, 16);
}

// State update function for Romulus-{N, M}, as defined in section 2.4.2 of
// Romulus specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf
inline static void rho(
    uint8_t* const __restrict state,      // 128 -bit state ( gets updated )
    const uint8_t* const __restrict txt,  // 128 -bit message block
    uint8_t* const __restrict cipher      // 128 -bit cipher block
) {
  uint8_t gs[16];

  for (size_t i = 0; i < 16; i++) {
    const uint8_t b7 = state[i] >> 7;
    const uint8_t b0 = state[i] & 1;

    gs[i] = ((b7 ^ b0) << 7) | (state[i] >> 1);
  }

  for (size_t i = 0; i < 16; i++) {
    cipher[i] = txt[i] ^ gs[i];
  }

  for (size_t i = 0; i < 16; i++) {
    state[i] ^= txt[i];
  }
}

// Inverse state update function for Romulus-{N, M}, as defined in section 2.4.2
// of Romulus specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf
inline static void rho_inv(
    uint8_t* const __restrict state,         // 128 -bit state ( gets updated )
    const uint8_t* const __restrict cipher,  // 128 -bit cipher block
    uint8_t* const __restrict txt            // 128 -bit message block
) {
  uint8_t gs[16];

  for (size_t i = 0; i < 16; i++) {
    const uint8_t b0 = state[i] >> 7;
    const uint8_t b7 = state[i] & 1;

    gs[i] = (state[i] << 1) | (b7 ^ b0);
  }

  for (size_t i = 0; i < 16; i++) {
    txt[i] = cipher[i] ^ gs[i];
  }

  for (size_t i = 0; i < 16; i++) {
    state[i] ^= txt[i];
  }
}

}  // namespace romulus_common
