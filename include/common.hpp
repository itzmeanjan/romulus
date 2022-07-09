#pragma once
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

}  // namespace romulus_common
