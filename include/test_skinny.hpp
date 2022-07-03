#pragma once
#include <cassert>

#include "skinny.hpp"

// Test functional correctness of Romulus AEAD/ Hash functions
namespace test_romulus {

// Tests functional correctness of Skinny-128-384+ TBC, using test vector
// provided at end of section 2.3 of Romulus specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf
static void skinny_tbc() {
  constexpr uint8_t txt[16] = {163, 153, 75,  102, 173, 133, 163, 69,
                               159, 68,  233, 43,  8,   245, 80,  203};
  constexpr uint8_t tweakey[48] = {
      223, 136, 149, 72,  207, 199, 234, 82,  210, 150, 51,  147,
      1,   121, 116, 73,  171, 88,  138, 52,  164, 127, 26,  178,
      223, 233, 200, 41,  63,  190, 169, 165, 171, 26,  250, 194,
      97,  16,  18,  205, 140, 239, 149, 38,  24,  195, 235, 232};
  constexpr uint8_t cipher[16] = {255, 56,  209, 210, 76, 134, 76,  67,
                                  82,  168, 83,  105, 15, 227, 110, 94};

  skinny::state st;
  skinny::initialize(&st, txt, tweakey);
  skinny::tbc(&st);

  for (size_t i = 0; i < 16; i++) {
    assert((cipher[i] ^ st.is[i]) == 0);
  }
}

}  // namespace test_romulus
