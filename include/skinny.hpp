#pragma once
#include <cstdint>
#include <cstring>

// Skinny-128-384+ Tweakable Block Cipher
namespace skinny {

// Pre-computed 8 -bit S-box for Skinny-128-384+, taken from table 2.1 of
// Romulus specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf
//
// Read description of `SubCells` routine in section 2.3 of Romulus
// specification, for understanding how this S-box is generated.
constexpr uint8_t S8[256] = {
  0x65, 0x4c, 0x6a, 0x42, 0x4b, 0x63, 0x43, 0x6b, 0x55, 0x75, 0x5a, 0x7a, 0x53,
  0x73, 0x5b, 0x7b, 0x35, 0x8c, 0x3a, 0x81, 0x89, 0x33, 0x80, 0x3b, 0x95, 0x25,
  0x98, 0x2a, 0x90, 0x23, 0x99, 0x2b, 0xe5, 0xcc, 0xe8, 0xc1, 0xc9, 0xe0, 0xc0,
  0xe9, 0xd5, 0xf5, 0xd8, 0xf8, 0xd0, 0xf0, 0xd9, 0xf9, 0xa5, 0x1c, 0xa8, 0x12,
  0x1b, 0xa0, 0x13, 0xa9, 0x05, 0xb5, 0x0a, 0xb8, 0x03, 0xb0, 0x0b, 0xb9, 0x32,
  0x88, 0x3c, 0x85, 0x8d, 0x34, 0x84, 0x3d, 0x91, 0x22, 0x9c, 0x2c, 0x94, 0x24,
  0x9d, 0x2d, 0x62, 0x4a, 0x6c, 0x45, 0x4d, 0x64, 0x44, 0x6d, 0x52, 0x72, 0x5c,
  0x7c, 0x54, 0x74, 0x5d, 0x7d, 0xa1, 0x1a, 0xac, 0x15, 0x1d, 0xa4, 0x14, 0xad,
  0x02, 0xb1, 0x0c, 0xbc, 0x04, 0xb4, 0x0d, 0xbd, 0xe1, 0xc8, 0xec, 0xc5, 0xcd,
  0xe4, 0xc4, 0xed, 0xd1, 0xf1, 0xdc, 0xfc, 0xd4, 0xf4, 0xdd, 0xfd, 0x36, 0x8e,
  0x38, 0x82, 0x8b, 0x30, 0x83, 0x39, 0x96, 0x26, 0x9a, 0x28, 0x93, 0x20, 0x9b,
  0x29, 0x66, 0x4e, 0x68, 0x41, 0x49, 0x60, 0x40, 0x69, 0x56, 0x76, 0x58, 0x78,
  0x50, 0x70, 0x59, 0x79, 0xa6, 0x1e, 0xaa, 0x11, 0x19, 0xa3, 0x10, 0xab, 0x06,
  0xb6, 0x08, 0xba, 0x00, 0xb3, 0x09, 0xbb, 0xe6, 0xce, 0xea, 0xc2, 0xcb, 0xe3,
  0xc3, 0xeb, 0xd6, 0xf6, 0xda, 0xfa, 0xd3, 0xf3, 0xdb, 0xfb, 0x31, 0x8a, 0x3e,
  0x86, 0x8f, 0x37, 0x87, 0x3f, 0x92, 0x21, 0x9e, 0x2e, 0x97, 0x27, 0x9f, 0x2f,
  0x61, 0x48, 0x6e, 0x46, 0x4f, 0x67, 0x47, 0x6f, 0x51, 0x71, 0x5e, 0x7e, 0x57,
  0x77, 0x5f, 0x7f, 0xa2, 0x18, 0xae, 0x16, 0x1f, 0xa7, 0x17, 0xaf, 0x01, 0xb2,
  0x0e, 0xbe, 0x07, 0xb7, 0x0f, 0xbf, 0xe2, 0xca, 0xee, 0xc6, 0xcf, 0xe7, 0xc7,
  0xef, 0xd2, 0xf2, 0xde, 0xfe, 0xd7, 0xf7, 0xdf, 0xff
};

// Skinny-128-384+ tweakable block cipher ( TBC ) state, where both internal
// state of 128 -bit & tweakey state of 384 -bit are maintained as four 4x4 byte
// matrices
//
// See section 2.3 of Romulus specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf
struct state
{
  uint8_t is[16];  // 128 -bit internal state
  uint8_t tk1[16]; // first 128 -bit of 384 -bit tweaky state
  uint8_t tk2[16]; // middle 128 -bit of 384 -bit tweaky state
  uint8_t tk3[16]; // last 128 -bit of 384 -bit tweaky state
};

// Initialize both internal state and tweaky state of Skinny-128-384+ TBC
//
// See section 2.3 of Romulus specification
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf
inline static void
initialize(state* const __restrict st,            // TBC state
           const uint8_t* const __restrict p_txt, // 16 -bytes plain text
           const uint8_t* const __restrict tweaky // 48 -bytes tweaky input
)
{
  std::memcpy(st->is, p_txt, 16);

  std::memcpy(st->tk1, tweaky + 0, 16);
  std::memcpy(st->tk2, tweaky + 16, 16);
  std::memcpy(st->tk3, tweaky + 32, 16);
}

}
