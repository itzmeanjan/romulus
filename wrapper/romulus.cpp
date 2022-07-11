#include "aead.hpp"
#include "hash.hpp"

// Thin C wrapper on top of underlying C++ implementation of Romulus-N
// authenticated encryption and Romulus-H hash function, which can be used for
// producing shared library object with conformant C-ABI & used from other
// languages such as Rust, Python

// Function prototype
extern "C" {

void romulush(const uint8_t* const __restrict,  // input message
              const size_t,                     // input message byte length
              uint8_t* const __restrict         // output digest
);

void romulusn_encrypt(
    const uint8_t* const __restrict,  // 128 -bit secret key
    const uint8_t* const __restrict,  // 128 -bit nonce
    const uint8_t* const __restrict,  // N -bytes associated data
    const size_t,  // byte length of associated data = N | >= 0
    const uint8_t* const __restrict,  // M -bytes plain text
    uint8_t* const __restrict,        // M -bytes encrypted text
    const size_t,  // byte length of plain/ encrypted text = M | >= 0
    uint8_t* const __restrict  // 128 -bit authentication tag
);

bool romulusn_decrypt(
    const uint8_t* const __restrict,  // 128 -bit secret key
    const uint8_t* const __restrict,  // 128 -bit nonce
    const uint8_t* const __restrict,  // 128 -bit authentication tag
    const uint8_t* const __restrict,  // N -bytes associated data
    const size_t,  // byte length of associated data = N | >= 0
    const uint8_t* const __restrict,  // M -bytes encrypted text
    uint8_t* const __restrict,        // M -bytes decrypted text
    const size_t  // byte length of encrypted/ decrypted text = M | >= 0
);
}

// Function implementation
extern "C" {

// Given N (>=0) -bytes input message, this routines computes 32 -bytes output
// digest, using Romulus-H hashing algorithm
void romulush(const uint8_t* const __restrict in,  // input message
              const size_t ilen,                   // len(in) | >= 0
              uint8_t* const __restrict out  // 32 -bytes digest, to be computed
) {
  romulus::hash(in, ilen, out);
}

void romulusn_encrypt(
    const uint8_t* const __restrict key,    // 128 -bit secret key
    const uint8_t* const __restrict nonce,  // 128 -bit nonce
    const uint8_t* const __restrict data,   // N -bytes associated data
    const size_t dlen,  // byte length of associated data = N | >= 0
    const uint8_t* const __restrict txt,  // M -bytes plain text
    uint8_t* const __restrict enc,        // M -bytes encrypted text
    const size_t ctlen,  // byte length of plain/ encrypted text = M | >= 0
    uint8_t* const __restrict tag  // 128 -bit authentication tag
) {
  romulus::encrypt_romulusn(key, nonce, data, dlen, txt, enc, ctlen, tag);
}

bool romulusn_decrypt(
    const uint8_t* const __restrict key,    // 128 -bit secret key
    const uint8_t* const __restrict nonce,  // 128 -bit nonce
    const uint8_t* const __restrict tag,    // 128 -bit authentication tag
    const uint8_t* const __restrict data,   // N -bytes associated data
    const size_t dlen,  // byte length of associated data = N | >= 0
    const uint8_t* const __restrict enc,  // M -bytes encrypted text
    uint8_t* const __restrict txt,        // M -bytes decrypted text
    const size_t ctlen  // byte length of encrypted/ decrypted text = M | >= 0
) {
  using namespace romulus;
  return decrypt_romulusn(key, nonce, tag, data, dlen, enc, txt, ctlen);
}
}
