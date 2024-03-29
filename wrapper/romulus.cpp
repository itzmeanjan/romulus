#include "romulush.hpp"
#include "romulusm.hpp"
#include "romulusn.hpp"
#include "romulust.hpp"

// Thin C wrapper on top of underlying C++ implementation of Romulus-N
// authenticated encryption and Romulus-H hash function, which can be used for
// producing shared library object with conformant C-ABI & used from other
// languages such as Rust, Python

// Function prototype
extern "C" {

void romulus_hash(const uint8_t* const __restrict,  // input message
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

void romulusm_encrypt(
    const uint8_t* const __restrict,  // 128 -bit secret key
    const uint8_t* const __restrict,  // 128 -bit nonce
    const uint8_t* const __restrict,  // N -bytes associated data
    const size_t,  // byte length of associated data = N | >= 0
    const uint8_t* const __restrict,  // M -bytes plain text
    uint8_t* const __restrict,        // M -bytes encrypted text
    const size_t,  // byte length of plain/ encrypted text = M | >= 0
    uint8_t* const __restrict  // 128 -bit authentication tag
);

bool romulusm_decrypt(
    const uint8_t* const __restrict,  // 128 -bit secret key
    const uint8_t* const __restrict,  // 128 -bit nonce
    const uint8_t* const __restrict,  // 128 -bit authentication tag
    const uint8_t* const __restrict,  // N -bytes associated data
    const size_t,  // byte length of associated data = N | >= 0
    const uint8_t* const __restrict,  // M -bytes encrypted text
    uint8_t* const __restrict,        // M -bytes decrypted text
    const size_t  // byte length of encrypted/ decrypted text = M | >= 0
);

void romulust_encrypt(
    const uint8_t* const __restrict,  // 128 -bit secret key
    const uint8_t* const __restrict,  // 128 -bit nonce
    const uint8_t* const __restrict,  // N -bytes associated data
    const size_t,  // byte length of associated data = N | >= 0
    const uint8_t* const __restrict,  // M -bytes plain text
    uint8_t* const __restrict,        // M -bytes encrypted text
    const size_t,  // byte length of plain/ encrypted text = M | >= 0
    uint8_t* const __restrict  // 128 -bit authentication tag
);

bool romulust_decrypt(
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
void romulus_hash(
    const uint8_t* const __restrict in,  // input message
    const size_t ilen,                   // len(in) | >= 0
    uint8_t* const __restrict out        // 32 -bytes digest, to be computed
) {
  romulush::hash(in, ilen, out);
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
  romulusn::encrypt(key, nonce, data, dlen, txt, enc, ctlen, tag);
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
  using namespace romulusn;
  return decrypt(key, nonce, tag, data, dlen, enc, txt, ctlen);
}

void romulusm_encrypt(
    const uint8_t* const __restrict key,    // 128 -bit secret key
    const uint8_t* const __restrict nonce,  // 128 -bit nonce
    const uint8_t* const __restrict data,   // N -bytes associated data
    const size_t dlen,  // byte length of associated data = N | >= 0
    const uint8_t* const __restrict txt,  // M -bytes plain text
    uint8_t* const __restrict enc,        // M -bytes encrypted text
    const size_t ctlen,  // byte length of plain/ encrypted text = M | >= 0
    uint8_t* const __restrict tag  // 128 -bit authentication tag
) {
  romulusm::encrypt(key, nonce, data, dlen, txt, enc, ctlen, tag);
}

bool romulusm_decrypt(
    const uint8_t* const __restrict key,    // 128 -bit secret key
    const uint8_t* const __restrict nonce,  // 128 -bit nonce
    const uint8_t* const __restrict tag,    // 128 -bit authentication tag
    const uint8_t* const __restrict data,   // N -bytes associated data
    const size_t dlen,  // byte length of associated data = N | >= 0
    const uint8_t* const __restrict enc,  // M -bytes encrypted text
    uint8_t* const __restrict txt,        // M -bytes decrypted text
    const size_t ctlen  // byte length of encrypted/ decrypted text = M | >= 0
) {
  using namespace romulusm;
  return decrypt(key, nonce, tag, data, dlen, enc, txt, ctlen);
}

void romulust_encrypt(
    const uint8_t* const __restrict key,    // 128 -bit secret key
    const uint8_t* const __restrict nonce,  // 128 -bit nonce
    const uint8_t* const __restrict data,   // N -bytes associated data
    const size_t dlen,  // byte length of associated data = N | >= 0
    const uint8_t* const __restrict txt,  // M -bytes plain text
    uint8_t* const __restrict enc,        // M -bytes encrypted text
    const size_t ctlen,  // byte length of plain/ encrypted text = M | >= 0
    uint8_t* const __restrict tag  // 128 -bit authentication tag
) {
  romulust::encrypt(key, nonce, data, dlen, txt, enc, ctlen, tag);
}

bool romulust_decrypt(
    const uint8_t* const __restrict key,    // 128 -bit secret key
    const uint8_t* const __restrict nonce,  // 128 -bit nonce
    const uint8_t* const __restrict tag,    // 128 -bit authentication tag
    const uint8_t* const __restrict data,   // N -bytes associated data
    const size_t dlen,  // byte length of associated data = N | >= 0
    const uint8_t* const __restrict enc,  // M -bytes encrypted text
    uint8_t* const __restrict txt,        // M -bytes decrypted text
    const size_t ctlen  // byte length of encrypted/ decrypted text = M | >= 0
) {
  using namespace romulust;
  return decrypt(key, nonce, tag, data, dlen, enc, txt, ctlen);
}
}
