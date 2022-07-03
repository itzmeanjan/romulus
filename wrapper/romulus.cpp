#include "hash.hpp"

// Thin C wrapper on top of underlying C++ implementation of Romulus-H hash
// function, which can be used for producing shared library object with C-ABI &
// used from other languages such as Rust, Python

// Function prototype
extern "C" {

void romulush(const uint8_t* const __restrict,  // input message
              const size_t,                     // input message byte length
              uint8_t* const __restrict         // output digest
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
}
