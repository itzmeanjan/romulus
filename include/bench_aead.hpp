#pragma once
#include <benchmark/benchmark.h>

#include <cassert>

#include "romulusn.hpp"
#include "utils.hpp"

// Benchmark Romulus AEAD/ Hash routines on CPU
namespace bench_romulus {

// Benchmarks Romulus-N authenticated encryption routine on CPU, with variable
// length associated data and plain text bytes
static void romulusn_encrypt(benchmark::State &state) {
  constexpr size_t kntlen = 16;

  const size_t dlen = state.range(0);
  const size_t ctlen = state.range(1);

  uint8_t *key = static_cast<uint8_t *>(std::malloc(kntlen));
  uint8_t *nonce = static_cast<uint8_t *>(std::malloc(kntlen));
  uint8_t *tag = static_cast<uint8_t *>(std::malloc(kntlen));
  uint8_t *data = static_cast<uint8_t *>(std::malloc(dlen));
  uint8_t *txt = static_cast<uint8_t *>(std::malloc(ctlen));
  uint8_t *enc = static_cast<uint8_t *>(std::malloc(ctlen));
  uint8_t *dec = static_cast<uint8_t *>(std::malloc(ctlen));

  random_data(key, kntlen);
  random_data(nonce, kntlen);
  random_data(data, dlen);
  random_data(txt, ctlen);

  std::memset(tag, 0, kntlen);
  std::memset(enc, 0, ctlen);
  std::memset(dec, 0, ctlen);

  for (auto _ : state) {
    romulusn::encrypt(key, nonce, data, dlen, txt, enc, ctlen, tag);

    benchmark::DoNotOptimize(enc);
    benchmark::DoNotOptimize(tag);
    benchmark::ClobberMemory();
  }

  bool f = false;
  f = romulusn::decrypt(key, nonce, tag, data, dlen, enc, dec, ctlen);
  assert(f);

  for (size_t i = 0; i < ctlen; i++) {
    assert((txt[i] ^ dec[i]) == 0);
  }

  const size_t per_itr_data = dlen + ctlen;
  const size_t total_data = per_itr_data * state.iterations();

  state.SetBytesProcessed(static_cast<int64_t>(total_data));

  std::free(key);
  std::free(nonce);
  std::free(tag);
  std::free(data);
  std::free(txt);
  std::free(enc);
  std::free(dec);
}

// Benchmarks Romulus-N verified decryption routine on CPU, with variable
// length associated data and plain/ cipher text bytes
static void romulusn_decrypt(benchmark::State &state) {
  constexpr size_t kntlen = 16;

  const size_t dlen = state.range(0);
  const size_t ctlen = state.range(1);

  uint8_t *key = static_cast<uint8_t *>(std::malloc(kntlen));
  uint8_t *nonce = static_cast<uint8_t *>(std::malloc(kntlen));
  uint8_t *tag = static_cast<uint8_t *>(std::malloc(kntlen));
  uint8_t *data = static_cast<uint8_t *>(std::malloc(dlen));
  uint8_t *txt = static_cast<uint8_t *>(std::malloc(ctlen));
  uint8_t *enc = static_cast<uint8_t *>(std::malloc(ctlen));
  uint8_t *dec = static_cast<uint8_t *>(std::malloc(ctlen));

  random_data(key, kntlen);
  random_data(nonce, kntlen);
  random_data(data, dlen);
  random_data(txt, ctlen);

  std::memset(tag, 0, kntlen);
  std::memset(enc, 0, ctlen);
  std::memset(dec, 0, ctlen);

  romulusn::encrypt(key, nonce, data, dlen, txt, enc, ctlen, tag);

  for (auto _ : state) {
    bool f = false;
    f = romulusn::decrypt(key, nonce, tag, data, dlen, enc, dec, ctlen);

    benchmark::DoNotOptimize(f);
    benchmark::DoNotOptimize(dec);
    benchmark::ClobberMemory();
  }

  for (size_t i = 0; i < ctlen; i++) {
    assert((txt[i] ^ dec[i]) == 0);
  }

  const size_t per_itr_data = dlen + ctlen;
  const size_t total_data = per_itr_data * state.iterations();

  state.SetBytesProcessed(static_cast<int64_t>(total_data));

  std::free(key);
  std::free(nonce);
  std::free(tag);
  std::free(data);
  std::free(txt);
  std::free(enc);
  std::free(dec);
}

}  // namespace bench_romulus
