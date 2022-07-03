#pragma once
#include <benchmark/benchmark.h>

#include "hash.hpp"
#include "utils.hpp"

// Benchmark Romulus AEAD/ Hash routines on CPU
namespace bench_romulus {

// Benchmarks Romulus-H hash function ( with variable length input sizes )
// on CPU
static void romulush(benchmark::State& state) {
  const size_t mlen = state.range(0);
  constexpr size_t dlen = 32;

  uint8_t* msg = static_cast<uint8_t*>(std::malloc(mlen));
  uint8_t* dig = static_cast<uint8_t*>(std::malloc(dlen));

  random_data(msg, mlen);

  for (auto _ : state) {
    romulus::hash(msg, mlen, dig);

    benchmark::DoNotOptimize(dig);
    benchmark::ClobberMemory();
  }

  state.SetBytesProcessed(static_cast<int64_t>(mlen * state.iterations()));

  std::free(msg);
  std::free(dig);
}

}  // namespace bench_romulus
