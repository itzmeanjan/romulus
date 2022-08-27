#pragma once
#include <benchmark/benchmark.h>

#include "skinny.hpp"
#include "utils.hpp"

// Benchmark Romulus AEAD/ Hash routines on CPU
namespace bench_romulus {

// Benchmarks Skinny-128-384+ tweakable block cipher on CPU
static void skinny_tbc(benchmark::State& state) {
  constexpr size_t N = 16;
  constexpr size_t T = 3 * N;

  uint8_t* txt = static_cast<uint8_t*>(std::malloc(N));
  uint8_t* key = static_cast<uint8_t*>(std::malloc(T));

  random_data(txt, N);
  random_data(key, T);

  skinny::state_t st;
  skinny::initialize(&st, txt, key);

  for (auto _ : state) {
    skinny::tbc(&st);

    benchmark::DoNotOptimize(st);
    benchmark::ClobberMemory();
  }

  state.SetBytesProcessed(static_cast<int64_t>(N * state.iterations()));

  std::free(txt);
  std::free(key);
}

}  // namespace bench_romulus
