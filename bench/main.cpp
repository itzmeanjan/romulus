#include "bench_skinny.hpp"

// register skinny-128-384+ TBC for benchmark
BENCHMARK(bench_romulus::skinny_tbc);

// benchmark runner main function
BENCHMARK_MAIN();
