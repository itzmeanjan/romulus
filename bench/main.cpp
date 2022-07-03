#include "bench_hash.hpp"
#include "bench_skinny.hpp"

// register skinny-128-384+ TBC for benchmark
BENCHMARK(bench_romulus::skinny_tbc);

// register Romulus-H hash function for benchmark
BENCHMARK(bench_romulus::romulush)->Arg(64);
BENCHMARK(bench_romulus::romulush)->Arg(128);
BENCHMARK(bench_romulus::romulush)->Arg(256);
BENCHMARK(bench_romulus::romulush)->Arg(512);
BENCHMARK(bench_romulus::romulush)->Arg(1024);
BENCHMARK(bench_romulus::romulush)->Arg(2048);
BENCHMARK(bench_romulus::romulush)->Arg(4096);

// benchmark runner main function
BENCHMARK_MAIN();
