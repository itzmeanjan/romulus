#include "bench_aead.hpp"
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

// register Romulus-N AEAD routines for benchmark
BENCHMARK(bench_romulus::romulusn_encrypt)->Args({32, 64});
BENCHMARK(bench_romulus::romulusn_decrypt)->Args({32, 64});
BENCHMARK(bench_romulus::romulusn_encrypt)->Args({32, 128});
BENCHMARK(bench_romulus::romulusn_decrypt)->Args({32, 128});
BENCHMARK(bench_romulus::romulusn_encrypt)->Args({32, 256});
BENCHMARK(bench_romulus::romulusn_decrypt)->Args({32, 256});
BENCHMARK(bench_romulus::romulusn_encrypt)->Args({32, 512});
BENCHMARK(bench_romulus::romulusn_decrypt)->Args({32, 512});
BENCHMARK(bench_romulus::romulusn_encrypt)->Args({32, 1024});
BENCHMARK(bench_romulus::romulusn_decrypt)->Args({32, 1024});
BENCHMARK(bench_romulus::romulusn_encrypt)->Args({32, 2048});
BENCHMARK(bench_romulus::romulusn_decrypt)->Args({32, 2048});
BENCHMARK(bench_romulus::romulusn_encrypt)->Args({32, 4096});
BENCHMARK(bench_romulus::romulusn_decrypt)->Args({32, 4096});

// register Romulus-M AEAD routines for benchmark
BENCHMARK(bench_romulus::romulusm_encrypt)->Args({32, 64});
BENCHMARK(bench_romulus::romulusm_decrypt)->Args({32, 64});
BENCHMARK(bench_romulus::romulusm_encrypt)->Args({32, 128});
BENCHMARK(bench_romulus::romulusm_decrypt)->Args({32, 128});
BENCHMARK(bench_romulus::romulusm_encrypt)->Args({32, 256});
BENCHMARK(bench_romulus::romulusm_decrypt)->Args({32, 256});
BENCHMARK(bench_romulus::romulusm_encrypt)->Args({32, 512});
BENCHMARK(bench_romulus::romulusm_decrypt)->Args({32, 512});
BENCHMARK(bench_romulus::romulusm_encrypt)->Args({32, 1024});
BENCHMARK(bench_romulus::romulusm_decrypt)->Args({32, 1024});
BENCHMARK(bench_romulus::romulusm_encrypt)->Args({32, 2048});
BENCHMARK(bench_romulus::romulusm_decrypt)->Args({32, 2048});
BENCHMARK(bench_romulus::romulusm_encrypt)->Args({32, 4096});
BENCHMARK(bench_romulus::romulusm_decrypt)->Args({32, 4096});

// benchmark runner main function
BENCHMARK_MAIN();
