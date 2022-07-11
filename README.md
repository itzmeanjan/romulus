# romulus
Romulus - The Lightweight Authenticated Encryption and Hash Function

## Motivation

On my journey of implementing all NIST Light Weight Cryptography (LWC) competition's finalists as zero-dependency, easy-to-use, header-only C++ library, Romulus cipher suite is the 7th candidate, whose library implementation is developed & maintained here.

Romulus cipher suite offers following functionalities, which are all based on Skinny-128-384+ tweakable block cipher.

Variant | What does it do ?
--- | ---
Romulus-H | Only cryptographic hash function offered by Romulus cipher suite
Romulus-N | A nonce-based authenticated encryption with associated data scheme, which is the primary AEAD candidate of this cipher suite

> Romulus-{M, T} AEAD coming soon.

### Romulus-H 

Given N -bytes input message, this algorithm computes 32 -bytes digest | N >= 0

### Romulus-N

`encrypt`: Given 16 -bytes secret key, 16 -bytes public message nonce, N -bytes associated data & M -bytes plain text, the encryption algorithm computes M -bytes cipher text and 16 -bytes authentication tag

`decrypt`: Given 16 -bytes secret key, 16 -bytes public message nonce, 16 -bytes authentication tag, N -bytes associated data & M -bytes cipher text, the decryption algorithm computes M -bytes plain text and boolean verification flag

> Avoid reusing same nonce under same secret key

> Note, associated data is never encrypted, only plain text is.

> Ensure presence of truth value in boolean verification flag, returned from `decrypt` routine

---

During implementing Romulus cipher suite, I've followed NIST LWC final round specification of Romulus, which can be found [here](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf). I suggest you go through the same, if you want to have deeper understanding of Romulus.

Other six NIST LWC finalists, I've already worked on, can found

- [Ascon](https://github.com/itzmeanjan/ascon)
- [TinyJambu](https://github.com/itzmeanjan/tinyjambu)
- [Xoodyak](https://github.com/itzmeanjan/xoodyak)
- [Sparkle](https://github.com/itzmeanjan/sparkle)
- [Photon-Beetle](https://github.com/itzmeanjan/photon-beetle)
- [ISAP](https://github.com/itzmeanjan/isap)

Track progress of NIST LWC standardization effort [here](https://csrc.nist.gov/Projects/lightweight-cryptography).

---

**AEAD scheme provides secrecy only for plain text but integrity for both cipher text & associated data.**

## Prerequisites

- C++ compiler such as `g++`/ `clang++`, with C++20 standard library

```fish
$ g++ --version
g++ (Ubuntu 11.2.0-19ubuntu1) 11.2.0
```

- System development tools such as `make`, `cmake`

```fish
$ make --version
GNU Make 3.81

$ cmake --version
cmake version 3.23.2
```

- For testing functional correctness of Romulus cipher suite implementation, you'll also need to have `wget`, `unzip`, `python3`

- Python dependencies can be downloaded using

```fish
python3 -m pip install --user -r wrapper/python/requirements.txt
```

- For benchmarking Romulus cipher suite on CPU, global availability of `google-benchmark` is a must, see [here](https://github.com/google/benchmark/tree/60b16f1#installation) for installation guide

## Testing

For ensuring functional correctness of Romulus cipher suite implementation, I make use of Known Answer Tests submitted with Romulus package to NIST final round call.

For Romulus-H, given input message bytes, I compute 32 -bytes digest using Romulus-H algorithm and check for correctness of computed digest, by comparing it against provided digests in KATs.

While for Romulus-N, given 16 -bytes secret key, 16 -bytes public message nonce, plain text and associated data, I use Romulus-N encrypt routine for computing cipher text and 16 -bytes authentication tag, which I use for byte-by-byte comparison against KATs. Finally an attempt to decrypt back to plain text, using Romulus-N verified decryption algorithm, is also made. 

For executing tests, issue

```fish
make
```

## Benchmarking

For benchmarking Skinny-128-384+ tweakable block cipher, Romulus-H hash function and Romulus-N authenticated encryption/ verified decryption, issue

```fish
make benchmark
```

> If you have CPU scaling enabled, consider checking [guide](https://github.com/google/benchmark/blob/60b16f1/docs/user_guide.md#disabling-cpu-frequency-scaling)

### On ARM Cortex-A72

```fish
2022-07-11T08:20:47+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.15, 0.09, 0.03
--------------------------------------------------------------------------------------------------
Benchmark                                        Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------
bench_romulus::skinny_tbc                     1877 ns         1877 ns       372969 bytes_per_second=8.13137M/s
bench_romulus::romulush/64                   11349 ns        11348 ns        61665 bytes_per_second=5.37832M/s
bench_romulus::romulush/128                  18917 ns        18917 ns        37003 bytes_per_second=6.45303M/s
bench_romulus::romulush/256                  34051 ns        34050 ns        20558 bytes_per_second=7.16998M/s
bench_romulus::romulush/512                  64319 ns        64318 ns        10883 bytes_per_second=7.59165M/s
bench_romulus::romulush/1024                124856 ns       124854 ns         5606 bytes_per_second=7.82166M/s
bench_romulus::romulush/2048                245925 ns       245924 ns         2846 bytes_per_second=7.942M/s
bench_romulus::romulush/4096                488074 ns       488071 ns         1434 bytes_per_second=8.00344M/s
bench_romulus::romulusn_encrypt/32/64        11375 ns        11375 ns        61536 bytes_per_second=8.04874M/s
bench_romulus::romulusn_decrypt/32/64        11529 ns        11529 ns        60714 bytes_per_second=7.94114M/s
bench_romulus::romulusn_encrypt/32/128       18905 ns        18905 ns        37006 bytes_per_second=8.07145M/s
bench_romulus::romulusn_decrypt/32/128       19159 ns        19159 ns        36513 bytes_per_second=7.96448M/s
bench_romulus::romulusn_encrypt/32/256       33962 ns        33962 ns        20611 bytes_per_second=8.08731M/s
bench_romulus::romulusn_decrypt/32/256       34422 ns        34422 ns        20334 bytes_per_second=7.97918M/s
bench_romulus::romulusn_encrypt/32/512       64079 ns        64079 ns        10919 bytes_per_second=8.09629M/s
bench_romulus::romulusn_decrypt/32/512       64969 ns        64969 ns        10777 bytes_per_second=7.98537M/s
bench_romulus::romulusn_encrypt/32/1024     124311 ns       124310 ns         5631 bytes_per_second=8.10135M/s
bench_romulus::romulusn_decrypt/32/1024     126008 ns       126005 ns         5555 bytes_per_second=7.99236M/s
bench_romulus::romulusn_encrypt/32/2048     244819 ns       244814 ns         2859 bytes_per_second=8.10267M/s
bench_romulus::romulusn_decrypt/32/2048     248112 ns       248110 ns         2821 bytes_per_second=7.99501M/s
bench_romulus::romulusn_encrypt/32/4096     485727 ns       485724 ns         1441 bytes_per_second=8.10495M/s
bench_romulus::romulusn_decrypt/32/4096     492341 ns       492338 ns         1422 bytes_per_second=7.99607M/s
```

### On AWS Graviton3

```fish
2022-07-11T08:24:04+00:00
Running ./bench/a.out
Run on (64 X 2100 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB (x64)
  L1 Instruction 64 KiB (x64)
  L2 Unified 1024 KiB (x64)
  L3 Unified 32768 KiB (x1)
Load Average: 0.13, 0.07, 0.02
--------------------------------------------------------------------------------------------------
Benchmark                                        Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------
bench_romulus::skinny_tbc                     1543 ns         1543 ns       453736 bytes_per_second=9.89044M/s
bench_romulus::romulush/64                    9335 ns         9334 ns        75005 bytes_per_second=6.53878M/s
bench_romulus::romulush/128                  15549 ns        15549 ns        45018 bytes_per_second=7.85086M/s
bench_romulus::romulush/256                  28003 ns        28003 ns        25001 bytes_per_second=8.71849M/s
bench_romulus::romulush/512                  52875 ns        52874 ns        13236 bytes_per_second=9.23483M/s
bench_romulus::romulush/1024                102639 ns       102636 ns         6819 bytes_per_second=9.51479M/s
bench_romulus::romulush/2048                202120 ns       202115 ns         3463 bytes_per_second=9.66342M/s
bench_romulus::romulush/4096                401193 ns       401185 ns         1745 bytes_per_second=9.73679M/s
bench_romulus::romulusn_encrypt/32/64         9399 ns         9398 ns        74481 bytes_per_second=9.74139M/s
bench_romulus::romulusn_decrypt/32/64         9387 ns         9386 ns        74588 bytes_per_second=9.75386M/s
bench_romulus::romulusn_encrypt/32/128       15617 ns        15617 ns        44813 bytes_per_second=9.77081M/s
bench_romulus::romulusn_decrypt/32/128       15589 ns        15589 ns        44903 bytes_per_second=9.78843M/s
bench_romulus::romulusn_encrypt/32/256       28058 ns        28057 ns        24951 bytes_per_second=9.78921M/s
bench_romulus::romulusn_decrypt/32/256       28007 ns        28006 ns        24999 bytes_per_second=9.80709M/s
bench_romulus::romulusn_encrypt/32/512       52918 ns        52917 ns        13227 bytes_per_second=9.8041M/s
bench_romulus::romulusn_decrypt/32/512       52822 ns        52821 ns        13251 bytes_per_second=9.82189M/s
bench_romulus::romulusn_encrypt/32/1024     102639 ns       102636 ns         6819 bytes_per_second=9.81215M/s
bench_romulus::romulusn_decrypt/32/1024     102475 ns       102472 ns         6833 bytes_per_second=9.82784M/s
bench_romulus::romulusn_encrypt/32/2048     202124 ns       202120 ns         3464 bytes_per_second=9.81419M/s
bench_romulus::romulusn_decrypt/32/2048     201745 ns       201738 ns         3470 bytes_per_second=9.83275M/s
bench_romulus::romulusn_encrypt/32/4096     400950 ns       400942 ns         1746 bytes_per_second=9.81879M/s
bench_romulus::romulusn_decrypt/32/4096     400342 ns       400332 ns         1749 bytes_per_second=9.83375M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```fish
2022-07-11T12:50:48+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 1.38, 1.74, 1.87
--------------------------------------------------------------------------------------------------
Benchmark                                        Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------
bench_romulus::skinny_tbc                      469 ns          469 ns      1345895 bytes_per_second=32.5648M/s
bench_romulus::romulush/64                    2874 ns         2871 ns       245246 bytes_per_second=21.2614M/s
bench_romulus::romulush/128                   4805 ns         4802 ns       147388 bytes_per_second=25.4223M/s
bench_romulus::romulush/256                   8552 ns         8547 ns        79992 bytes_per_second=28.5653M/s
bench_romulus::romulush/512                  16207 ns        16197 ns        42877 bytes_per_second=30.1465M/s
bench_romulus::romulush/1024                 32371 ns        32244 ns        22246 bytes_per_second=30.2863M/s
bench_romulus::romulush/2048                 67457 ns        66758 ns        10313 bytes_per_second=29.2567M/s
bench_romulus::romulush/4096                132889 ns       131711 ns         5174 bytes_per_second=29.6578M/s
bench_romulus::romulusn_encrypt/32/64         3260 ns         3239 ns       207911 bytes_per_second=28.2666M/s
bench_romulus::romulusn_decrypt/32/64         3241 ns         3219 ns       209197 bytes_per_second=28.4416M/s
bench_romulus::romulusn_encrypt/32/128        5529 ns         5484 ns       133917 bytes_per_second=27.8219M/s
bench_romulus::romulusn_decrypt/32/128        5367 ns         5336 ns       131312 bytes_per_second=28.5934M/s
bench_romulus::romulusn_encrypt/32/256        9656 ns         9533 ns        72442 bytes_per_second=28.8104M/s
bench_romulus::romulusn_decrypt/32/256        9512 ns         9477 ns        70078 bytes_per_second=28.9805M/s
bench_romulus::romulusn_encrypt/32/512       17352 ns        17321 ns        38654 bytes_per_second=29.9514M/s
bench_romulus::romulusn_decrypt/32/512       19228 ns        18881 ns        38612 bytes_per_second=27.4774M/s
bench_romulus::romulusn_encrypt/32/1024      34638 ns        34553 ns        20240 bytes_per_second=29.1457M/s
bench_romulus::romulusn_decrypt/32/1024      35171 ns        35033 ns        20909 bytes_per_second=28.7465M/s
bench_romulus::romulusn_encrypt/32/2048      68921 ns        68589 ns         9814 bytes_per_second=28.9206M/s
bench_romulus::romulusn_decrypt/32/2048      67825 ns        67640 ns         9627 bytes_per_second=29.3265M/s
bench_romulus::romulusn_encrypt/32/4096     138260 ns       137590 ns         5324 bytes_per_second=28.6123M/s
bench_romulus::romulusn_decrypt/32/4096     147715 ns       145607 ns         5283 bytes_per_second=27.0369M/s
```
