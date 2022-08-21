# romulus
Romulus - The Lightweight Authenticated Encryption and Hash Function

## Motivation

On my journey of implementing all NIST Light Weight Cryptography (LWC) competition's finalists as zero-dependency, easy-to-use, header-only C++ library, Romulus cipher suite is the 7th candidate, whose library implementation is developed & maintained here.

Romulus cipher suite offers following functionalities, which are all based on Skinny-128-384+ tweakable block cipher.

Variant | What does it do ?
--- | ---
Romulus-H | Only cryptographic hash function offered by Romulus cipher suite
Romulus-N | A nonce-based authenticated encryption with associated data scheme, which is the primary AEAD candidate of this cipher suite
Romulus-M | A nonce misuse-resistant authenticated encryption with associated data scheme

> Romulus-T AEAD coming soon.

### Romulus-H 

Given N -bytes input message, this algorithm computes 32 -bytes digest | N >= 0

### Romulus-{N, M}

`encrypt`: Given 16 -bytes secret key, 16 -bytes public message nonce, N -bytes associated data & M -bytes plain text, the encryption algorithm computes M -bytes cipher text and 16 -bytes authentication tag

`decrypt`: Given 16 -bytes secret key, 16 -bytes public message nonce, 16 -bytes authentication tag, N -bytes associated data & M -bytes cipher text, the decryption algorithm computes M -bytes plain text and boolean verification flag. If authentication check fails i.e. boolean verification flag is false, unverified plain text is not released, more explicitly plain text bytes are zeroed.

> Avoid reusing same nonce under same secret key

> Note, associated data is never encrypted, only plain text is.

> Ensure presence of truth value in boolean verification flag, returned from `decrypt` routine, before consuming decrypted bytes.

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

```fish
$ python3 --version
Python 3.10.6
```

- Python dependencies can be downloaded using

```fish
python3 -m pip install --user -r wrapper/python/requirements.txt
```

- For benchmarking Romulus cipher suite on CPU, global availability of `google-benchmark` is a must, see [here](https://github.com/google/benchmark/tree/60b16f1#installation) for installation guide

## Testing

For ensuring functional correctness of Romulus cipher suite implementation, I make use of Known Answer Tests submitted with Romulus package to NIST final round call.

For Romulus-H, given input message bytes, I compute 32 -bytes digest using Romulus-H algorithm and check for correctness of computed digest, by comparing it against provided digests in KATs.

While for Romulus-{N, M}, given 16 -bytes secret key, 16 -bytes public message nonce, plain text and associated data, I use Romulus-{N, M} encrypt routine for computing cipher text and 16 -bytes authentication tag, which I use for byte-by-byte comparison against KATs. Finally an attempt to decrypt back to plain text, using Romulus-{N, M} verified decryption algorithm, is also made. 

For executing tests, issue

```fish
make
```

## Benchmarking

For benchmarking Skinny-128-384+ tweakable block cipher, Romulus-H hash function and Romulus-{N, M} authenticated encryption/ verified decryption, issue

```fish
make benchmark
```

> If you have CPU scaling enabled, consider checking [guide](https://github.com/google/benchmark/blob/60b16f1/docs/user_guide.md#disabling-cpu-frequency-scaling)

### On ARM Cortex-A72

```fish
2022-08-19T12:54:00+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.13, 0.03, 0.01
--------------------------------------------------------------------------------------------------
Benchmark                                        Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------
bench_romulus::skinny_tbc                     1877 ns         1877 ns       372974 bytes_per_second=8.13115M/s
bench_romulus::romulush/64                   11357 ns        11357 ns        61614 bytes_per_second=5.37432M/s
bench_romulus::romulush/128                  18930 ns        18929 ns        36980 bytes_per_second=6.44875M/s
bench_romulus::romulush/256                  34063 ns        34062 ns        20551 bytes_per_second=7.16752M/s
bench_romulus::romulush/512                  64333 ns        64331 ns        10881 bytes_per_second=7.59014M/s
bench_romulus::romulush/1024                124863 ns       124862 ns         5606 bytes_per_second=7.82114M/s
bench_romulus::romulush/2048                245931 ns       245930 ns         2846 bytes_per_second=7.9418M/s
bench_romulus::romulush/4096                488111 ns       488088 ns         1434 bytes_per_second=8.00316M/s
bench_romulus::romulusn_encrypt/32/64        11375 ns        11375 ns        61534 bytes_per_second=8.04845M/s
bench_romulus::romulusn_decrypt/32/64        11529 ns        11528 ns        60708 bytes_per_second=7.94146M/s
bench_romulus::romulusn_encrypt/32/128       18904 ns        18903 ns        37029 bytes_per_second=8.07199M/s
bench_romulus::romulusn_decrypt/32/128       19159 ns        19159 ns        36536 bytes_per_second=7.96427M/s
bench_romulus::romulusn_encrypt/32/256       33962 ns        33962 ns        20612 bytes_per_second=8.08731M/s
bench_romulus::romulusn_decrypt/32/256       34421 ns        34420 ns        20335 bytes_per_second=7.97969M/s
bench_romulus::romulusn_encrypt/32/512       64078 ns        64078 ns        10923 bytes_per_second=8.09637M/s
bench_romulus::romulusn_decrypt/32/512       64953 ns        64951 ns        10777 bytes_per_second=7.98754M/s
bench_romulus::romulusn_encrypt/32/1024     124310 ns       124309 ns         5631 bytes_per_second=8.10143M/s
bench_romulus::romulusn_decrypt/32/1024     126006 ns       126005 ns         5555 bytes_per_second=7.99241M/s
bench_romulus::romulusn_encrypt/32/2048     244779 ns       244778 ns         2860 bytes_per_second=8.10386M/s
bench_romulus::romulusn_decrypt/32/2048     248110 ns       248109 ns         2821 bytes_per_second=7.99505M/s
bench_romulus::romulusn_encrypt/32/4096     485795 ns       485786 ns         1441 bytes_per_second=8.10391M/s
bench_romulus::romulusn_decrypt/32/4096     492380 ns       492368 ns         1422 bytes_per_second=7.99558M/s
bench_romulus::romulusm_encrypt/32/64        15249 ns        15249 ns        45904 bytes_per_second=6.00398M/s
bench_romulus::romulusm_decrypt/32/64        15282 ns        15282 ns        45804 bytes_per_second=5.99094M/s
bench_romulus::romulusm_encrypt/32/128       26662 ns        26662 ns        26260 bytes_per_second=5.72315M/s
bench_romulus::romulusm_decrypt/32/128       26671 ns        26670 ns        26246 bytes_per_second=5.72135M/s
bench_romulus::romulusm_encrypt/32/256       49471 ns        49470 ns        14150 bytes_per_second=5.552M/s
bench_romulus::romulusm_decrypt/32/256       49446 ns        49446 ns        14157 bytes_per_second=5.55475M/s
bench_romulus::romulusm_encrypt/32/512       95100 ns        95098 ns         7360 bytes_per_second=5.45539M/s
bench_romulus::romulusm_decrypt/32/512       95001 ns        95000 ns         7368 bytes_per_second=5.46101M/s
bench_romulus::romulusm_encrypt/32/1024     186354 ns       186353 ns         3756 bytes_per_second=5.40415M/s
bench_romulus::romulusm_decrypt/32/1024     186104 ns       186103 ns         3761 bytes_per_second=5.4114M/s
bench_romulus::romulusm_encrypt/32/2048     368877 ns       368874 ns         1898 bytes_per_second=5.37756M/s
bench_romulus::romulusm_decrypt/32/2048     368325 ns       368322 ns         1900 bytes_per_second=5.38562M/s
bench_romulus::romulusm_encrypt/32/4096     733971 ns       733966 ns          954 bytes_per_second=5.36369M/s
bench_romulus::romulusm_decrypt/32/4096     732837 ns       732832 ns          955 bytes_per_second=5.37199M/s
```

### On AWS Graviton3

```fish
2022-08-19T12:51:08+00:00
Running ./bench/a.out
Run on (64 X 2100 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB (x64)
  L1 Instruction 64 KiB (x64)
  L2 Unified 1024 KiB (x64)
  L3 Unified 32768 KiB (x1)
Load Average: 0.07, 0.02, 0.00
--------------------------------------------------------------------------------------------------
Benchmark                                        Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------
bench_romulus::skinny_tbc                     1544 ns         1544 ns       453409 bytes_per_second=9.88404M/s
bench_romulus::romulush/64                    9348 ns         9348 ns        74864 bytes_per_second=6.52952M/s
bench_romulus::romulush/128                  15575 ns        15575 ns        44950 bytes_per_second=7.8377M/s
bench_romulus::romulush/256                  28023 ns        28022 ns        24977 bytes_per_second=8.71238M/s
bench_romulus::romulush/512                  52923 ns        52921 ns        13226 bytes_per_second=9.22665M/s
bench_romulus::romulush/1024                102740 ns       102738 ns         6814 bytes_per_second=9.50537M/s
bench_romulus::romulush/2048                202330 ns       202325 ns         3459 bytes_per_second=9.65339M/s
bench_romulus::romulush/4096                401557 ns       401545 ns         1743 bytes_per_second=9.72805M/s
bench_romulus::romulusn_encrypt/32/64         9375 ns         9375 ns        74703 bytes_per_second=9.76566M/s
bench_romulus::romulusn_decrypt/32/64         9401 ns         9401 ns        74483 bytes_per_second=9.73868M/s
bench_romulus::romulusn_encrypt/32/128       15586 ns        15586 ns        44894 bytes_per_second=9.78998M/s
bench_romulus::romulusn_decrypt/32/128       15602 ns        15602 ns        44852 bytes_per_second=9.78013M/s
bench_romulus::romulusn_encrypt/32/256       28018 ns        28018 ns        25000 bytes_per_second=9.80308M/s
bench_romulus::romulusn_decrypt/32/256       28012 ns        28011 ns        24990 bytes_per_second=9.80525M/s
bench_romulus::romulusn_encrypt/32/512       52882 ns        52881 ns        13239 bytes_per_second=9.81071M/s
bench_romulus::romulusn_decrypt/32/512       52819 ns        52818 ns        13253 bytes_per_second=9.82244M/s
bench_romulus::romulusn_encrypt/32/1024     102526 ns       102524 ns         6826 bytes_per_second=9.82286M/s
bench_romulus::romulusn_decrypt/32/1024     102416 ns       102413 ns         6834 bytes_per_second=9.83348M/s
bench_romulus::romulusn_encrypt/32/2048     201938 ns       201934 ns         3465 bytes_per_second=9.82322M/s
bench_romulus::romulusn_decrypt/32/2048     201599 ns       201593 ns         3472 bytes_per_second=9.83985M/s
bench_romulus::romulusn_encrypt/32/4096     400620 ns       400607 ns         1747 bytes_per_second=9.82701M/s
bench_romulus::romulusn_decrypt/32/4096     399989 ns       399974 ns         1750 bytes_per_second=9.84255M/s
bench_romulus::romulusm_encrypt/32/64        12552 ns        12552 ns        55777 bytes_per_second=7.29412M/s
bench_romulus::romulusm_decrypt/32/64        12551 ns        12551 ns        55752 bytes_per_second=7.29456M/s
bench_romulus::romulusm_encrypt/32/128       21917 ns        21916 ns        31939 bytes_per_second=6.96238M/s
bench_romulus::romulusm_decrypt/32/128       21920 ns        21919 ns        31929 bytes_per_second=6.96131M/s
bench_romulus::romulusm_encrypt/32/256       40661 ns        40660 ns        17216 bytes_per_second=6.75498M/s
bench_romulus::romulusm_decrypt/32/256       40662 ns        40661 ns        17216 bytes_per_second=6.75482M/s
bench_romulus::romulusm_encrypt/32/512       78126 ns        78124 ns         8959 bytes_per_second=6.64075M/s
bench_romulus::romulusm_decrypt/32/512       78139 ns        78136 ns         8958 bytes_per_second=6.63967M/s
bench_romulus::romulusm_encrypt/32/1024     153067 ns       153062 ns         4574 bytes_per_second=6.57956M/s
bench_romulus::romulusm_decrypt/32/1024     153058 ns       153052 ns         4573 bytes_per_second=6.57998M/s
bench_romulus::romulusm_encrypt/32/2048     302916 ns       302909 ns         2311 bytes_per_second=6.54863M/s
bench_romulus::romulusm_decrypt/32/2048     302908 ns       302902 ns         2311 bytes_per_second=6.54879M/s
bench_romulus::romulusm_encrypt/32/4096     602605 ns       602592 ns         1162 bytes_per_second=6.53306M/s
bench_romulus::romulusm_decrypt/32/4096     602620 ns       602607 ns         1161 bytes_per_second=6.53289M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```fish
2022-08-19T16:48:01+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 1.81, 1.61, 1.44
--------------------------------------------------------------------------------------------------
Benchmark                                        Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------
bench_romulus::skinny_tbc                      527 ns          519 ns      1105321 bytes_per_second=29.3926M/s
bench_romulus::romulush/64                    2946 ns         2939 ns       224047 bytes_per_second=20.7684M/s
bench_romulus::romulush/128                   5052 ns         5009 ns       132498 bytes_per_second=24.3686M/s
bench_romulus::romulush/256                   9666 ns         9552 ns        80816 bytes_per_second=25.5596M/s
bench_romulus::romulush/512                  17837 ns        17685 ns        39321 bytes_per_second=27.61M/s
bench_romulus::romulush/1024                 34904 ns        34484 ns        21419 bytes_per_second=28.3191M/s
bench_romulus::romulush/2048                 63325 ns        63246 ns        11029 bytes_per_second=30.8814M/s
bench_romulus::romulush/4096                133427 ns       132470 ns         4958 bytes_per_second=29.4877M/s
bench_romulus::romulusn_encrypt/32/64         3380 ns         3344 ns       212037 bytes_per_second=27.3755M/s
bench_romulus::romulusn_decrypt/32/64         3550 ns         3355 ns       221011 bytes_per_second=27.2856M/s
bench_romulus::romulusn_encrypt/32/128        5088 ns         5086 ns       126683 bytes_per_second=30.0029M/s
bench_romulus::romulusn_decrypt/32/128        5481 ns         5437 ns       128013 bytes_per_second=28.0665M/s
bench_romulus::romulusn_encrypt/32/256        9527 ns         9479 ns        73234 bytes_per_second=28.9748M/s
bench_romulus::romulusn_decrypt/32/256        9201 ns         9196 ns        75475 bytes_per_second=29.8678M/s
bench_romulus::romulusn_encrypt/32/512       17270 ns        17264 ns        38737 bytes_per_second=30.0516M/s
bench_romulus::romulusn_decrypt/32/512       17179 ns        17174 ns        40424 bytes_per_second=30.2091M/s
bench_romulus::romulusn_encrypt/32/1024      33311 ns        33291 ns        20895 bytes_per_second=30.2505M/s
bench_romulus::romulusn_decrypt/32/1024      33388 ns        33364 ns        20915 bytes_per_second=30.1845M/s
bench_romulus::romulusn_encrypt/32/2048      66414 ns        66342 ns        10486 bytes_per_second=29.9004M/s
bench_romulus::romulusn_decrypt/32/2048      65836 ns        65791 ns        10494 bytes_per_second=30.1506M/s
bench_romulus::romulusn_encrypt/32/4096     130895 ns       130827 ns         5373 bytes_per_second=30.0913M/s
bench_romulus::romulusn_decrypt/32/4096     130697 ns       130609 ns         5275 bytes_per_second=30.1416M/s
bench_romulus::romulusm_encrypt/32/64         4137 ns         4134 ns       171531 bytes_per_second=22.1475M/s
bench_romulus::romulusm_decrypt/32/64         4109 ns         4107 ns       171336 bytes_per_second=22.2913M/s
bench_romulus::romulusm_encrypt/32/128        7204 ns         7196 ns        96456 bytes_per_second=21.204M/s
bench_romulus::romulusm_decrypt/32/128        7208 ns         7203 ns        96258 bytes_per_second=21.1825M/s
bench_romulus::romulusm_encrypt/32/256       14404 ns        14284 ns        52804 bytes_per_second=19.2278M/s
bench_romulus::romulusm_decrypt/32/256       13976 ns        13838 ns        48482 bytes_per_second=19.8476M/s
bench_romulus::romulusm_encrypt/32/512       26146 ns        26026 ns        25720 bytes_per_second=19.9342M/s
bench_romulus::romulusm_decrypt/32/512       25769 ns        25687 ns        26271 bytes_per_second=20.197M/s
bench_romulus::romulusm_encrypt/32/1024      50586 ns        50521 ns        13841 bytes_per_second=19.9338M/s
bench_romulus::romulusm_decrypt/32/1024      49625 ns        49609 ns        13657 bytes_per_second=20.3004M/s
bench_romulus::romulusm_encrypt/32/2048      98420 ns        98369 ns         7025 bytes_per_second=20.1653M/s
bench_romulus::romulusm_decrypt/32/2048      97950 ns        97899 ns         6982 bytes_per_second=20.2621M/s
bench_romulus::romulusm_encrypt/32/4096     195871 ns       195746 ns         3520 bytes_per_second=20.1116M/s
bench_romulus::romulusm_decrypt/32/4096     194782 ns       194569 ns         3518 bytes_per_second=20.2333M/s
```
