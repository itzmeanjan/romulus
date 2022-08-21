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
Romulus-T | A leakage-resistant authenticated encryption with associated data scheme

### Romulus-H

Given N -bytes input message, this algorithm computes 32 -bytes digest | N >= 0

### Romulus-{N, M, T}

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

$ wget --version
GNU Wget 1.21.2 built on linux-gnu.

$ unzip -v
UnZip 6.00 of 20 April 2009, by Debian. Original by Info-ZIP.
```

- Python dependencies can be downloaded using

```fish
python3 -m pip install --user -r wrapper/python/requirements.txt
```

- For benchmarking Romulus cipher suite on CPU, global availability of `google-benchmark` is a must, see [here](https://github.com/google/benchmark/tree/60b16f1#installation) for installation guide

## Testing

For ensuring functional correctness of Romulus cipher suite implementation, I make use of Known Answer Tests submitted with Romulus package to NIST final round call.

For Romulus-H, given input message bytes, I compute 32 -bytes digest using Romulus-H algorithm and check for correctness of computed digest, by comparing it against provided digests in KATs.

While for Romulus-{N, M, T}, given 16 -bytes secret key, 16 -bytes public message nonce, plain text and associated data, I use Romulus-{N, M, T} encrypt routine for computing cipher text and 16 -bytes authentication tag, which I use for byte-by-byte comparison against KATs. Finally an attempt to decrypt back to plain text, using Romulus-{N, M, T} verified decryption algorithm, is also made. 

For executing tests, issue

```fish
make
```

## Benchmarking

For benchmarking Skinny-128-384+ tweakable block cipher, Romulus-H hash function and Romulus-{N, M, T} authenticated encryption/ verified decryption, issue

```fish
make benchmark
```

> If you have CPU scaling enabled, consider checking [guide](https://github.com/google/benchmark/blob/60b16f1/docs/user_guide.md#disabling-cpu-frequency-scaling)

### On ARM Cortex-A72

```fish
2022-08-21T19:35:57+00:00
Running ./bench/a.out
Run on (16 X 166.66 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 48 KiB (x16)
  L2 Unified 2048 KiB (x4)
Load Average: 0.08, 0.02, 0.01
--------------------------------------------------------------------------------------------------
Benchmark                                        Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------
bench_romulus::skinny_tbc                     1877 ns         1877 ns       372911 bytes_per_second=8.13129M/s
bench_romulus::romulush/64                   11355 ns        11355 ns        61615 bytes_per_second=5.3753M/s
bench_romulus::romulush/128                  18930 ns        18930 ns        36979 bytes_per_second=6.44864M/s
bench_romulus::romulush/256                  34062 ns        34062 ns        20550 bytes_per_second=7.16753M/s
bench_romulus::romulush/512                  64327 ns        64325 ns        10880 bytes_per_second=7.59079M/s
bench_romulus::romulush/1024                124866 ns       124865 ns         5606 bytes_per_second=7.82094M/s
bench_romulus::romulush/2048                245944 ns       245939 ns         2846 bytes_per_second=7.94151M/s
bench_romulus::romulush/4096                488113 ns       488103 ns         1434 bytes_per_second=8.00293M/s
bench_romulus::romulusn_encrypt/32/64        11376 ns        11376 ns        61524 bytes_per_second=8.04781M/s
bench_romulus::romulusn_decrypt/32/64        11537 ns        11537 ns        60672 bytes_per_second=7.93561M/s
bench_romulus::romulusn_encrypt/32/128       18905 ns        18905 ns        37025 bytes_per_second=8.07114M/s
bench_romulus::romulusn_decrypt/32/128       19170 ns        19169 ns        36516 bytes_per_second=7.96012M/s
bench_romulus::romulusn_encrypt/32/256       33965 ns        33964 ns        20610 bytes_per_second=8.08675M/s
bench_romulus::romulusn_decrypt/32/256       34432 ns        34432 ns        20329 bytes_per_second=7.97678M/s
bench_romulus::romulusn_encrypt/32/512       64263 ns        64262 ns        10891 bytes_per_second=8.07316M/s
bench_romulus::romulusn_decrypt/32/512       65139 ns        65136 ns        10747 bytes_per_second=7.96484M/s
bench_romulus::romulusn_encrypt/32/1024     124318 ns       124314 ns         5631 bytes_per_second=8.10109M/s
bench_romulus::romulusn_decrypt/32/1024     126018 ns       126015 ns         5555 bytes_per_second=7.99172M/s
bench_romulus::romulusn_encrypt/32/2048     245061 ns       245059 ns         2857 bytes_per_second=8.09454M/s
bench_romulus::romulusn_decrypt/32/2048     248121 ns       248119 ns         2821 bytes_per_second=7.99471M/s
bench_romulus::romulusn_encrypt/32/4096     486000 ns       485996 ns         1440 bytes_per_second=8.1004M/s
bench_romulus::romulusn_decrypt/32/4096     492365 ns       492356 ns         1422 bytes_per_second=7.99578M/s
bench_romulus::romulusm_encrypt/32/64        15250 ns        15249 ns        45902 bytes_per_second=6.00368M/s
bench_romulus::romulusm_decrypt/32/64        15283 ns        15283 ns        45806 bytes_per_second=5.9906M/s
bench_romulus::romulusm_encrypt/32/128       26657 ns        26656 ns        26260 bytes_per_second=5.72426M/s
bench_romulus::romulusm_decrypt/32/128       26673 ns        26672 ns        26244 bytes_per_second=5.7208M/s
bench_romulus::romulusm_encrypt/32/256       49472 ns        49471 ns        14150 bytes_per_second=5.55189M/s
bench_romulus::romulusm_decrypt/32/256       49449 ns        49448 ns        14156 bytes_per_second=5.55446M/s
bench_romulus::romulusm_encrypt/32/512       95198 ns        95197 ns         7356 bytes_per_second=5.44975M/s
bench_romulus::romulusm_decrypt/32/512       95258 ns        95257 ns         7350 bytes_per_second=5.44632M/s
bench_romulus::romulusm_encrypt/32/1024     186362 ns       186360 ns         3756 bytes_per_second=5.40394M/s
bench_romulus::romulusm_decrypt/32/1024     186121 ns       186116 ns         3761 bytes_per_second=5.41105M/s
bench_romulus::romulusm_encrypt/32/2048     369156 ns       369146 ns         1896 bytes_per_second=5.3736M/s
bench_romulus::romulusm_decrypt/32/2048     368342 ns       368335 ns         1900 bytes_per_second=5.38543M/s
bench_romulus::romulusm_encrypt/32/4096     734220 ns       734207 ns          953 bytes_per_second=5.36193M/s
bench_romulus::romulusm_decrypt/32/4096     732788 ns       732783 ns          955 bytes_per_second=5.37235M/s
bench_romulus::romulust_encrypt/32/64        35990 ns        35989 ns        19449 bytes_per_second=2.54391M/s
bench_romulus::romulust_decrypt/32/64        35956 ns        35955 ns        19469 bytes_per_second=2.5463M/s
bench_romulus::romulust_encrypt/32/128       58657 ns        58656 ns        11933 bytes_per_second=2.60139M/s
bench_romulus::romulust_decrypt/32/128       58612 ns        58610 ns        11942 bytes_per_second=2.60342M/s
bench_romulus::romulust_encrypt/32/256      104050 ns       104048 ns         6731 bytes_per_second=2.63973M/s
bench_romulus::romulust_decrypt/32/256      103927 ns       103924 ns         6735 bytes_per_second=2.64287M/s
bench_romulus::romulust_encrypt/32/512      194876 ns       194872 ns         3593 bytes_per_second=2.66225M/s
bench_romulus::romulust_decrypt/32/512      194550 ns       194546 ns         3595 bytes_per_second=2.66671M/s
bench_romulus::romulust_encrypt/32/1024     376029 ns       376016 ns         1862 bytes_per_second=2.67829M/s
bench_romulus::romulust_decrypt/32/1024     375810 ns       375800 ns         1863 bytes_per_second=2.67983M/s
bench_romulus::romulust_encrypt/32/2048     738817 ns       738804 ns          947 bytes_per_second=2.68494M/s
bench_romulus::romulust_decrypt/32/2048     738279 ns       738274 ns          948 bytes_per_second=2.68686M/s
bench_romulus::romulust_encrypt/32/4096    1464244 ns      1464199 ns          478 bytes_per_second=2.68868M/s
bench_romulus::romulust_decrypt/32/4096    1463337 ns      1463297 ns          478 bytes_per_second=2.69034M/s
```

### On AWS Graviton3

```fish
2022-08-21T19:37:45+00:00
Running ./bench/a.out
Run on (64 X 2100 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB (x64)
  L1 Instruction 64 KiB (x64)
  L2 Unified 1024 KiB (x64)
  L3 Unified 32768 KiB (x1)
Load Average: 0.00, 0.00, 0.00
--------------------------------------------------------------------------------------------------
Benchmark                                        Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------
bench_romulus::skinny_tbc                     1543 ns         1543 ns       453543 bytes_per_second=9.88907M/s
bench_romulus::romulush/64                    9351 ns         9351 ns        74863 bytes_per_second=6.52742M/s
bench_romulus::romulush/128                  15579 ns        15579 ns        44944 bytes_per_second=7.8357M/s
bench_romulus::romulush/256                  28028 ns        28027 ns        24973 bytes_per_second=8.71086M/s
bench_romulus::romulush/512                  52924 ns        52923 ns        13226 bytes_per_second=9.22629M/s
bench_romulus::romulush/1024                102733 ns       102731 ns         6814 bytes_per_second=9.50602M/s
bench_romulus::romulush/2048                202323 ns       202319 ns         3460 bytes_per_second=9.65371M/s
bench_romulus::romulush/4096                401538 ns       401524 ns         1743 bytes_per_second=9.72856M/s
bench_romulus::romulusn_encrypt/32/64         9398 ns         9398 ns        74482 bytes_per_second=9.74154M/s
bench_romulus::romulusn_decrypt/32/64         9405 ns         9405 ns        74420 bytes_per_second=9.73467M/s
bench_romulus::romulusn_encrypt/32/128       15622 ns        15622 ns        44812 bytes_per_second=9.76761M/s
bench_romulus::romulusn_decrypt/32/128       15620 ns        15619 ns        44812 bytes_per_second=9.76908M/s
bench_romulus::romulusn_encrypt/32/256       28042 ns        28042 ns        24957 bytes_per_second=9.79457M/s
bench_romulus::romulusn_decrypt/32/256       28027 ns        28027 ns        24972 bytes_per_second=9.79982M/s
bench_romulus::romulusn_encrypt/32/512       52903 ns        52902 ns        13232 bytes_per_second=9.80682M/s
bench_romulus::romulusn_decrypt/32/512       52893 ns        52892 ns        13228 bytes_per_second=9.80862M/s
bench_romulus::romulusn_encrypt/32/1024     102609 ns       102607 ns         6822 bytes_per_second=9.81497M/s
bench_romulus::romulusn_decrypt/32/1024     102610 ns       102608 ns         6824 bytes_per_second=9.81485M/s
bench_romulus::romulusn_encrypt/32/2048     202015 ns       202011 ns         3465 bytes_per_second=9.81949M/s
bench_romulus::romulusn_decrypt/32/2048     201938 ns       201931 ns         3467 bytes_per_second=9.82339M/s
bench_romulus::romulusn_encrypt/32/4096     400842 ns       400830 ns         1746 bytes_per_second=9.82154M/s
bench_romulus::romulusn_decrypt/32/4096     400721 ns       400709 ns         1747 bytes_per_second=9.8245M/s
bench_romulus::romulusm_encrypt/32/64        12563 ns        12563 ns        55710 bytes_per_second=7.28755M/s
bench_romulus::romulusm_decrypt/32/64        12582 ns        12582 ns        55651 bytes_per_second=7.27665M/s
bench_romulus::romulusm_encrypt/32/128       21930 ns        21930 ns        31922 bytes_per_second=6.95797M/s
bench_romulus::romulusm_decrypt/32/128       21949 ns        21949 ns        31884 bytes_per_second=6.95199M/s
bench_romulus::romulusm_encrypt/32/256       40650 ns        40649 ns        17222 bytes_per_second=6.75684M/s
bench_romulus::romulusm_decrypt/32/256       40683 ns        40682 ns        17204 bytes_per_second=6.7514M/s
bench_romulus::romulusm_encrypt/32/512       78080 ns        78078 ns         8964 bytes_per_second=6.64461M/s
bench_romulus::romulusm_decrypt/32/512       78155 ns        78152 ns         8958 bytes_per_second=6.6383M/s
bench_romulus::romulusm_encrypt/32/1024     152932 ns       152929 ns         4577 bytes_per_second=6.58528M/s
bench_romulus::romulusm_decrypt/32/1024     153072 ns       153067 ns         4573 bytes_per_second=6.57932M/s
bench_romulus::romulusm_encrypt/32/2048     302629 ns       302620 ns         2313 bytes_per_second=6.5549M/s
bench_romulus::romulusm_decrypt/32/2048     302872 ns       302865 ns         2311 bytes_per_second=6.54959M/s
bench_romulus::romulusm_encrypt/32/4096     601987 ns       601965 ns         1163 bytes_per_second=6.53986M/s
bench_romulus::romulusm_decrypt/32/4096     602431 ns       602418 ns         1162 bytes_per_second=6.53495M/s
bench_romulus::romulust_encrypt/32/64        29635 ns        29634 ns        23624 bytes_per_second=3.08943M/s
bench_romulus::romulust_decrypt/32/64        29589 ns        29588 ns        23658 bytes_per_second=3.09426M/s
bench_romulus::romulust_encrypt/32/128       48241 ns        48240 ns        14511 bytes_per_second=3.16311M/s
bench_romulus::romulust_decrypt/32/128       48202 ns        48200 ns        14526 bytes_per_second=3.16572M/s
bench_romulus::romulust_encrypt/32/256       85576 ns        85574 ns         8179 bytes_per_second=3.20959M/s
bench_romulus::romulust_decrypt/32/256       85493 ns        85491 ns         8189 bytes_per_second=3.21273M/s
bench_romulus::romulust_encrypt/32/512      160195 ns       160191 ns         4370 bytes_per_second=3.23862M/s
bench_romulus::romulust_decrypt/32/512      160011 ns       160006 ns         4374 bytes_per_second=3.24238M/s
bench_romulus::romulust_encrypt/32/1024     309410 ns       309402 ns         2262 bytes_per_second=3.25493M/s
bench_romulus::romulust_decrypt/32/1024     309169 ns       309162 ns         2265 bytes_per_second=3.25745M/s
bench_romulus::romulust_encrypt/32/2048     607777 ns       607764 ns         1152 bytes_per_second=3.26384M/s
bench_romulus::romulust_decrypt/32/2048     607243 ns       607230 ns         1153 bytes_per_second=3.26671M/s
bench_romulus::romulust_encrypt/32/4096    1204559 ns      1204511 ns          581 bytes_per_second=3.26835M/s
bench_romulus::romulust_decrypt/32/4096    1203425 ns      1203391 ns          582 bytes_per_second=3.2714M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```fish
2022-08-21T23:32:44+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 2.25, 1.88, 1.65
--------------------------------------------------------------------------------------------------
Benchmark                                        Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------
bench_romulus::skinny_tbc                      476 ns          475 ns      1368711 bytes_per_second=32.1309M/s
bench_romulus::romulush/64                    2927 ns         2916 ns       238275 bytes_per_second=20.9317M/s
bench_romulus::romulush/128                   5090 ns         5068 ns       139565 bytes_per_second=24.0859M/s
bench_romulus::romulush/256                   9085 ns         9055 ns        77301 bytes_per_second=26.9633M/s
bench_romulus::romulush/512                  16565 ns        16544 ns        41289 bytes_per_second=29.5135M/s
bench_romulus::romulush/1024                 34007 ns        33851 ns        21531 bytes_per_second=28.8488M/s
bench_romulus::romulush/2048                 64136 ns        64003 ns        10035 bytes_per_second=30.5162M/s
bench_romulus::romulush/4096                124405 ns       124000 ns         5596 bytes_per_second=31.502M/s
bench_romulus::romulusn_encrypt/32/64         3135 ns         3125 ns       225454 bytes_per_second=29.2965M/s
bench_romulus::romulusn_decrypt/32/64         3099 ns         3095 ns       225469 bytes_per_second=29.578M/s
bench_romulus::romulusn_encrypt/32/128        5156 ns         5144 ns       131591 bytes_per_second=29.6641M/s
bench_romulus::romulusn_decrypt/32/128        5166 ns         5153 ns       132895 bytes_per_second=29.6102M/s
bench_romulus::romulusn_encrypt/32/256        9307 ns         9282 ns        74852 bytes_per_second=29.5906M/s
bench_romulus::romulusn_decrypt/32/256        9222 ns         9211 ns        74298 bytes_per_second=29.8187M/s
bench_romulus::romulusn_encrypt/32/512       17566 ns        17554 ns        39196 bytes_per_second=29.5553M/s
bench_romulus::romulusn_decrypt/32/512       17491 ns        17440 ns        40160 bytes_per_second=29.748M/s
bench_romulus::romulusn_encrypt/32/1024      33921 ns        33840 ns        20284 bytes_per_second=29.7601M/s
bench_romulus::romulusn_decrypt/32/1024      33648 ns        33604 ns        20895 bytes_per_second=29.9686M/s
bench_romulus::romulusn_encrypt/32/2048      67125 ns        66956 ns        10182 bytes_per_second=29.6263M/s
bench_romulus::romulusn_decrypt/32/2048      66307 ns        66114 ns        10240 bytes_per_second=30.0032M/s
bench_romulus::romulusn_encrypt/32/4096     132831 ns       132485 ns         5311 bytes_per_second=29.7149M/s
bench_romulus::romulusn_decrypt/32/4096     132272 ns       132141 ns         5239 bytes_per_second=29.7922M/s
bench_romulus::romulusm_encrypt/32/64         4131 ns         4120 ns       170206 bytes_per_second=22.2196M/s
bench_romulus::romulusm_decrypt/32/64         4226 ns         4212 ns       169436 bytes_per_second=21.7369M/s
bench_romulus::romulusm_encrypt/32/128        7366 ns         7341 ns        95785 bytes_per_second=20.7848M/s
bench_romulus::romulusm_decrypt/32/128        7601 ns         7541 ns        94208 bytes_per_second=20.2347M/s
bench_romulus::romulusm_encrypt/32/256       13282 ns        13270 ns        51038 bytes_per_second=20.6974M/s
bench_romulus::romulusm_decrypt/32/256       13248 ns        13215 ns        52442 bytes_per_second=20.7844M/s
bench_romulus::romulusm_encrypt/32/512       26086 ns        25944 ns        26184 bytes_per_second=19.997M/s
bench_romulus::romulusm_decrypt/32/512       25469 ns        25408 ns        27044 bytes_per_second=20.4184M/s
bench_romulus::romulusm_encrypt/32/1024      50556 ns        50340 ns        13247 bytes_per_second=20.0055M/s
bench_romulus::romulusm_decrypt/32/1024      50956 ns        50667 ns        13645 bytes_per_second=19.8764M/s
bench_romulus::romulusm_encrypt/32/2048      98750 ns        98671 ns         6921 bytes_per_second=20.1037M/s
bench_romulus::romulusm_decrypt/32/2048      98626 ns        98358 ns         6937 bytes_per_second=20.1675M/s
bench_romulus::romulusm_encrypt/32/4096     197203 ns       196711 ns         3557 bytes_per_second=20.0129M/s
bench_romulus::romulusm_decrypt/32/4096     197363 ns       196823 ns         3517 bytes_per_second=20.0015M/s
bench_romulus::romulust_encrypt/32/64         9333 ns         9306 ns        75202 bytes_per_second=9.8382M/s
bench_romulus::romulust_decrypt/32/64         9292 ns         9270 ns        74761 bytes_per_second=9.87637M/s
bench_romulus::romulust_encrypt/32/128       15281 ns        15263 ns        45300 bytes_per_second=9.99723M/s
bench_romulus::romulust_decrypt/32/128       15139 ns        15126 ns        45444 bytes_per_second=10.0876M/s
bench_romulus::romulust_encrypt/32/256       26896 ns        26854 ns        25612 bytes_per_second=10.2278M/s
bench_romulus::romulust_decrypt/32/256       26667 ns        26650 ns        25819 bytes_per_second=10.3059M/s
bench_romulus::romulust_encrypt/32/512       49917 ns        49801 ns        13530 bytes_per_second=10.4175M/s
bench_romulus::romulust_decrypt/32/512       50775 ns        50624 ns        12693 bytes_per_second=10.248M/s
bench_romulus::romulust_encrypt/32/1024      98957 ns        98588 ns         7151 bytes_per_second=10.2151M/s
bench_romulus::romulust_decrypt/32/1024      96374 ns        96237 ns         6921 bytes_per_second=10.4646M/s
bench_romulus::romulust_encrypt/32/2048     193526 ns       193312 ns         3566 bytes_per_second=10.2613M/s
bench_romulus::romulust_decrypt/32/2048     192901 ns       192304 ns         3654 bytes_per_second=10.3152M/s
bench_romulus::romulust_encrypt/32/4096     383525 ns       382952 ns         1851 bytes_per_second=10.28M/s
bench_romulus::romulust_decrypt/32/4096     377523 ns       377248 ns         1864 bytes_per_second=10.4355M/s
```

### On Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz

```fish
2022-08-21T19:39:46+00:00
Running ./bench/a.out
Run on (4 X 2300 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x2)
  L1 Instruction 32 KiB (x2)
  L2 Unified 256 KiB (x2)
  L3 Unified 46080 KiB (x1)
Load Average: 0.08, 0.02, 0.01
--------------------------------------------------------------------------------------------------
Benchmark                                        Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------
bench_romulus::skinny_tbc                     3143 ns         3143 ns       222686 bytes_per_second=4.85441M/s
bench_romulus::romulush/64                   18996 ns        18995 ns        36851 bytes_per_second=3.21314M/s
bench_romulus::romulush/128                  31642 ns        31642 ns        22122 bytes_per_second=3.85791M/s
bench_romulus::romulush/256                  56897 ns        56895 ns        12300 bytes_per_second=4.29111M/s
bench_romulus::romulush/512                 107381 ns       107380 ns         6518 bytes_per_second=4.54721M/s
bench_romulus::romulush/1024                208420 ns       208416 ns         3358 bytes_per_second=4.68565M/s
bench_romulus::romulush/2048                410526 ns       410523 ns         1705 bytes_per_second=4.75766M/s
bench_romulus::romulush/4096                814683 ns       814658 ns          859 bytes_per_second=4.79496M/s
bench_romulus::romulusn_encrypt/32/64        19006 ns        19006 ns        36833 bytes_per_second=4.81706M/s
bench_romulus::romulusn_decrypt/32/64        19039 ns        19039 ns        36757 bytes_per_second=4.80866M/s
bench_romulus::romulusn_encrypt/32/128       31660 ns        31659 ns        22117 bytes_per_second=4.81976M/s
bench_romulus::romulusn_decrypt/32/128       31701 ns        31699 ns        22080 bytes_per_second=4.81358M/s
bench_romulus::romulusn_encrypt/32/256       56972 ns        56971 ns        12289 bytes_per_second=4.82101M/s
bench_romulus::romulusn_decrypt/32/256       56986 ns        56987 ns        12289 bytes_per_second=4.81971M/s
bench_romulus::romulusn_encrypt/32/512      107505 ns       107502 ns         6511 bytes_per_second=4.82596M/s
bench_romulus::romulusn_decrypt/32/512      107535 ns       107532 ns         6510 bytes_per_second=4.82459M/s
bench_romulus::romulusn_encrypt/32/1024     209277 ns       209260 ns         3354 bytes_per_second=4.81257M/s
bench_romulus::romulusn_decrypt/32/1024     209364 ns       209348 ns         3342 bytes_per_second=4.81056M/s
bench_romulus::romulusn_encrypt/32/2048     411090 ns       411057 ns         1698 bytes_per_second=4.82571M/s
bench_romulus::romulusn_decrypt/32/2048     410689 ns       410680 ns         1703 bytes_per_second=4.83014M/s
bench_romulus::romulusn_encrypt/32/4096     814943 ns       814884 ns          859 bytes_per_second=4.83108M/s
bench_romulus::romulusn_decrypt/32/4096     814826 ns       814806 ns          859 bytes_per_second=4.83154M/s
bench_romulus::romulusm_encrypt/32/64        25431 ns        25431 ns        27538 bytes_per_second=3.60008M/s
bench_romulus::romulusm_decrypt/32/64        25448 ns        25448 ns        27511 bytes_per_second=3.59765M/s
bench_romulus::romulusm_encrypt/32/128       44474 ns        44472 ns        15731 bytes_per_second=3.43107M/s
bench_romulus::romulusm_decrypt/32/128       44497 ns        44497 ns        15734 bytes_per_second=3.42917M/s
bench_romulus::romulusm_encrypt/32/256       82512 ns        82507 ns         8484 bytes_per_second=3.3289M/s
bench_romulus::romulusm_decrypt/32/256       82590 ns        82590 ns         8475 bytes_per_second=3.32557M/s
bench_romulus::romulusm_encrypt/32/512      158574 ns       158573 ns         4409 bytes_per_second=3.27167M/s
bench_romulus::romulusm_decrypt/32/512      158562 ns       158558 ns         4411 bytes_per_second=3.27199M/s
bench_romulus::romulusm_encrypt/32/1024     310656 ns       310652 ns         2254 bytes_per_second=3.24182M/s
bench_romulus::romulusm_decrypt/32/1024     310552 ns       310544 ns         2254 bytes_per_second=3.24295M/s
bench_romulus::romulusm_encrypt/32/2048     615561 ns       615566 ns         1139 bytes_per_second=3.22247M/s
bench_romulus::romulusm_decrypt/32/2048     615076 ns       615021 ns         1138 bytes_per_second=3.22533M/s
bench_romulus::romulusm_encrypt/32/4096    1224294 ns      1224265 ns          571 bytes_per_second=3.21562M/s
bench_romulus::romulusm_decrypt/32/4096    1223899 ns      1223872 ns          572 bytes_per_second=3.21665M/s
bench_romulus::romulust_encrypt/32/64        60216 ns        60216 ns        11626 bytes_per_second=1.52042M/s
bench_romulus::romulust_decrypt/32/64        60195 ns        60194 ns        11627 bytes_per_second=1.52096M/s
bench_romulus::romulust_encrypt/32/128       98141 ns        98131 ns         7135 bytes_per_second=1.55494M/s
bench_romulus::romulust_decrypt/32/128       98112 ns        98110 ns         7133 bytes_per_second=1.55528M/s
bench_romulus::romulust_encrypt/32/256      173824 ns       173821 ns         4026 bytes_per_second=1.58012M/s
bench_romulus::romulust_decrypt/32/256      173829 ns       173827 ns         4027 bytes_per_second=1.58006M/s
bench_romulus::romulust_encrypt/32/512      325406 ns       325398 ns         2152 bytes_per_second=1.59435M/s
bench_romulus::romulust_decrypt/32/512      325393 ns       325386 ns         2151 bytes_per_second=1.59441M/s
bench_romulus::romulust_encrypt/32/1024     628542 ns       628547 ns         1114 bytes_per_second=1.60224M/s
bench_romulus::romulust_decrypt/32/1024     628635 ns       628612 ns         1113 bytes_per_second=1.60207M/s
bench_romulus::romulust_encrypt/32/2048    1235484 ns      1235460 ns          567 bytes_per_second=1.60559M/s
bench_romulus::romulust_decrypt/32/2048    1235968 ns      1235876 ns          567 bytes_per_second=1.60505M/s
bench_romulus::romulust_encrypt/32/4096    2448648 ns      2448638 ns          285 bytes_per_second=1.60774M/s
bench_romulus::romulust_decrypt/32/4096    2450591 ns      2450409 ns          286 bytes_per_second=1.60658M/s
```
