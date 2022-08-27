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
2022-08-27T08:23:11+00:00
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
bench_romulus::skinny_tbc                     1877 ns         1877 ns       372972 bytes_per_second=8.13119M/s
bench_romulus::romulush/64                   11332 ns        11331 ns        61770 bytes_per_second=5.3864M/s
bench_romulus::romulush/128                  18853 ns        18853 ns        37129 bytes_per_second=6.475M/s
bench_romulus::romulush/256                  33897 ns        33896 ns        20651 bytes_per_second=7.20261M/s
bench_romulus::romulush/512                  63984 ns        63984 ns        10940 bytes_per_second=7.63132M/s
bench_romulus::romulush/1024                124161 ns       124159 ns         5638 bytes_per_second=7.86539M/s
bench_romulus::romulush/2048                244511 ns       244509 ns         2863 bytes_per_second=7.98794M/s
bench_romulus::romulush/4096                485243 ns       485233 ns         1443 bytes_per_second=8.05025M/s
bench_romulus::romulusn_encrypt/32/64        11376 ns        11376 ns        61463 bytes_per_second=8.04786M/s
bench_romulus::romulusn_decrypt/32/64        11414 ns        11414 ns        61328 bytes_per_second=8.0214M/s
bench_romulus::romulusn_encrypt/32/128       18933 ns        18932 ns        36987 bytes_per_second=8.05972M/s
bench_romulus::romulusn_decrypt/32/128       18919 ns        18919 ns        36995 bytes_per_second=8.06551M/s
bench_romulus::romulusn_encrypt/32/256       34039 ns        34039 ns        20569 bytes_per_second=8.06898M/s
bench_romulus::romulusn_decrypt/32/256       33933 ns        33933 ns        20628 bytes_per_second=8.09416M/s
bench_romulus::romulusn_encrypt/32/512       64245 ns        64244 ns        10897 bytes_per_second=8.07546M/s
bench_romulus::romulusn_decrypt/32/512       63959 ns        63959 ns        10944 bytes_per_second=8.11149M/s
bench_romulus::romulusn_encrypt/32/1024     124659 ns       124658 ns         5615 bytes_per_second=8.07873M/s
bench_romulus::romulusn_decrypt/32/1024     124042 ns       124041 ns         5644 bytes_per_second=8.11891M/s
bench_romulus::romulusn_encrypt/32/2048     245472 ns       245466 ns         2852 bytes_per_second=8.08113M/s
bench_romulus::romulusn_decrypt/32/2048     244125 ns       244121 ns         2867 bytes_per_second=8.12567M/s
bench_romulus::romulusn_encrypt/32/4096     487103 ns       487100 ns         1437 bytes_per_second=8.08206M/s
bench_romulus::romulusn_decrypt/32/4096     484360 ns       484357 ns         1445 bytes_per_second=8.12783M/s
bench_romulus::romulusm_encrypt/32/64        15232 ns        15231 ns        45961 bytes_per_second=6.01077M/s
bench_romulus::romulusm_decrypt/32/64        15237 ns        15236 ns        45961 bytes_per_second=6.00888M/s
bench_romulus::romulusm_encrypt/32/128       26602 ns        26602 ns        26312 bytes_per_second=5.73604M/s
bench_romulus::romulusm_decrypt/32/128       26595 ns        26594 ns        26320 bytes_per_second=5.73759M/s
bench_romulus::romulusm_encrypt/32/256       49349 ns        49346 ns        14186 bytes_per_second=5.56595M/s
bench_romulus::romulusm_decrypt/32/256       49323 ns        49322 ns        14192 bytes_per_second=5.56863M/s
bench_romulus::romulusm_encrypt/32/512       94836 ns        94831 ns         7382 bytes_per_second=5.4708M/s
bench_romulus::romulusm_decrypt/32/512       94778 ns        94778 ns         7385 bytes_per_second=5.47384M/s
bench_romulus::romulusm_encrypt/32/1024     185813 ns       185809 ns         3767 bytes_per_second=5.41997M/s
bench_romulus::romulusm_decrypt/32/1024     185742 ns       185741 ns         3770 bytes_per_second=5.42196M/s
bench_romulus::romulusm_encrypt/32/2048     367733 ns       367731 ns         1904 bytes_per_second=5.39427M/s
bench_romulus::romulusm_decrypt/32/2048     367531 ns       367523 ns         1905 bytes_per_second=5.39732M/s
bench_romulus::romulusm_encrypt/32/4096     731647 ns       731631 ns          957 bytes_per_second=5.38081M/s
bench_romulus::romulusm_decrypt/32/4096     731217 ns       731212 ns          957 bytes_per_second=5.38389M/s
bench_romulus::romulust_encrypt/32/64        35922 ns        35922 ns        19486 bytes_per_second=2.54867M/s
bench_romulus::romulust_decrypt/32/64        35880 ns        35879 ns        19510 bytes_per_second=2.55168M/s
bench_romulus::romulust_encrypt/32/128       58574 ns        58573 ns        11950 bytes_per_second=2.60511M/s
bench_romulus::romulust_decrypt/32/128       58474 ns        58473 ns        11971 bytes_per_second=2.60955M/s
bench_romulus::romulust_encrypt/32/256      103871 ns       103870 ns         6739 bytes_per_second=2.64425M/s
bench_romulus::romulust_decrypt/32/256      103658 ns       103657 ns         6753 bytes_per_second=2.64967M/s
bench_romulus::romulust_encrypt/32/512      194541 ns       194540 ns         3597 bytes_per_second=2.6668M/s
bench_romulus::romulust_decrypt/32/512      194157 ns       194154 ns         3605 bytes_per_second=2.6721M/s
bench_romulus::romulust_encrypt/32/1024     375725 ns       375714 ns         1863 bytes_per_second=2.68044M/s
bench_romulus::romulust_decrypt/32/1024     374804 ns       374795 ns         1868 bytes_per_second=2.68702M/s
bench_romulus::romulust_encrypt/32/2048     738084 ns       738079 ns          948 bytes_per_second=2.68757M/s
bench_romulus::romulust_decrypt/32/2048     736298 ns       736288 ns          951 bytes_per_second=2.69411M/s
bench_romulus::romulust_encrypt/32/4096    1462933 ns      1462923 ns          478 bytes_per_second=2.69103M/s
bench_romulus::romulust_decrypt/32/4096    1459371 ns      1459361 ns          480 bytes_per_second=2.6976M/s
```

### On AWS Graviton3

```fish
2022-08-27T08:19:10+00:00
Running ./bench/a.out
Run on (64 X 2100 MHz CPU s)
CPU Caches:
  L1 Data 64 KiB (x64)
  L1 Instruction 64 KiB (x64)
  L2 Unified 1024 KiB (x64)
  L3 Unified 32768 KiB (x1)
Load Average: 0.08, 0.02, 0.01
--------------------------------------------------------------------------------------------------
Benchmark                                        Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------
bench_romulus::skinny_tbc                     1458 ns         1458 ns       479752 bytes_per_second=10.4664M/s
bench_romulus::romulush/64                    8903 ns         8903 ns        78615 bytes_per_second=6.85595M/s
bench_romulus::romulush/128                  14824 ns        14823 ns        47216 bytes_per_second=8.23512M/s
bench_romulus::romulush/256                  26668 ns        26667 ns        26251 bytes_per_second=9.15505M/s
bench_romulus::romulush/512                  50343 ns        50342 ns        13909 bytes_per_second=9.69934M/s
bench_romulus::romulush/1024                 97697 ns        97693 ns         7166 bytes_per_second=9.9962M/s
bench_romulus::romulush/2048                192416 ns       192411 ns         3638 bytes_per_second=10.1508M/s
bench_romulus::romulush/4096                381869 ns       381856 ns         1833 bytes_per_second=10.2296M/s
bench_romulus::romulusn_encrypt/32/64         8928 ns         8928 ns        78382 bytes_per_second=10.2548M/s
bench_romulus::romulusn_decrypt/32/64         8961 ns         8961 ns        78112 bytes_per_second=10.2172M/s
bench_romulus::romulusn_encrypt/32/128       14884 ns        14884 ns        47021 bytes_per_second=10.252M/s
bench_romulus::romulusn_decrypt/32/128       14902 ns        14901 ns        46954 bytes_per_second=10.2399M/s
bench_romulus::romulusn_encrypt/32/256       26809 ns        26808 ns        26114 bytes_per_second=10.2452M/s
bench_romulus::romulusn_decrypt/32/256       26783 ns        26783 ns        26134 bytes_per_second=10.255M/s
bench_romulus::romulusn_encrypt/32/512       50642 ns        50641 ns        13826 bytes_per_second=10.2447M/s
bench_romulus::romulusn_decrypt/32/512       50525 ns        50523 ns        13861 bytes_per_second=10.2685M/s
bench_romulus::romulusn_encrypt/32/1024      98349 ns        98347 ns         7120 bytes_per_second=10.2401M/s
bench_romulus::romulusn_decrypt/32/1024      98028 ns        98025 ns         7142 bytes_per_second=10.2737M/s
bench_romulus::romulusn_encrypt/32/2048     193699 ns       193695 ns         3613 bytes_per_second=10.2411M/s
bench_romulus::romulusn_decrypt/32/2048     193043 ns       193038 ns         3629 bytes_per_second=10.2759M/s
bench_romulus::romulusn_encrypt/32/4096     384482 ns       384474 ns         1820 bytes_per_second=10.2394M/s
bench_romulus::romulusn_decrypt/32/4096     382928 ns       382920 ns         1828 bytes_per_second=10.2809M/s
bench_romulus::romulusm_encrypt/32/64        11971 ns        11971 ns        58490 bytes_per_second=7.64797M/s
bench_romulus::romulusm_decrypt/32/64        12001 ns        12001 ns        58326 bytes_per_second=7.62886M/s
bench_romulus::romulusm_encrypt/32/128       20946 ns        20946 ns        33430 bytes_per_second=7.28483M/s
bench_romulus::romulusm_decrypt/32/128       20970 ns        20970 ns        33376 bytes_per_second=7.27664M/s
bench_romulus::romulusm_encrypt/32/256       38865 ns        38864 ns        18012 bytes_per_second=7.0672M/s
bench_romulus::romulusm_decrypt/32/256       38931 ns        38930 ns        17979 bytes_per_second=7.05518M/s
bench_romulus::romulusm_encrypt/32/512       74715 ns        74713 ns         9369 bytes_per_second=6.94389M/s
bench_romulus::romulusm_decrypt/32/512       74882 ns        74880 ns         9341 bytes_per_second=6.92843M/s
bench_romulus::romulusm_encrypt/32/1024     146499 ns       146496 ns         4781 bytes_per_second=6.87444M/s
bench_romulus::romulusm_decrypt/32/1024     146683 ns       146679 ns         4772 bytes_per_second=6.86586M/s
bench_romulus::romulusm_encrypt/32/2048     289831 ns       289825 ns         2416 bytes_per_second=6.84428M/s
bench_romulus::romulusm_decrypt/32/2048     290306 ns       290300 ns         2410 bytes_per_second=6.83308M/s
bench_romulus::romulusm_encrypt/32/4096     576631 ns       576619 ns         1214 bytes_per_second=6.82733M/s
bench_romulus::romulusm_decrypt/32/4096     577494 ns       577482 ns         1211 bytes_per_second=6.81713M/s
bench_romulus::romulust_encrypt/32/64        28113 ns        28113 ns        24901 bytes_per_second=3.25664M/s
bench_romulus::romulust_decrypt/32/64        28104 ns        28104 ns        24902 bytes_per_second=3.25767M/s
bench_romulus::romulust_encrypt/32/128       45849 ns        45847 ns        15265 bytes_per_second=3.32818M/s
bench_romulus::romulust_decrypt/32/128       45839 ns        45838 ns        15269 bytes_per_second=3.32888M/s
bench_romulus::romulust_encrypt/32/256       81338 ns        81335 ns         8605 bytes_per_second=3.37687M/s
bench_romulus::romulust_decrypt/32/256       81309 ns        81307 ns         8606 bytes_per_second=3.37805M/s
bench_romulus::romulust_encrypt/32/512      152288 ns       152284 ns         4597 bytes_per_second=3.40679M/s
bench_romulus::romulust_decrypt/32/512      152269 ns       152266 ns         4596 bytes_per_second=3.40719M/s
bench_romulus::romulust_encrypt/32/1024     294202 ns       294194 ns         2379 bytes_per_second=3.42318M/s
bench_romulus::romulust_decrypt/32/1024     294216 ns       294210 ns         2379 bytes_per_second=3.423M/s
bench_romulus::romulust_encrypt/32/2048     578131 ns       578114 ns         1211 bytes_per_second=3.43123M/s
bench_romulus::romulust_decrypt/32/2048     578140 ns       578123 ns         1211 bytes_per_second=3.43118M/s
bench_romulus::romulust_encrypt/32/4096    1145961 ns      1145933 ns          611 bytes_per_second=3.43543M/s
bench_romulus::romulust_decrypt/32/4096    1145968 ns      1145945 ns          611 bytes_per_second=3.43539M/s
```

### On Intel(R) Core(TM) i5-8279U CPU @ 2.40GHz

```fish
2022-08-27T12:27:50+04:00
Running ./bench/a.out
Run on (8 X 2400 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB
  L1 Instruction 32 KiB
  L2 Unified 256 KiB (x4)
  L3 Unified 6144 KiB
Load Average: 1.78, 1.59, 1.53
--------------------------------------------------------------------------------------------------
Benchmark                                        Time             CPU   Iterations UserCounters...
--------------------------------------------------------------------------------------------------
bench_romulus::skinny_tbc                      597 ns          491 ns      1326738 bytes_per_second=31.102M/s
bench_romulus::romulush/64                    2873 ns         2868 ns       241515 bytes_per_second=21.2828M/s
bench_romulus::romulush/128                   4771 ns         4767 ns       134854 bytes_per_second=25.6086M/s
bench_romulus::romulush/256                   8592 ns         8583 ns        79908 bytes_per_second=28.444M/s
bench_romulus::romulush/512                  16205 ns        16191 ns        42446 bytes_per_second=30.1584M/s
bench_romulus::romulush/1024                 31517 ns        31490 ns        21938 bytes_per_second=31.0114M/s
bench_romulus::romulush/2048                 62131 ns        62055 ns        11025 bytes_per_second=31.4743M/s
bench_romulus::romulush/4096                122759 ns       122694 ns         5478 bytes_per_second=31.8372M/s
bench_romulus::romulusn_encrypt/32/64         3013 ns         3009 ns       231382 bytes_per_second=30.4226M/s
bench_romulus::romulusn_decrypt/32/64         3025 ns         3022 ns       231517 bytes_per_second=30.2992M/s
bench_romulus::romulusn_encrypt/32/128        5002 ns         4998 ns       134282 bytes_per_second=30.5268M/s
bench_romulus::romulusn_decrypt/32/128        5043 ns         5037 ns       135609 bytes_per_second=30.2911M/s
bench_romulus::romulusn_encrypt/32/256        9050 ns         9039 ns        75446 bytes_per_second=30.3849M/s
bench_romulus::romulusn_decrypt/32/256        9032 ns         9025 ns        75436 bytes_per_second=30.4329M/s
bench_romulus::romulusn_encrypt/32/512       16848 ns        16837 ns        41159 bytes_per_second=30.8134M/s
bench_romulus::romulusn_decrypt/32/512       16850 ns        16843 ns        40490 bytes_per_second=30.8026M/s
bench_romulus::romulusn_encrypt/32/1024      32840 ns        32803 ns        21333 bytes_per_second=30.7008M/s
bench_romulus::romulusn_decrypt/32/1024      32888 ns        32856 ns        21335 bytes_per_second=30.6512M/s
bench_romulus::romulusn_encrypt/32/2048      64455 ns        64426 ns        10470 bytes_per_second=30.7895M/s
bench_romulus::romulusn_decrypt/32/2048      64610 ns        64540 ns        10423 bytes_per_second=30.7351M/s
bench_romulus::romulusn_encrypt/32/4096     127764 ns       127688 ns         5345 bytes_per_second=30.8312M/s
bench_romulus::romulusn_decrypt/32/4096     128276 ns       128142 ns         5329 bytes_per_second=30.7219M/s
bench_romulus::romulusm_encrypt/32/64         4044 ns         4040 ns       168174 bytes_per_second=22.6609M/s
bench_romulus::romulusm_decrypt/32/64         4040 ns         4034 ns       171876 bytes_per_second=22.6931M/s
bench_romulus::romulusm_encrypt/32/128        7033 ns         7024 ns        96570 bytes_per_second=21.7223M/s
bench_romulus::romulusm_decrypt/32/128        7029 ns         7023 ns        97288 bytes_per_second=21.7275M/s
bench_romulus::romulusm_encrypt/32/256       12962 ns        12953 ns        52972 bytes_per_second=21.2045M/s
bench_romulus::romulusm_decrypt/32/256       13090 ns        13073 ns        52926 bytes_per_second=21.0097M/s
bench_romulus::romulusm_encrypt/32/512       24971 ns        24952 ns        28062 bytes_per_second=20.7918M/s
bench_romulus::romulusm_decrypt/32/512       24925 ns        24908 ns        27929 bytes_per_second=20.8284M/s
bench_romulus::romulusm_encrypt/32/1024      48639 ns        48606 ns        13752 bytes_per_second=20.7193M/s
bench_romulus::romulusm_decrypt/32/1024      49087 ns        49033 ns        13620 bytes_per_second=20.5389M/s
bench_romulus::romulusm_encrypt/32/2048      96211 ns        96157 ns         7107 bytes_per_second=20.6291M/s
bench_romulus::romulusm_decrypt/32/2048      97181 ns        97115 ns         7110 bytes_per_second=20.4256M/s
bench_romulus::romulusm_encrypt/32/4096     192519 ns       192360 ns         3620 bytes_per_second=20.4656M/s
bench_romulus::romulusm_decrypt/32/4096     191911 ns       191686 ns         3617 bytes_per_second=20.5376M/s
bench_romulus::romulust_encrypt/32/64         9086 ns         9082 ns        74818 bytes_per_second=10.0807M/s
bench_romulus::romulust_decrypt/32/64         9126 ns         9120 ns        74968 bytes_per_second=10.0389M/s
bench_romulus::romulust_encrypt/32/128       14784 ns        14774 ns        46770 bytes_per_second=10.3284M/s
bench_romulus::romulust_decrypt/32/128       14895 ns        14885 ns        46646 bytes_per_second=10.2514M/s
bench_romulus::romulust_encrypt/32/256       27713 ns        27444 ns        26590 bytes_per_second=10.0079M/s
bench_romulus::romulust_decrypt/32/256       28093 ns        27777 ns        25255 bytes_per_second=9.88788M/s
bench_romulus::romulust_encrypt/32/512       52286 ns        51722 ns        13078 bytes_per_second=10.0304M/s
bench_romulus::romulust_decrypt/32/512       52528 ns        51967 ns        13033 bytes_per_second=9.98328M/s
bench_romulus::romulust_encrypt/32/1024      96738 ns        96396 ns         6853 bytes_per_second=10.4473M/s
bench_romulus::romulust_decrypt/32/1024      98624 ns        97818 ns         6808 bytes_per_second=10.2955M/s
bench_romulus::romulust_encrypt/32/2048     194079 ns       192559 ns         3740 bytes_per_second=10.3015M/s
bench_romulus::romulust_decrypt/32/2048     191018 ns       190285 ns         3500 bytes_per_second=10.4246M/s
bench_romulus::romulust_encrypt/32/4096     405953 ns       398465 ns         1849 bytes_per_second=9.87984M/s
bench_romulus::romulust_decrypt/32/4096     383029 ns       381876 ns         1773 bytes_per_second=10.309M/s
```

### On Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz

```fish
2022-08-27T08:25:34+00:00
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
bench_romulus::skinny_tbc                     2287 ns         2286 ns       305994 bytes_per_second=6.67348M/s
bench_romulus::romulush/64                   13828 ns        13828 ns        50665 bytes_per_second=4.41377M/s
bench_romulus::romulush/128                  23018 ns        23019 ns        30415 bytes_per_second=5.30314M/s
bench_romulus::romulush/256                  41417 ns        41417 ns        16905 bytes_per_second=5.89476M/s
bench_romulus::romulush/512                  78193 ns        78193 ns         8956 bytes_per_second=6.24453M/s
bench_romulus::romulush/1024                152360 ns       152361 ns         4613 bytes_per_second=6.40951M/s
bench_romulus::romulush/2048                298897 ns       298899 ns         2340 bytes_per_second=6.5344M/s
bench_romulus::romulush/4096                592860 ns       592795 ns         1180 bytes_per_second=6.58954M/s
bench_romulus::romulusn_encrypt/32/64        13964 ns        13964 ns        50155 bytes_per_second=6.55635M/s
bench_romulus::romulusn_decrypt/32/64        13969 ns        13969 ns        50083 bytes_per_second=6.55405M/s
bench_romulus::romulusn_encrypt/32/128       23261 ns        23259 ns        30083 bytes_per_second=6.56027M/s
bench_romulus::romulusn_decrypt/32/128       23286 ns        23286 ns        30064 bytes_per_second=6.55278M/s
bench_romulus::romulusn_encrypt/32/256       41878 ns        41877 ns        16713 bytes_per_second=6.55874M/s
bench_romulus::romulusn_decrypt/32/256       41902 ns        41901 ns        16704 bytes_per_second=6.55491M/s
bench_romulus::romulusn_encrypt/32/512       79069 ns        79069 ns         8852 bytes_per_second=6.56131M/s
bench_romulus::romulusn_decrypt/32/512       79060 ns        79061 ns         8852 bytes_per_second=6.56204M/s
bench_romulus::romulusn_encrypt/32/1024     153504 ns       153503 ns         4561 bytes_per_second=6.56067M/s
bench_romulus::romulusn_decrypt/32/1024     153380 ns       153379 ns         4566 bytes_per_second=6.56596M/s
bench_romulus::romulusn_encrypt/32/2048     302290 ns       302287 ns         2316 bytes_per_second=6.56212M/s
bench_romulus::romulusn_decrypt/32/2048     302072 ns       302074 ns         2318 bytes_per_second=6.56674M/s
bench_romulus::romulusn_encrypt/32/4096     599964 ns       599953 ns         1167 bytes_per_second=6.5618M/s
bench_romulus::romulusn_decrypt/32/4096     599255 ns       599250 ns         1168 bytes_per_second=6.56949M/s
bench_romulus::romulusm_encrypt/32/64        18689 ns        18689 ns        37437 bytes_per_second=4.89872M/s
bench_romulus::romulusm_decrypt/32/64        18720 ns        18720 ns        37385 bytes_per_second=4.89074M/s
bench_romulus::romulusm_encrypt/32/128       32734 ns        32734 ns        21378 bytes_per_second=4.66139M/s
bench_romulus::romulusm_decrypt/32/128       32764 ns        32764 ns        21359 bytes_per_second=4.65725M/s
bench_romulus::romulusm_encrypt/32/256       60823 ns        60824 ns        11512 bytes_per_second=4.51563M/s
bench_romulus::romulusm_decrypt/32/256       60891 ns        60891 ns        11497 bytes_per_second=4.51062M/s
bench_romulus::romulusm_encrypt/32/512      116986 ns       116987 ns         5986 bytes_per_second=4.43466M/s
bench_romulus::romulusm_decrypt/32/512      117157 ns       117156 ns         5970 bytes_per_second=4.42827M/s
bench_romulus::romulusm_encrypt/32/1024     229713 ns       229704 ns         3049 bytes_per_second=4.38425M/s
bench_romulus::romulusm_decrypt/32/1024     229442 ns       229439 ns         3048 bytes_per_second=4.38932M/s
bench_romulus::romulusm_encrypt/32/2048     453891 ns       453895 ns         1542 bytes_per_second=4.37027M/s
bench_romulus::romulusm_decrypt/32/2048     454204 ns       454201 ns         1541 bytes_per_second=4.36733M/s
bench_romulus::romulusm_encrypt/32/4096     903288 ns       903281 ns          775 bytes_per_second=4.3583M/s
bench_romulus::romulusm_decrypt/32/4096     903607 ns       903613 ns          775 bytes_per_second=4.35669M/s
bench_romulus::romulust_encrypt/32/64        43843 ns        43844 ns        15960 bytes_per_second=2.08816M/s
bench_romulus::romulust_decrypt/32/64        43893 ns        43894 ns        15949 bytes_per_second=2.08578M/s
bench_romulus::romulust_encrypt/32/128       71494 ns        71493 ns         9794 bytes_per_second=2.13429M/s
bench_romulus::romulust_decrypt/32/128       71518 ns        71518 ns         9789 bytes_per_second=2.13357M/s
bench_romulus::romulust_encrypt/32/256      126747 ns       126746 ns         5520 bytes_per_second=2.167M/s
bench_romulus::romulust_decrypt/32/256      126817 ns       126818 ns         5521 bytes_per_second=2.16576M/s
bench_romulus::romulust_encrypt/32/512      237236 ns       237235 ns         2950 bytes_per_second=2.18686M/s
bench_romulus::romulust_decrypt/32/512      237307 ns       237308 ns         2950 bytes_per_second=2.18618M/s
bench_romulus::romulust_encrypt/32/1024     458219 ns       458222 ns         1527 bytes_per_second=2.1978M/s
bench_romulus::romulust_decrypt/32/1024     458466 ns       458453 ns         1527 bytes_per_second=2.19669M/s
bench_romulus::romulust_encrypt/32/2048     900659 ns       900652 ns          776 bytes_per_second=2.20245M/s
bench_romulus::romulust_decrypt/32/2048     900651 ns       900657 ns          777 bytes_per_second=2.20244M/s
bench_romulus::romulust_encrypt/32/4096    1789293 ns      1789306 ns          392 bytes_per_second=2.20016M/s
bench_romulus::romulust_decrypt/32/4096    1784805 ns      1784818 ns          392 bytes_per_second=2.2057M/s
```


## Usage

Using Romulus zero-dependency, header-only C++ library is as easy as 

- Importing proper header files into your program
- While compiling letting your compiler know where to find these header files

Here, I implement all schemes described in Romulus cipher suite [specification](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/romulus-spec-final.pdf)

Scheme | Header File | Usage Example
--- | --: | --:
Romulus-H [only hash function] | [romulush.hpp](./include/romulush.hpp) | [romulush.cpp](./example/romulush.cpp)
Romulus-N [nonce-based AEAD] | [romulusn.hpp](./include/romulusn.hpp) | [romulusn.cpp](./example/romulusn.cpp)
Romulus-M [nonce misuse-resistant AEAD] | [romulusm.hpp](./include/romulusm.hpp) | [romulusm.cpp](./example/romulusm.cpp)
Romulus-T [leakage-resistant AEAD] | [romulust.hpp](./include/romulust.hpp) | [romulust.cpp](./example/romulust.cpp)

```fish
$ g++ -Wall -std=c++20 -O3 -march=native -I include example/romulush.cpp && ./a.out

Romulus-H Hash Function

Message : f7f275dbee2bdcce51a5b1fa4adef0952293bef2f51425d05b840089fdeebe1dcb55b5f6f5e4da1bffb82dc2549f6588
Digest  : 5ba00a78b4f946179499ee853e8300ec0a799609e5e133593590125def042cc1

# ---

$ g++ -Wall -std=c++20 -O3 -march=native -I include example/romulusn.cpp && ./a.out

Romulus-N AEAD

Key       : 7cda7580c0d74472051616717e92631e
Nonce     : 4ef907b92b06e5e40c87ec6026be0823
Tag       : fdeaf67a3f17b3555173fccc58f12548
Data      : eded42cec7f92797582a17cdef1e19114fb46fe2a9241edf7c862064db663280
Text      : 9e21f46ea6bed1ad200d60fb1015830ea49bbf01916f7fca60c7171065c25017
Encrypted : d2594dcdfdf19934e1859b8943e5ea18fcdc3b6bea2067cfd2c6c0275ae8062a
Decrypted : 9e21f46ea6bed1ad200d60fb1015830ea49bbf01916f7fca60c7171065c25017

# ---

$ g++ -Wall -std=c++20 -O3 -march=native -I include example/romulusm.cpp && ./a.out

Romulus-M AEAD

Key       : e0ea43631897c3c6d4da9659e34b9712
Nonce     : 6e4670ac1ca9ae0879986967a3dfae78
Tag       : 86cc2326ca767f3850180b0c3064e3eb
Data      : e772443c46b3d8744f2714c52d5cb975c3aecbbae7b4de619ff930e6f2f8a558
Text      : c06034b3d95a47e2f3724832dd7e8cf87657b88ae093012d31b6494d8034fafa
Encrypted : 29265cc306baa1e83c144a1b266b21ddca7d904ea30b3fd42f9bbec1a039cafe
Decrypted : c06034b3d95a47e2f3724832dd7e8cf87657b88ae093012d31b6494d8034fafa

# ---

$ g++ -Wall -std=c++20 -O3 -march=native -I include example/romulust.cpp && ./a.out

Romulus-T AEAD

Key       : 06278853ce440b61d4e6025ab9f47de2
Nonce     : c7119cb178dea251d782cd7927d1f836
Tag       : 37ccee0eed48da50b303c8a73df0dfa3
Data      : 4f09b67515a88171dd0a5acae3068af1fdf354862876ca0948bbc2ebd480e1a6
Text      : 20ea73a583171f763c9e7f4da52845f9ce8ae6f9a9a5d94c2e50a80d90c8d64d
Encrypted : b37249398c9a718002aeda9f51b81e97fbf4871efe14b26b0d8156aa3bc14f7b
Decrypted : 20ea73a583171f763c9e7f4da52845f9ce8ae6f9a9a5d94c2e50a80d90c8d64d
```
