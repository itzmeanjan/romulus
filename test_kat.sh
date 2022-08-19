#!/bin/bash

# Script for ease of execution of Known Answer Tests against Romulus implementation

make lib

# ---

mkdir -p tmp
pushd tmp

wget -O romulus.zip https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-submissions/romulus.zip
unzip romulus.zip

cp romulus/Implementations/crypto_aead/romulush/LWC_HASH_KAT_256.txt ../romulush.txt
cp romulus/Implementations/crypto_aead/romulusn/LWC_AEAD_KAT_128_128.txt ../romulusn.txt
cp romulus/Implementations/crypto_aead/romulusm/LWC_AEAD_KAT_128_128.txt ../romulusm.txt
cp romulus/Implementations/crypto_aead/romulust/LWC_AEAD_KAT_128_128.txt ../romulust.txt

popd

# ---

rm -rf tmp
mv romulus{h,n,m,t}.txt wrapper/python/

# ---

pushd wrapper/python

mv romulush.txt LWC_HASH_KAT_256.txt
python3 -m pytest -k romulush -v

mv romulusn.txt LWC_AEAD_KAT_128_128.txt
python3 -m pytest -k romulusn -v

mv romulusm.txt LWC_AEAD_KAT_128_128.txt
python3 -m pytest -k romulusm -v

mv romulust.txt LWC_AEAD_KAT_128_128.txt
python3 -m pytest -k romulust -v

rm LWC_*_KAT_*.txt

popd

# ---
