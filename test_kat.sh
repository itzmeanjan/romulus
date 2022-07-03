#!/bin/bash

# Script for ease of execution of Known Answer Tests against Romulus implementation

make lib

# ---

mkdir -p tmp
pushd tmp

wget -O romulus.zip https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-submissions/romulus.zip
unzip romulus.zip

cp romulus/Implementations/crypto_aead/romulush/LWC_HASH_KAT_256.txt ../

popd

# ---

rm -rf tmp
mv LWC_HASH_KAT_256.txt wrapper/python/

# ---

pushd wrapper/python

python3 -m pytest -v
rm LWC_*_KAT_*.txt

popd

# ---
