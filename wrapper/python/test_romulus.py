#!/usr/bin/python3

import romulus
import numpy as np

u8 = np.uint8


def test_romulush_kat():
    """
    Test functional correctness of Romulus-H cryptographic hash implementation,
    by comparing digests against NIST LWC submission package's Known Answer Tests

    See https://csrc.nist.gov/projects/lightweight-cryptography/finalists
    """
    with open("LWC_HASH_KAT_256.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs
                break

            msg = fd.readline()
            md = fd.readline()

            cnt = int([i.strip() for i in cnt.split("=")][-1])
            msg = [i.strip() for i in msg.split("=")][-1]
            md = [i.strip() for i in md.split("=")][-1]

            msg = bytes(
                [
                    int(f"0x{msg[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(msg) >> 1)
                ]
            )

            md = bytes(
                [
                    int(f"0x{md[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(md) >> 1)
                ]
            )

            digest = romulus.romulush(msg)

            assert (
                md == digest
            ), f"[Romulus-H Hash KAT {cnt}] expected {md}, found {digest} !"

            fd.readline()


def test_romulusn_kat():
    """
    Tests functional correctness of Romulus-N AEAD implementation, using
    Known Answer Tests submitted along with final round submission of Romulus
    in NIST LWC

    See https://csrc.nist.gov/projects/lightweight-cryptography/finalists
    """
    with open("LWC_AEAD_KAT_128_128.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            key = fd.readline()
            nonce = fd.readline()
            pt = fd.readline()
            ad = fd.readline()
            ct = fd.readline()

            # extract out required fields
            cnt = int([i.strip() for i in cnt.split("=")][-1])
            key = [i.strip() for i in key.split("=")][-1]
            nonce = [i.strip() for i in nonce.split("=")][-1]
            pt = [i.strip() for i in pt.split("=")][-1]
            ad = [i.strip() for i in ad.split("=")][-1]
            ct = [i.strip() for i in ct.split("=")][-1]

            # 128 -bit secret key
            key = int(f"0x{key}", base=16).to_bytes(16, "big")
            # 128 -bit public message nonce
            nonce = int(f"0x{nonce}", base=16).to_bytes(16, "big")
            # plain text
            pt = bytes(
                [
                    int(f"0x{pt[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(pt) >> 1)
                ]
            )
            # associated data
            ad = bytes(
                [
                    int(f"0x{ad[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ad) >> 1)
                ]
            )
            # cipher text + authentication tag ( expected )
            ct = bytes(
                [
                    int(f"0x{ct[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ct) >> 1)
                ]
            )

            cipher, tag = romulus.romulusn_encrypt(key, nonce, ad, pt)
            flag, text = romulus.romulusn_decrypt(key, nonce, tag, ad, cipher)

            assert (
                cipher + tag == ct
            ), f"[Romulus-N KAT {cnt}] expected cipher to be 0x{ct.hex()}, found 0x{(cipher + tag).hex()} !"
            assert (
                pt == text and flag
            ), f"[Romulus-N KAT {cnt}] expected plain text 0x{pt.hex()}, found 0x{text.hex()} !"

            # don't need this line, so discard
            fd.readline()


def test_romulusm_kat():
    """
    Tests functional correctness of Romulus-M AEAD implementation, using
    Known Answer Tests submitted along with final round submission of Romulus
    in NIST LWC

    See https://csrc.nist.gov/projects/lightweight-cryptography/finalists
    """
    with open("LWC_AEAD_KAT_128_128.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            key = fd.readline()
            nonce = fd.readline()
            pt = fd.readline()
            ad = fd.readline()
            ct = fd.readline()

            # extract out required fields
            cnt = int([i.strip() for i in cnt.split("=")][-1])
            key = [i.strip() for i in key.split("=")][-1]
            nonce = [i.strip() for i in nonce.split("=")][-1]
            pt = [i.strip() for i in pt.split("=")][-1]
            ad = [i.strip() for i in ad.split("=")][-1]
            ct = [i.strip() for i in ct.split("=")][-1]

            # 128 -bit secret key
            key = int(f"0x{key}", base=16).to_bytes(16, "big")
            # 128 -bit public message nonce
            nonce = int(f"0x{nonce}", base=16).to_bytes(16, "big")
            # plain text
            pt = bytes(
                [
                    int(f"0x{pt[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(pt) >> 1)
                ]
            )
            # associated data
            ad = bytes(
                [
                    int(f"0x{ad[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ad) >> 1)
                ]
            )
            # cipher text + authentication tag ( expected )
            ct = bytes(
                [
                    int(f"0x{ct[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ct) >> 1)
                ]
            )

            cipher, tag = romulus.romulusm_encrypt(key, nonce, ad, pt)
            flag, text = romulus.romulusm_decrypt(key, nonce, tag, ad, cipher)

            assert (
                cipher + tag == ct
            ), f"[Romulus-M KAT {cnt}] expected cipher to be 0x{ct.hex()}, found 0x{(cipher + tag).hex()} !"
            assert (
                pt == text and flag
            ), f"[Romulus-M KAT {cnt}] expected plain text 0x{pt.hex()}, found 0x{text.hex()} !"

            # don't need this line, so discard
            fd.readline()


def test_romulust_kat():
    """
    Tests functional correctness of Romulus-T AEAD implementation, using
    Known Answer Tests submitted along with final round submission of Romulus
    in NIST LWC

    See https://csrc.nist.gov/projects/lightweight-cryptography/finalists
    """
    with open("LWC_AEAD_KAT_128_128.txt", "r") as fd:
        while True:
            cnt = fd.readline()
            if not cnt:
                # no more KATs remaining
                break

            key = fd.readline()
            nonce = fd.readline()
            pt = fd.readline()
            ad = fd.readline()
            ct = fd.readline()

            # extract out required fields
            cnt = int([i.strip() for i in cnt.split("=")][-1])
            key = [i.strip() for i in key.split("=")][-1]
            nonce = [i.strip() for i in nonce.split("=")][-1]
            pt = [i.strip() for i in pt.split("=")][-1]
            ad = [i.strip() for i in ad.split("=")][-1]
            ct = [i.strip() for i in ct.split("=")][-1]

            # 128 -bit secret key
            key = int(f"0x{key}", base=16).to_bytes(16, "big")
            # 128 -bit public message nonce
            nonce = int(f"0x{nonce}", base=16).to_bytes(16, "big")
            # plain text
            pt = bytes(
                [
                    int(f"0x{pt[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(pt) >> 1)
                ]
            )
            # associated data
            ad = bytes(
                [
                    int(f"0x{ad[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ad) >> 1)
                ]
            )
            # cipher text + authentication tag ( expected )
            ct = bytes(
                [
                    int(f"0x{ct[(i << 1): ((i+1) << 1)]}", base=16)
                    for i in range(len(ct) >> 1)
                ]
            )

            cipher, tag = romulus.romulust_encrypt(key, nonce, ad, pt)
            flag, text = romulus.romulust_decrypt(key, nonce, tag, ad, cipher)

            assert (
                cipher + tag == ct
            ), f"[Romulus-T KAT {cnt}] expected cipher to be 0x{ct.hex()}, found 0x{(cipher + tag).hex()} !"
            assert (
                pt == text and flag
            ), f"[Romulus-T KAT {cnt}] expected plain text 0x{pt.hex()}, found 0x{text.hex()} !"

            # don't need this line, so discard
            fd.readline()


if __name__ == "__main__":
    print("Execute test cases using `pytest`")
