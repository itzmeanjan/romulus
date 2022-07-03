#!/usr/bin/python3

'''
  Before using `romulus` library module, make sure you've run
  `make lib` and generated shared library object, which is loaded
  here; then all function calls are forwarded to respective C++
  implementation, executed on host CPU.

  Author: Anjan Roy <hello@itzmeanjan.in>
  
  Project: https://github.com/itzmeanjan/romulus
'''

from ctypes import c_size_t, CDLL
import numpy as np
from posixpath import exists, abspath

SO_PATH: str = abspath('../libromulus.so')
assert exists(SO_PATH), 'Use `make lib` to generate shared library object !'

SO_LIB: CDLL = CDLL(SO_PATH)

u8 = np.uint8
len_t = c_size_t
uint8_tp = np.ctypeslib.ndpointer(dtype=u8, ndim=1, flags='CONTIGUOUS')


def romulush(msg: bytes) -> bytes:
    '''
    Given a N ( >= 0 ) -bytes input message, this function computes 32 -bytes
    Romulus-H cryptographic hash
    '''
    m_len = len(msg)
    msg_ = np.frombuffer(msg, dtype=u8)
    digest = np.empty(32, dtype=u8)

    args = [uint8_tp, len_t, uint8_tp]
    SO_LIB.romulush.argtypes = args

    SO_LIB.romulush(msg_, m_len, digest)

    digest_ = digest.tobytes()
    return digest_
