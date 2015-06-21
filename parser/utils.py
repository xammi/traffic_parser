#! /usr/bin/env python
# encoding: utf-8

__author__ = 'max'


LE = 0
BE = 1
BYTE_ORDER = {
    LE: 'little',
    BE: 'big'
}


def bytes_to_uint(raw_bytes, byte_order):
    return int.from_bytes(raw_bytes, byteorder=BYTE_ORDER[byte_order], signed=False)