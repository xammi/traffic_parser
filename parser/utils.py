#! /usr/bin/env python
# encoding: utf-8

from exceptions import NotUnicode

__author__ = 'max'


LE = 0
BE = 1
BYTE_ORDER = {
    LE: 'little',
    BE: 'big'
}


def bytes_to_uint(raw_bytes, byte_order):
    return int.from_bytes(raw_bytes, byteorder=BYTE_ORDER[byte_order], signed=False)


def bytes_to_string(raw_bytes):
    try:
        return raw_bytes.decode(encoding='UTF-8')
    except UnicodeDecodeError:
        raise NotUnicode()


def read_til_zero(data, start):
    pos = start
    while True:
        if data[pos] == 0:
            break
        else:
            pos += 1
    return data[start:pos], pos + 1