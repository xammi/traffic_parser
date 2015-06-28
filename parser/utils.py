#! /usr/bin/env python
# encoding: utf-8

from exceptions import NotUnicode
import os
import errno

__author__ = 'max'


LE = 0
BE = 1
BYTE_ORDER = {
    LE: 'little',
    BE: 'big'
}

FTP_HEADER_LENGTH = 32
FTP_TRANSFER_COMPLETE = '226'
FTP_TRANSFER_START = '150'


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

def save_file(path, data):
    path, name = os.path.split(path)
    path = '/home/max/parser/' + path + '/'
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
    open(path + name, 'wb').write(data)
