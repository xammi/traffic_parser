#! /usr/bin/env python
# encoding: utf-8

from constants import BYTE_ORDER, SAVE_PATH
from exceptions import NotUnicode, FileAlreadyExist
import os
import errno

__author__ = 'max'


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


def read_til(data, start, end_seq):
    data_len = len(data)
    end_len = len(end_seq)
    pos = start
    while True:
        if pos + end_len >= data_len or data[pos:pos + end_len] == end_seq:
            break
        else:
            pos += 1
    return data[start:pos], pos + end_len


def ip_to_string(bytes_ip):
    return '%d.%d.%d.%d' % (bytes_ip[0], bytes_ip[1], bytes_ip[2], bytes_ip[3])


def form_path(source_ip, dest_ip, path):
    sip = ip_to_string(source_ip)
    dip = ip_to_string(dest_ip)
    prefix = SAVE_PATH.strip('/')
    trimmed_path = path.strip('/')
    return '/%s/%s/%s/%s' % (prefix, sip, dip, trimmed_path)


def save_file(path, data, buffered=False):
    dirs_path, name = os.path.split(path)

    try:
        os.makedirs(dirs_path)
    except OSError as e:
        if e.errno == errno.EEXIST:
            pass
        else:
            raise

    if not buffered:
        open(path, 'w').write(data)
    else:
        open(path, 'wb').write(data)
