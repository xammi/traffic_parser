#! /usr/bin/env python
# encoding: utf-8

from pcap import PCapFile, PCapParser

__author__ = 'max'


def parse_simple():
    p_cap = PCapFile()
    p_cap.open("../samples/simple.cap")

    parser = PCapParser(p_cap)
    global_header, chunks = parser.parse()

    p_cap.close()

if __name__ == "__main__":
    parse_simple()