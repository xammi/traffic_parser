#! /usr/bin/env python
# encoding: utf-8

from pcap import PCapFile, PCapParser
from analyze import FramesAnalyzer

__author__ = 'max'


def parse_file(path):
    p_cap = PCapFile()
    p_cap.open(path)

    parser = PCapParser(p_cap)
    global_header, frames = parser.parse()

    analyzer = FramesAnalyzer(frames)
    analyzer.analyze()

    p_cap.close()

if __name__ == "__main__":
    parse_file("../samples/http.cap")