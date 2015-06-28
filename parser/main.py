#! /usr/bin/env python
# encoding: utf-8

from pcap import PCapFile, PCapParser, HttpParser
from utils import save_file
# from analyze import FramesAnalyzer

__author__ = 'max'


def parse_file(path):
    p_cap = PCapFile()
    p_cap.open(path)

    parser = PCapParser(p_cap)
    global_header, frames = parser.parse()

    # analyzer = FramesAnalyzer(frames)
    # analyzer.analyze()

    # TODO: kostyl, use analyzer
    if HttpParser.current_file_name is not None:
        save_file(HttpParser.current_file_name, HttpParser.current_file)
    # TODO: end kostyl

    p_cap.close()

if __name__ == "__main__":
    parse_file("../samples/http.cap")
