#! /usr/bin/env python
# encoding: utf-8

from constants import SRC_PATH
from pcap import PCapFile, PCapParser, HTTPParser
from utils import save_file

__author__ = 'max'


def parse_file(path):
    print('\nStart parsing of (%s):' % path)

    p_cap = PCapFile()
    p_cap.open(path)

    parser = PCapParser(p_cap)
    global_header, frames = parser.parse()

    # analyzer = FramesAnalyzer(frames)
    # analyzer.analyze()

    # TODO: kostyl, use analyzer
    if HTTPParser.current_file_name is not None:
        save_file(HTTPParser.current_file_name, HTTPParser.current_file)
    # TODO: end kostyl

    print('Successfully parsed\n')
    p_cap.close()

if __name__ == "__main__":
    parse_file(SRC_PATH + 'http.cap')
    parse_file(SRC_PATH + 'ftp2.pcap')
    parse_file(SRC_PATH + 'smtp.pcap')


