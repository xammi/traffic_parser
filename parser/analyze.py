#! /usr/bin/env python
# encoding: utf-8

from pcap import EthernetParser, IPParser, TCPParser, HttpParser, SMTPParser, SMB2Parser, POP3Parser
from exceptions import SecondMethodInvoke

__author__ = 'max'


class Analyzer():
    analyze_was_invoked = False

    def analyze(self):
        if not self.analyze_was_invoked:
            self.analyze_was_invoked = True
        else:
            raise SecondMethodInvoke('analyze')


class PartialAnalyzer(Analyzer):
    def analyze_part(self, body, parser):
        super().analyze()


class HttpAnalyzer(PartialAnalyzer):
    def __init__(self):
        pass

    def analyze_part(self, body, parser):
        pass


class FramesAnalyzer(Analyzer):
    def __init__(self, frames):
        self.frames = frames

        self.ANALYZERS = {
            HttpParser.__name__: HttpAnalyzer()
        }

    def analyze_frame(self, frame):
        header, body = frame[0], frame[1]
        for parser in body.help_parsers:
            try:
                analyzer = self.ANALYZERS[parser.__class__.__name__]
                analyzer.analyze_part(body, parser)
            except KeyError:
                pass

    def analyze(self):
        super().analyze()
        for frame in self.frames:
            self.analyze_frame(frame)