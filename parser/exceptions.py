#! /usr/bin/env python
# encoding: utf-8

__author__ = 'max'


class PCapException(Exception):
    pass


class FormatException(PCapException):
    def __init__(self, message):
        super(FormatException, self).__init__(message)


class SecondMethodInvoke(PCapException):
    def __init__(self):
        super().__init__(
            'Method must be called once'
        )


class PhInterfaceNotImplemented(PCapException):
    def __init__(self):
        super().__init__(
            'Data parser for such kind of physical interface not implemented'
        )


class ProtocolNotImplemented(PCapException):
    def __init__(self):
        super().__init__(
            'Such protocol have not been implemented'
        )


class InvalidFieldValue(PCapException):
    def __init__(self):
        super().__init__(
            'Unexpected value of special byte field'
        )


class InvalidHttpFormat(PCapException):
    def __init__(self):
        super().__init__(
            'Unexpected value of special byte field'
        )


class NotUnicode(PCapException):
    def __init__(self):
        super().__init__(
            'Expected byte data must be unicode'
        )