#! /usr/bin/env python
# encoding: utf-8

__author__ = 'max'


class PCapException(Exception):
    pass


class FormatException(PCapException):
    def __init__(self, message):
        super(FormatException, self).__init__(message)


class SecondMethodInvoke(PCapException):
    def __init__(self, method_name):
        super().__init__(
            'Method (%s) must be called once' % method_name
        )


class PhInterfaceNotImplemented(PCapException):
    def __init__(self, interface):
        super().__init__(
            'Data parser for such kind of physical interface (%s) not implemented' % interface
        )


class ProtocolNotImplemented(PCapException):
    def __init__(self, protocol):
        super().__init__(
            'Such protocol (%d) have not been implemented' % protocol
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


class FileAlreadyExist(PCapException):
    def __init__(self, path):
        super().__init__(
            'File already exists at (%s)' % path
        )