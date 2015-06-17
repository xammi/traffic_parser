#! /usr/bin/env python
# encoding: utf-8


class PCapFormatException(Exception):
    def __init__(self, message):
        super(PCapFormatException, self).__init__(message)


class PCapFile:
    def __init__(self):
        self.file = None

    def open(self, file_path):
        self.file = open(file_path, "rb")
        return self

    def close(self):
        self.file.close()
        return self

    def read_global(self):
        return self.read_data(24, 'global header')

    def read_header(self):
        return self.read_data(16, 'header')

    def read_data(self, size, err_format_msg='data'):
        try:
            data = self.file.read(size)
            return data
        except IOError:
            raise PCapFormatException('Wrong length of ' + err_format_msg)


LE = 0
BE = 1
BYTE_ORDER = {
    LE: 'Little-endian',
    BE: 'Big-endian'
}


class SecondMethodInvoke(Exception):
    def __init__(self):
        super(SecondMethodInvoke, self).__init__('Method must be called once')


class Parser:
    parse_was_invoke = False

    def parse(self):
        if not self.parse_was_invoke:
            self.parse_was_invoke = True
        else:
            raise SecondMethodInvoke()


class PCapGlobalHeaderParser(Parser):
    magic_number = None
    byte_order = None
    version = None
    time_offset = None
    time_accuracy = None
    snapshot_length = None
    link_layer_type = None

    def __init__(self, p_cap):
        self.header = p_cap.read_global()

    def parse_magic_number(self):
        self.magic_number = self.header[:4]
        if self.magic_number == '\xd4\xc3\xb2\xa1':
            self.byte_order = LE
        else:
            self.byte_order = BE

    def parse_version(self):
        self.version = self.header[4:8]

    def parse_time_offset(self):
        self.time_offset = self.header[8:12]

    def parse_time_accuracy(self):
        self.time_accuracy = self.header[12:16]

    def parse_snapshot_length(self):
        self.snapshot_length = self.header[16:20]

    def parse_link_layer_type(self):
        self.link_layer_type = self.header[16:20]

    def parse(self):
        super().parse()
        self.parse_magic_number()
        self.parse_version()
        self.parse_time_offset()
        self.parse_time_accuracy()
        self.parse_snapshot_length()
        self.parse_link_layer_type()


class PCapHeaderParser(Parser):
    seconds = None
    microseconds = None
    saved_size = None
    captured_size = None

    def __init__(self, p_cap, byte_order):
        self.header = p_cap.read_header()
        self.byte_order = byte_order

    def parse_seconds(self):
        self.seconds = self.header[:4]

    def parse_microseconds(self):
        self.microseconds = self.header[4:8]

    def parse_saved_size(self):
        self.saved_size = self.header[8:12]

    def parse_captured_size(self):
        self.seconds = self.header[12:16]

    def parse(self):
        super().parse()
        self.parse_seconds()
        self.parse_microseconds()
        self.parse_saved_size()
        self.parse_captured_size()


class PCapDataParser(Parser):
    def __init__(self, p_cap, p_cap_header):
        saved_size = p_cap_header.saved_size
        self.data = p_cap.read_data(saved_size)
        self.header = p_cap_header

    def parse(self):
        super().parse()


class PCapParser(Parser):
    def __init__(self, p_cap):
        self.p_cap = p_cap

    def parse(self):
        super().parse()

        global_header_parser = PCapGlobalHeaderParser(self.p_cap)
        global_header_parser.parse()

        byte_order = global_header_parser.byte_order

        chunks = []
        while True:
            header_parser = PCapHeaderParser(self.p_cap, byte_order)
            if header_parser.header == '':
                break

            header_parser.parse()
            data_parser = PCapDataParser(self.p_cap, header_parser)
            data_parser.parse()

            chunks += [(header_parser, data_parser)]

        return global_header_parser, chunks


if __name__ == "__main__":
    p_cap = PCapFile()
    p_cap.open("../samples/simple.cap")

    parser = PCapParser(p_cap)
    global_header, chunks = parser.parse()

    p_cap.close()