#! /usr/bin/env python
# encoding: utf-8

from utils import LE, BE, bytes_to_uint

__author__ = 'max'


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


class SecondMethodInvoke(Exception):
    def __init__(self):
        super().__init__(
            'Method must be called once'
        )


class PhInterfaceNotImplemented(Exception):
    def __init__(self):
        super().__init__(
            'Data parser for such kind of physical interface not implemented'
        )


class ProtocolNotImplemented(Exception):
    def __init__(self):
        super().__init__(
            'Such protocol have not been implemented'
        )


class InvalidFieldValue(Exception):
    def __init__(self):
        super().__init__(
            'Unexpected value of special byte field'
        )


class Parser:
    parse_was_invoke = False

    def parse(self):
        if not self.parse_was_invoke:
            self.parse_was_invoke = True
        else:
            raise SecondMethodInvoke()


class PCapGlobalHeaderParser(Parser):
    LINK_LAYERS = {
        0: 'NULL',
        1: 'ETHERNET',
        3: 'AX25',
        6: 'IEEE802_5',
        7: 'ARCNET_BSD',
        8: 'SLIP',
        9: 'PPP',
        10: 'FDDI',
        50: 'PPP_HDLC',
        51: 'PPP_ETHER',
        100: 'ATM_RFC1483',
        101: 'RAW',
        104: 'C_HDLC',
        105: 'IEEE802_11',
        107: 'FRELAY',
        108: 'LOOP',
        113: 'LINUX_SLL',
        114: 'LTALK',
        117: 'PFLOG',
        119: 'IEEE802_11_PRISM',
        122: 'IP_OVER_FC',
        123: 'SUNATM',
        127: 'IEEE802_11_RADIOTAP',
        129: 'ARCNET_LINUX',
        138: 'APPLE_IP_OVER_IEEE1394',
        139: 'MTP2_WITH_PHDR',
        140: 'MTP2',
        141: 'MTP3',
        142: 'SCCP',
        143: 'DOCSIS',
        144: 'LINUX_IRDA',
        147: 'USER0',
        162: 'USER15',
        163: 'IEEE802_11_AVS',
        165: 'BACNET_MS_TP',
        166: 'PPP_PPPD',
        169: 'GPRS_LLC',
        177: 'LINUX_LAPD',
        187: 'BLUETOOTH_HCI_H4',
        189: 'USB_LINUX',
        192: 'PPI',
        195: 'IEEE802_15_4',
        196: 'SITA',
        197: 'ERF',
        201: 'BLUETOOTH_HCI_H4_WITH_PHDR',
        202: 'AX25_KISS',
        203: 'LAPD',
        204: 'PPP_WITH_DIR',
        205: 'C_HDLC_WITH_DIR',
        206: 'FRELAY_WITH_DIR',
        209: 'IPMB_LINUX',
        215: 'IEEE802_15_4_NONASK_PHY',
        220: 'USB_LINUX_MMAPPED',
        224: 'FC_2',
        225: 'FC_2_WITH_FRAME_DELIMS',
        226: 'IPNET',
        227: 'CAN_SOCKETCAN',
        228: 'IPV4',
        229: 'IPV6',
        230: 'IEEE802_15_4_NOFCS',
        231: 'DBUS',
        235: 'DVB_CI',
        236: 'MUX27010',
        237: 'STANAG_5066_D_PDU',
        239: 'NFLOG',
        240: 'NETANALYZER',
        241: 'NETANALYZER_TRANSPARENT',
        242: 'IPOIB',
        243: 'MPEG_2_TS',
        244: 'NG40',
        245: 'NFC_LLCP',
        247: 'INFINIBAND',
        248: 'SCTP',
        249: 'USBPCAP',
        250: 'RTAC_SERIAL',
        251: 'BLUETOOTH_LE_LL',
        253: 'NETLINK',
        254: 'BLUETOOTH_LINUX_MONITOR',
        255: 'BLUETOOTH_BREDR_BB',
        256: 'BLUETOOTH_LE_LL_WITH_PHDR',
        257: 'PROFIBUS_DL',
        258: 'PKTAP',
        259: 'EPON',
        260: 'IPMI_HPM_2',
        261: 'ZWAVE_R1_R2',
        262: 'ZWAVE_R3',
        263: 'WATTSTOPPER_DLM',
    }

    def get_link_type(self):
        return 'LINKTYPE_' + self.LINK_LAYERS[self.link_layer_type]

    def get_dlt_link_type(self):
        return 'DLT_' + self.LINK_LAYERS[self.link_layer_type]

    def __init__(self, p_cap):
        super().__init__()
        self.header = p_cap.read_global()
        self.magic_number = None
        self.byte_order = None
        self.version = None
        self.time_offset = None
        self.time_accuracy = None
        self.snapshot_length = None
        self.link_layer_type = None

    def parse_magic_number(self):
        self.magic_number = self.header[:4]
        if self.magic_number == b'\xd4\xc3\xb2\xa1':
            self.byte_order = LE
        else:
            self.byte_order = BE

    def parse_version(self):
        self.version = self.header[4:8]

    def parse_time_offset(self):
        raw_bytes = self.header[8:12]
        self.time_offset = bytes_to_uint(raw_bytes, self.byte_order)

    def parse_time_accuracy(self):
        self.time_accuracy = self.header[12:16]

    def parse_snapshot_length(self):
        raw_bytes = self.header[16:20]
        self.snapshot_length = bytes_to_uint(raw_bytes, self.byte_order)

    def parse_link_layer_type(self):
        raw_bytes = self.header[20:24]
        self.link_layer_type = bytes_to_uint(raw_bytes, self.byte_order)

    def parse(self):
        super().parse()
        self.parse_magic_number()
        self.parse_version()
        self.parse_time_offset()
        self.parse_time_accuracy()
        self.parse_snapshot_length()
        self.parse_link_layer_type()


class PCapHeaderParser(Parser):
    def __init__(self, p_cap, byte_order):
        super().__init__()
        self.header = p_cap.read_header()
        self.byte_order = byte_order
        self.seconds = None
        self.microseconds = None
        self.saved_size = None
        self.captured_size = None

    def parse_seconds(self):
        self.seconds = self.header[:4]

    def parse_microseconds(self):
        self.microseconds = self.header[4:8]

    def parse_saved_size(self):
        raw_bytes = self.header[8:12]
        self.saved_size = bytes_to_uint(raw_bytes, self.byte_order)

    def parse_captured_size(self):
        raw_bytes = self.header[12:16]
        self.seconds = bytes_to_uint(raw_bytes, self.byte_order)

    def parse(self):
        super().parse()
        self.parse_seconds()
        self.parse_microseconds()
        self.parse_saved_size()
        self.parse_captured_size()


class BodyParser(Parser):
    def __init__(self, data, byte_order):
        super().__init__()
        self.byte_order = byte_order
        self.data = data
        self.processed = None


class PCapBodyParser(Parser):
    def __init__(self, p_cap, p_cap_header, phys_interface_type):
        super().__init__()
        saved_size = p_cap_header.saved_size
        self.data = p_cap.read_data(saved_size)
        self.header = p_cap_header
        self.phys_interface_type = phys_interface_type
        self.help_parsers = []

    def get_init_parser(self):
        byte_order = self.header.byte_order

        if self.phys_interface_type == 1:
            return EthernetParser(self.data, byte_order)
        else:
            raise PhInterfaceNotImplemented()

    def parse(self):
        super().parse()
        length = self.header.saved_size
        parser = self.get_init_parser()
        self.help_parsers.append(parser)

        while length > 0:
            parser.parse()
            length -= parser.processed

            parser = parser.next_parser()
            if parser:
                self.help_parsers.append(parser)
            else:
                break


class EthernetParser(BodyParser):
    def __init__(self, data, byte_order):
        super().__init__(data, byte_order)
        self.destination = None
        self.source = None
        self.type = None

    def parse_destination(self):
        self.destination = self.data[:6]

    def parse_source(self):
        self.source = self.data[6:12]

    def parse_type(self):
        self.type = self.data[12:14]

    def parse(self):
        super().parse()
        self.parse_destination()
        self.parse_source()
        self.parse_type()
        self.processed = 14

    def next_parser(self):
        start = self.processed
        if self.type == b'\x08\x00':
            return IPParser(self.data[start:], self.byte_order)
        else:
            raise ProtocolNotImplemented()


class IPParser(BodyParser):
    def __init__(self, data, byte_order):
        super().__init__(data, byte_order)
        self.version = None
        self.length = None
        self.source = None
        self.destination = None
        self.protocol = None

    def parse_first_byte(self):
        raw_bytes = self.data[:1]
        raw_num = bytes_to_uint(raw_bytes, self.byte_order)
        if 64 < raw_num <= 80:
            self.version = 4
            self.length = (raw_num - 64) * 4
        elif 96 < raw_num:
            self.version = 6
            self.length = (raw_num - 96) * 4
        else:
            raise InvalidFieldValue()

    def parse_protocol(self):
        raw_bytes = self.data[9:10]
        self.protocol = bytes_to_uint(raw_bytes, self.byte_order)

    def parse_source(self):
        self.source = self.data[12:16]

    def parse_destination(self):
        self.destination = self.data[16:20]

    def parse(self):
        super().parse()
        self.parse_first_byte()
        self.parse_source()
        self.parse_destination()
        self.parse_protocol()
        self.processed = self.length

    def next_parser(self):
        start = self.processed
        if self.protocol == 6:
            return TCPParser(self.data[start:], self.byte_order)
        else:
            raise ProtocolNotImplemented()


class TCPParser(BodyParser):
    def __init__(self, data, byte_order):
        super().__init__(data, byte_order)
        self.length = None

    def parse_length(self):
        # raw_bytes = self.data[:1]
        # self.length = bytes_to_uint(raw_bytes, self.byte_order)
        self.length = 20

    def parse(self):
        super().parse()
        self.parse_length()
        self.processed = self.length

    def next_parser(self):
        return None


class PCapParser(Parser):
    def __init__(self, p_cap):
        self.p_cap = p_cap

    def parse(self):
        super().parse()

        global_header_parser = PCapGlobalHeaderParser(self.p_cap)
        global_header_parser.parse()

        phys_interface_type = global_header_parser.link_layer_type
        byte_order = global_header_parser.byte_order

        frames = []
        while True:
            header_parser = PCapHeaderParser(self.p_cap, byte_order)
            if header_parser.header == b'':
                break

            header_parser.parse()
            body_parser = PCapBodyParser(self.p_cap, header_parser, phys_interface_type)
            body_parser.parse()

            frames += [(header_parser, body_parser)]

        return global_header_parser, frames