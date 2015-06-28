#! /usr/bin/env python
# encoding: utf-8

from constants import HTTP_PORTS, SMTP_PORTS, LE, BE, FTP_HEADER_LENGTH, FTP_TRANSFER_COMPLETE,\
    FTP_TRANSFER_START, POP3_PORT
from utils import bytes_to_uint, bytes_to_string, read_til, read_til_zero, save_file
from exceptions import PCapException, FormatException, SecondMethodInvoke, PhInterfaceNotImplemented, \
    ProtocolNotImplemented, InvalidFieldValue, InvalidHttpFormat, NotUnicode
import re


__author__ = 'max'


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
            raise FormatException('Wrong length of ' + err_format_msg)


class Parser:
    parse_was_invoke = False

    def parse(self):
        if not self.parse_was_invoke:
            self.parse_was_invoke = True
        else:
            raise SecondMethodInvoke('parse')


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
        byte_order = BE

        if self.phys_interface_type == 1:
            return EthernetParser(self.data, byte_order)
        else:
            interface = PCapGlobalHeaderParser.LINK_LAYERS[self.phys_interface_type]
            raise PhInterfaceNotImplemented(interface)

    def forward_parse(self):
        length = self.header.saved_size
        parser = self.get_init_parser()
        self.help_parsers.append(parser)

        while length > 0:
            parser.parse()
            # print(parser.processed)
            length -= parser.processed

            parser = parser.next_parser()
            if parser:
                self.help_parsers.append(parser)
            else:
                break
        return length

    def parse(self):
        super().parse()
        length = self.forward_parse()
        if length > 0:
            print('Not parsed %d bytes' % length)


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
            raise ProtocolNotImplemented(self.type)


class IPParser(BodyParser):
    def __init__(self, data, byte_order):
        super().__init__(data, byte_order)
        self.version = None
        self.length = None
        self.total = None
        self.source = None
        self.destination = None
        self.protocol = None

    def parse_first_byte(self):
        raw_bytes = self.data[:1]
        raw_num = bytes_to_uint(raw_bytes, self.byte_order)
        firstb, secondb = raw_num // 16, raw_num % 16
        if firstb not in [4, 6]:
            raise InvalidFieldValue()
        self.version = firstb
        self.length = secondb * 4

    def parse_total(self):
        raw_bytes = self.data[2:4]
        raw_num = bytes_to_uint(raw_bytes, self.byte_order)
        if raw_num < 20 or raw_num > 65535:
            return InvalidFieldValue()
        self.total = raw_num

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
        self.parse_total()
        self.parse_source()
        self.parse_destination()
        self.parse_protocol()
        self.processed = self.length

    def next_parser(self):
        start = self.processed
        if self.protocol == 6:
            tcp_packet_size = self.total - self.length
            return TCPParser(self.data[start:], tcp_packet_size, self.byte_order)
        elif self.protocol == 17:
            return UDPParser(self.data[start:], self.byte_order)
        else:
            raise ProtocolNotImplemented(self.protocol)


class TCPParser(BodyParser):
    def __init__(self, data, packet_size, byte_order):
        super().__init__(data, byte_order)
        self.packet_size = packet_size
        self.length = None
        self.flags = None
        self.seq_num = None
        self.ack_num = None
        self.source_port = None
        self.destination_port = None

    def parse_length(self):
        raw_bytes = self.data[12:13]
        raw_num = bytes_to_uint(raw_bytes, self.byte_order)
        firstb, secondb = raw_num // 16, raw_num % 16
        if secondb != 0 or firstb < 5 or firstb > 15:
            raise InvalidFieldValue()
        self.length = firstb * 4

    def parse_padding(self):
        length = len(self.data)
        counter = self.length
        while counter < length and self.data[counter] == 0:
            counter += 1
            self.length += 1

    def parse_flags(self):
        self.flags = self.data[12:14]

    def parse_seq_num(self):
        self.seq_num = self.data[4:8]

    def parse_ack_num(self):
        self.ack_num = self.data[8:12]

    def parse_source_port(self):
        raw_bytes = self.data[:2]
        self.source_port = bytes_to_uint(raw_bytes, self.byte_order)

    def parse_destination_port(self):
        raw_bytes = self.data[2:4]
        self.destination_port = bytes_to_uint(raw_bytes, self.byte_order)

    def parse(self):
        super().parse()
        self.parse_length()
        self.parse_flags()
        self.parse_seq_num()
        self.parse_ack_num()
        self.parse_padding()
        self.parse_source_port()
        self.parse_destination_port()
        self.processed = self.length

    def next_parser(self):
        start = self.processed
        packet_size = self.packet_size - self.length
        parametrs = [self.data[start:], packet_size, self.byte_order]
        if self.source_port in HTTP_PORTS or self.destination_port in HTTP_PORTS:
            return HTTPParser(*parametrs)
        elif self.source_port in SMTP_PORTS or self.destination_port in SMTP_PORTS:
            return SMTPParser(*parametrs)
        elif self.source_port == POP3_PORT:
            return POP3Parser(*parametrs)
        else:
            return FTPParser(*parametrs)


class UDPParser(BodyParser):
    def __init__(self, data, byte_order):
        super().__init__(data, byte_order)
        self.source_port = None
        self.destination_port = None
        self.data_length = None

    def parse_source_port(self):
        raw_bytes = self.data[:2]
        self.source_port = bytes_to_uint(raw_bytes, self.byte_order)

    def parse_destination_port(self):
        raw_bytes = self.data[2:4]
        self.destination_port = bytes_to_uint(raw_bytes, self.byte_order)

    def parse_data_length(self):
        raw_bytes = self.data[4:6]
        self.data_length = bytes_to_uint(raw_bytes, self.byte_order)

    def parse(self):
        super().parse()
        self.parse_source_port()
        self.parse_destination_port()
        self.parse_data_length()
        self.processed = 8

    def next_parser(self):
        start = self.processed
        dns_packet_size = self.data_length
        if self.source_port == 53 or self.destination_port == 53:
            return DNSParser(self.data[start:], dns_packet_size, self.byte_order)
        else:
            raise ProtocolNotImplemented(17)


class HTTPParser(BodyParser):
    current_file = ''
    current_file_name = None

    def __init__(self, data, packet_size, byte_order):
        super().__init__(data, byte_order)
        self.packet_size = packet_size

        self.starting_line = None
        self.headers = dict()
        self.body = ''

    def parse_starting_line(self, line):
        if len(line.split(' ')) == 3:
            self.starting_line = line
            return True
        else:
            return False

    def parse_header(self, line):
        key, value = line.split(':', 1)
        key = key.strip()
        value = value.strip()
        self.headers[key] = value

    def parse_headers(self, lines):
        for (I, line) in enumerate(lines):
            if line == '':
                return I
            if I != 0:
                self.parse_header(line)
        return None

    def parse_body(self, body_start_num, lines):
        for I in range(body_start_num, len(lines)):
            self.body += lines[I]

    # TODO: kostyl, use analyzer
    def set_current_file_name(self):
        current_name = self.starting_line.split(' ')[1]
        if '?' in current_name:
            current_name = current_name.split('?')[0]

        if current_name.isnumeric():
            return

        if HTTPParser.current_file_name is not None and HTTPParser.current_file_name != current_name:
            save_file(HTTPParser.current_file_name, HTTPParser.current_file)
            HTTPParser.current_file = ''

        HTTPParser.current_file_name = current_name
    # TODO: end kostyl

    def parse(self):
        super().parse()
        char_data = bytes_to_string(self.data[:self.packet_size])
        lines = char_data.splitlines()

        if len(lines) > 0:
            parsed = self.parse_starting_line(lines[0])
            if parsed:
                # TODO: kostyl, use analyzer
                self.set_current_file_name()
                # TODO: end kostyl

                empty_str_index = self.parse_headers(lines)
                self.parse_body(empty_str_index + 1, lines)
            else:
                self.parse_body(0, lines)

            self.processed = self.packet_size

            # TODO: kostyl, use analyzer
            HTTPParser.current_file += self.body
            # TODO: end kostyl
        else:
            raise InvalidHttpFormat()

    def next_parser(self):
        return None


class DNSParser(BodyParser):
    def __init__(self, data, packet_size, byte_order):
        super().__init__(data, byte_order)
        self.packet_size = packet_size

        self.transaction_id = None
        self.questions = None
        self.answers_rss = None
        self.flags = None
        self.queries = []
        self.answers = []

    def parse_transaction_id(self):
        self.transaction_id = self.data[:2]

    def parse_flags(self):
        self.flags = self.data[2:4]

    def parse_questions(self):
        raw_bytes = self.data[4:6]
        self.questions = bytes_to_uint(raw_bytes, self.byte_order)

    def parse_answers_rss(self):
        raw_bytes = self.data[6:8]
        self.answers_rss = bytes_to_uint(raw_bytes, self.byte_order)

    def parse_queries(self):
        pos = 12
        for I in range(0, self.questions):
            name, pos = read_til_zero(self.data, pos)
            self.queries.append({
                'name': bytes_to_string(name),
                'type': self.data[pos:pos+2],
                'class': self.data[pos+2:pos+4],
            })
            pos += 4
        return pos

    def parse_answers(self, start_pos):
        pos = start_pos
        for I in range(0, self.answers_rss):
            raw_data_length = self.data[pos+10:pos+12]
            data_length = bytes_to_uint(raw_data_length, self.byte_order)
            answer_length = 12 + data_length

            self.answers.append({
                'name': self.data[pos:pos+2],
                'type': self.data[pos+2:pos+4],
                'class': self.data[pos+4:pos+6],
                'time_to_live': self.data[pos+6:pos+10],
                'data': self.data[pos+12:pos+answer_length],
            })
            pos += answer_length
        return pos

    def parse(self):
        super().parse()
        self.parse_transaction_id()
        self.parse_flags()
        self.parse_questions()
        self.parse_answers_rss()

        end_queries_pos = self.parse_queries()
        end_answers_pos = self.parse_answers(end_queries_pos)
        self.processed = self.packet_size

    def next_parser(self):
        return None


class SMTPParser(BodyParser):

    # TODO: kostyl, use analyzer
    current_mail_data = ''
    file_counter = 0

    SMTH_STATE = 0
    PRE_DATA_STATE = 1
    DATA_STATE = 2

    session_state = SMTH_STATE
    # TODO: end kostyl

    def __init__(self, data, packet_size, byte_order):
        super().__init__(data, byte_order)
        self.packet_size = packet_size
        # self.ip_address = ip_address
        self.parts = []

    # TODO: kostyl, use analyzer
    def save_current_mail_data(self):
        if SMTPParser.current_mail_data != '':
            path = 'smtp_data_%d' % SMTPParser.file_counter
            save_file(path, SMTPParser.current_mail_data)
            SMTPParser.current_mail_data = ''
            SMTPParser.file_counter += 1

    def check_state(self, part):
        if SMTPParser.session_state == self.PRE_DATA_STATE and 'Enter message' not in part:
            SMTPParser.session_state = self.DATA_STATE

        if 'DATA' in part:
            SMTPParser.session_state = self.PRE_DATA_STATE
        elif '250 OK' in part:
            SMTPParser.session_state = self.SMTH_STATE
            self.save_current_mail_data()
    # TODO: end kostyl

    def parse(self):
        super().parse()
        pos = 0
        while pos < self.packet_size:
            part, pos = read_til(self.data, pos, b'\x0d\x0a')
            part = bytes_to_string(part)

            # TODO: kostyl, use analyzer
            self.check_state(part)
            if SMTPParser.session_state == self.DATA_STATE:
                SMTPParser.current_mail_data += part
            # TODO: end kostyl

            self.parts.append(part)

        self.processed = self.packet_size

    def next_parser(self):
        return None


class SMB2Parser(BodyParser):
    def __init__(self, data, byte_order):
        super().__init__(data, byte_order)

    def parse(self):
        super().parse()

    def next_parser(self):
        return None


class POP3Parser(BodyParser):

    sender = None
    receiver = None
    date = None
    subject = None
    message = None

    def __init__(self, data, packet_size, byte_order):
        self.packet_size = packet_size
        super().__init__(data, byte_order)

    def is_start_message(self):
        return True if b'From:' in self.data else False

    def is_end_message(self):
        end = b'\r\n.\r\n'
        if end in self.data:
            self.data = self.data[:self.data.index(end)]
            return True
        return False

    def parse_sender(self):
        response = bytes_to_string(self.data)
        r = re.compile('From: (.*?)>')
        m = r.search(response)
        if m:
            POP3Parser.sender = m.group(1) + '>'

    def parse_receiver(self):
        response = bytes_to_string(self.data)
        r = re.compile('To: (.*?)\r\n')
        m = r.search(response)
        if m:
            POP3Parser.receiver = m.group(1)

    def parse_date(self):
        response = bytes_to_string(self.data)
        r = re.compile('Date: (.*?)\r\n')
        m = r.search(response)
        if m:
            POP3Parser.date = m.group(1)

    def parse_subject(self):
        response = bytes_to_string(self.data)
        r = re.compile('Subject: (.*?)\r\n')
        m = r.search(response)
        if m:
            POP3Parser.subject = m.group(1)

    def parse(self):
        super().parse()
        self.processed = self.packet_size
        if self.sender is not None:
            if self.is_end_message():
                self.message += self.data
                print(self.sender)
                print(self.receiver)
                print(self.date)
                print(self.subject)
                print(self.message)
                print("_________")
                self.sender = None
            else:
                POP3Parser.message += self.data
        if self.is_start_message():
            self.parse_sender()
            self.parse_receiver()
            self.parse_date()
            self.parse_subject()
            delimiter = b'Encoding: quoted-printable:'
            if delimiter in self.data:
                self.data = self.data[self.data.index(delimiter):]
            delimiter = b'\r\n\r\n'
            if delimiter in self.data:
                self.data = self.data[self.data.index(delimiter):]
            POP3Parser.message = self.data
            pass

    def next_parser(self):
        return None


class FTPParser(BodyParser):

    file = b""
    current_file_name = None

    def __init__(self, data, packet_size, byte_order):
        super().__init__(data, byte_order)
        self.packet_size = packet_size

    def is_code_type(self, code):
        try:
            code_type = bytes_to_string(self.data[0:3])
            if code_type == FTP_TRANSFER_COMPLETE:
                pass
            return True if code_type == code else False
        except PCapException as e:
            print(e.__str__())

    def set_current_file_name(self):
        if b'\r' in self.data:
            self.data = self.data[:self.data.index(b'\r')]
        response = bytes_to_string(self.data)
        r = re.compile('for (.*?) \(')
        m = r.search(response)
        if m:
            FTPParser.current_file_name = m.group(1)

    def parse(self):
        super().parse()
        self.processed = self.packet_size
        if self.is_code_type(FTP_TRANSFER_COMPLETE) and FTPParser.current_file_name is not None:
            save_file(FTPParser.current_file_name, FTPParser.file, True)
            FTPParser.current_file_name = None
            FTPParser.file = b""
        if FTPParser.current_file_name is not None:
            FTPParser.file += self.data
        elif self.is_code_type(FTP_TRANSFER_START):
            self.set_current_file_name()

    def next_parser(self):
        return None


class PCapParser(Parser):
    def __init__(self, p_cap):
        self.p_cap = p_cap

    def parse_frame(self, byte_order, phys_interface_type):
        header_parser = PCapHeaderParser(self.p_cap, byte_order)
        if header_parser.header == b'':
            return None

        header_parser.parse()
        body_parser = PCapBodyParser(self.p_cap, header_parser, phys_interface_type)
        body_parser.parse()
        return header_parser, body_parser

    def parse(self):
        super().parse()

        global_header_parser = PCapGlobalHeaderParser(self.p_cap)
        global_header_parser.parse()

        phys_interface_type = global_header_parser.link_layer_type
        byte_order = global_header_parser.byte_order

        frames = []
        counter = 1
        while True:
            try:
                frame = self.parse_frame(byte_order, phys_interface_type)
                if not frame:
                    break

                frames += [frame]
                print('Frame number %d parsed' % counter)
                counter += 1

            except PCapException as e:
                print(e.__str__())

        return global_header_parser, frames