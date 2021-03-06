__author__ = 'max'


DEBUG = True


LE = 0
BE = 1
BYTE_ORDER = {
    LE: 'little',
    BE: 'big'
}

HTTP_PORTS = [80, 3371, 3372]
SMTP_PORTS = [25, 587, 465]
POP3_PORTS = [110]


FTP_HEADER_LENGTH = 32
FTP_TRANSFER_COMPLETE = '226'
FTP_TRANSFER_START = '150'

SRC_PATH = "/home/max/workspace/git/traffic_parser/samples/"
# must be absolute path
SAVE_PATH = '/home/max/traffic_parser/result/'