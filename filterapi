#!/usr/bin/env python
# coding: utf8

import re
import pcap
import struct
import optparse

parser = optparse.OptionParser(usage='usage: %prog [options]\n\t')

parser.add_option(
    '-p', '--port', action='store', help=u'port filter'
    )
parser.add_option(
    '-f', '--filter', action='store', help=u'name SOAP/JSON function'
    )
parser.add_option(
    '-i', '--interface', action='store', help=u'interface name'
    )
parser.add_option(
    '-x', '--protocol', action='store',
    help=u'type protocol SOAP/JSON'
    )

parser.add_option(
    '--xml-tag', action='store', help=u'xml template',
    default="<[a-zA-Z0-9-]*:*Body>\s*<[a-zA-Z0-9]*:*([^(>|/)]+)"
    )
parser.add_option(
    '--json-filter', action='store', help=u'dict filter',
    default="method"
)

(opt, args) = parser.parse_args()

if not opt.port or not opt.interface:
    parser.print_help()
    exit(1)

PORT = int(opt.port)
FILTER = re.compile(r'%s' % opt.filter)
INTERFACE = opt.interface
ETH_TYPE = 2048  # tcp
XML_TAG = re.compile(r'%s' % opt.xml_tag)
JSON_FILTER = opt.json_filter
JSON_SPLIT = re.compile(r'\s')

XML_START_BODY = re.compile(r'(<\?xml version=)')
TAB = '  '


def eth_stream():
    for ts, pkt in pcap.pcap(name=INTERFACE):
        if len(pkt) > 14:
            (src, dst, eth_type) = struct.unpack_from('!6s6sH', pkt)
            if eth_type == ETH_TYPE:
                yield pkt[14:]


def ip_stream():
    for pkt in eth_stream():
        header_len = (struct.unpack('B', pkt[0])[0] & 15) * 4
        yield pkt[header_len:]


def tcp_data_stream():
    for pkt in ip_stream():
        (src_port, dst_port, seq, ack, bits) = \
            struct.unpack_from('!HHLLB', pkt)
        header_len = ((bits & 240) >> 4) * 4
        if (src_port == PORT or dst_port == PORT) and len(pkt) > header_len:
            yield ack, pkt[header_len:]


def protocol_stream():
    old_ack = 0
    old_data = ''
    for ack, data in tcp_data_stream():
        if old_ack == ack:
            old_data += data
        else:
            old_ack = ack
            if len(old_data) > 0:
                yield old_data
            old_data = data


def xml_filter():
    for pkt in protocol_stream():
        ret = XML_TAG.search(pkt)
        if ret:
            tag = ret.groups()[0]
            if FILTER.search(tag):
                start_body = XML_START_BODY.search(pkt)
                if start_body:
                    start = start_body.start(0)
                    yield pkt[start:]
                else:
                    print('error extract body')


def pretty_xml():
    for pkt in xml_filter():
        tab_index = 0
        txt = ''
        xml = re.sub('><', '>\n<', pkt)
        for line in xml.split('\n'):

            if re.search(r'^</', line):
                tab_index -= 1

            txt += '%s%s\n' % (TAB * tab_index, line)

            if re.search(r'[^\\|^?]>$', line):
                tab_index += 1
            if re.search(r'</', line):
                tab_index -= 1
            if re.search(r'/>$', line):
                tab_index -= 1

        yield txt


def json_split():
    for pkt in protocol_stream():
        start = 0
        stop = 0
        str_ = ''
        for symbol in pkt:
            str_ += symbol
            if symbol == '{':
                start += 1
            if symbol == '}':
                stop += 1
            if start != 0 and start == stop:
                yield str_
                start = 0
                stop = 0
                str_ = ''


def pretty_json():
    current_id = []
    for pkt in json_split():
        dict_ = json.loads(pkt)
        id_ = dict_['id']
        if JSON_FILTER in dict_.keys():
            if dict_[opt.json_filter] == opt.filter:
                current_id.append(id_)
                yield json.dumps(
                    dict_, sort_keys=True, indent=2,
                    separators=(',', ': ')
                    )
        else:
            if id_ in current_id:
                current_id.remove(id_)
                yield json.dumps(
                    dict_, sort_keys=True, indent=2,
                    separators=(',', ': ')
                    )


try:
    if opt.protocol.lower() == 'soap':
        func = pretty_xml
    elif opt.protocol.lower() == 'json':
        func = pretty_json
        import json
    else:
        print('bad protocol')
        exit(1)

    for pkt in func():
        print(pkt)

except KeyboardInterrupt:
    print('\npress Ctrl+C')
