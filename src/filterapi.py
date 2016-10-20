#!/usr/bin/env python
# coding: utf8

import re
import time
from multiprocessing import Process

import stream
import options
import settings
__author__ = 'Anton Dzyk'


opt = options.get()
PORT = int(opt.port)
FILTER = re.compile(r'%s' % opt.filter)
INTERFACE = opt.interface
XML_TAG = re.compile(r'%s' % opt.xml_tag)
JSON_FILTER = opt.json_filter


def xml_filter():
    for pkt in stream.protocol_stream(INTERFACE, PORT, PORT):
        ret = XML_TAG.search(pkt)
        if ret:
            tag = ret.groups()[0]
            if FILTER.search(tag):
                start_body = settings.XML_START_BODY.search(pkt)
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

            txt += '%s%s\n' % (settings.TAB * tab_index, line)

            if re.search(r'[^\\|^?]>$', line):
                tab_index += 1
            if re.search(r'</', line):
                tab_index -= 1
            if re.search(r'/>$', line):
                tab_index -= 1

        yield txt


def json_split():
    for pkt in stream.protocol_stream():
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
    for pkt in stream.protocol_stream():
        print '-->', pkt, '<---'
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


if opt.protocol.lower() == 'soap':
    func = pretty_xml
elif opt.protocol.lower() == 'json':
    func = pretty_json
    import json
else:
    print('bad protocol')
    exit(1)


def pr():
    for pkt in func():
        print(pkt)

filterapi = Process(
    target=pr,
    args=()
)
filterapi.start()

try:
    while True:
        time.sleep(1)

except KeyboardInterrupt:
    filterapi.terminate()
    print('\npress Ctrl+C')
