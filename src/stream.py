# coding: utf8

import struct

import pcap

import settings

__author__ = 'Anton Dzyk'


def stream():

    st = pcap.pcap(name=settings.INTERFACE)
    st.setfilter(settings.BPF)

    return st


def tcp_data_stream():
    for tt, pkt in stream():
        eth_header_len = 14
        ip_l = (struct.unpack('B', pkt[14])[0] & 15) * 4
        tcp_l = ((struct.unpack('B', pkt[14 + ip_l + 12])[0] & 240) >> 4) * 4
        header_len = eth_header_len + ip_l + tcp_l
        yield struct.unpack('!L', pkt[ip_l + 8:ip_l + 12])[0], pkt[header_len:]


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
