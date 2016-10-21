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
        yield pkt[header_len:]
