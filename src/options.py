# coding: utf8

import sys
import optparse

import settings
__author__ = 'Anton Dzyk'

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
parser.add_option(
    '--bpf', action='store', help=u'Berkeley Packet Filter'
)


def get():

    (opt, args) = parser.parse_args()

    if not opt.port or not opt.interface:
        print('Not set port or interface')
        parser.print_help()
        sys.exit(1)
    else:
        settings.INTERFACE = opt.interface

    if not opt.protocol:
        print('Not set protocol')
        parser.print_help()
        sys.exit(1)

    if opt.bpf:
        settings.BPF = opt.bpf
    else:
        settings.BPF = "tcp port {0} and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)".format(opt.port)

    print('interface: {0}'.format(settings.INTERFACE))
    print('BPF: {0}'.format(settings.BPF))

    return opt
