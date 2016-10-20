# coding: utf8

import re
__author__ = 'Anton Dzyk'

INTERFACE = 'eth0'

# JSON
JSON_SPLIT = re.compile(r'\s')

# XML
XML_START_BODY = re.compile(r'(<\?xml version=)')
TAB = '  '
