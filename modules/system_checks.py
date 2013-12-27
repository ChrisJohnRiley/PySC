# !/usr/bin/python
# -*- coding: utf-8 -*-

#

"""
	PySc System Checks
	This module contains the logic for the following checks .:
	
	- check_platform --> Checks for Windows system
	- check_network --> Checks network connectivity
"""

from sys import exit, maxsize
import platform
from ctypes import *
from ctypes.wintypes import DWORD

wininet = windll.wininet

def check_platform(debug):

    # check target is 'winXX'

    if not platform.system().lower() == 'windows':
        if debug:
            print '\n [!] Not a Windows system!, exiting'
        exit(1)
    else:
        if debug:
            print '\n [>] Windows detected - %s' \
                % platform.system(), platform.version(), platform.architecture()[0]

        # check 32bit / 64bit
        is_64bits = maxsize > 2**32

        if is_64bits and debug:
            print ' [!] Injection into 64bit processes is not currently supported'

def check_network(debug):

    # check network connection

    flags = DWORD()
    if debug:
        print '\n [>] Checking connection'

    connected = wininet.InternetGetConnectedState(
                byref(flags),
                None,
                )

    if not connected:
        if debug:
            print ' [!] No internet connection, cannot retrieve data'
        exit(1)
    else:
        if debug:
            print ' [>] Connection check confirmed\n'