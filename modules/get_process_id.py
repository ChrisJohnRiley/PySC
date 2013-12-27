# !/usr/bin/python
# -*- coding: utf-8 -*-
#
# Based on http://code.activestate.com/recipes/576362/ 
# License: MIT

#

"""
	PySc Get Process ID
	This module contains the logic for the following checks .:
	
	- get_procid --> Retrieves process ID matching processname provided
"""

from ctypes import c_long , c_int , c_uint , c_char , c_ubyte , c_char_p , c_void_p
from ctypes import windll
from ctypes import Structure
from ctypes import sizeof , POINTER , pointer , cast

# const variable
TH32CS_SNAPPROCESS = 2
STANDARD_RIGHTS_REQUIRED = 0x000F0000
SYNCHRONIZE = 0x00100000
PROCESS_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF)
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPTHREAD = 0x00000004

# struct 
class PROCESSENTRY32(Structure):
    _fields_ = [ ( 'dwSize' , c_uint ) , 
                 ( 'cntUsage' , c_uint) ,
                 ( 'th32ProcessID' , c_uint) ,
                 ( 'th32DefaultHeapID' , c_uint) ,
                 ( 'th32ModuleID' , c_uint) ,
                 ( 'cntThreads' , c_uint) ,
                 ( 'th32ParentProcessID' , c_uint) ,
                 ( 'pcPriClassBase' , c_long) ,
                 ( 'dwFlags' , c_uint) ,
                 ( 'szExeFile' , c_char * 260 ) , 
                 ( 'th32MemoryBase' , c_long) ,
                 ( 'th32AccessKey' , c_long ) ]


class MODULEENTRY32(Structure):
    _fields_ = [ ( 'dwSize' , c_long ) , 
                ( 'th32ModuleID' , c_long ),
                ( 'th32ProcessID' , c_long ),
                ( 'GlblcntUsage' , c_long ),
                ( 'ProccntUsage' , c_long ) ,
                ( 'modBaseAddr' , c_long ) ,
                ( 'modBaseSize' , c_long ) , 
                ( 'hModule' , c_void_p ) ,
                ( 'szModule' , c_char * 256 ),
                ( 'szExePath' , c_char * 260 ) ]

class THREADENTRY32(Structure):
    _fields_ = [
        ('dwSize' , c_long ),
        ('cntUsage' , c_long),
        ('th32ThreadID' , c_long),
        ('th32OwnerProcessID' , c_long),
        ('tpBasePri' , c_long),
        ('tpDeltaPri' , c_long),
        ('dwFlags' , c_long) ]

def get_procid(processname):
    hProcessSnap = c_void_p(0)
    hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS , 0 )

    pe32 = PROCESSENTRY32()
    pe32.dwSize = sizeof( PROCESSENTRY32 )
    ret = Process32First( hProcessSnap , pointer( pe32 ) )

    while ret :
        # loop through and find matching processname
        if pe32.szExeFile.lower() == processname.lower():
            return pe32.th32ProcessID
            break
        # not found, try next
        ret = Process32Next( hProcessSnap, pointer(pe32) )        

# forigen function
## CreateToolhelp32Snapshot
CreateToolhelp32Snapshot= windll.kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.reltype = c_long
CreateToolhelp32Snapshot.argtypes = [ c_int , c_int ]
## Process32First
Process32First = windll.kernel32.Process32First
Process32First.argtypes = [ c_void_p , POINTER( PROCESSENTRY32 ) ]
Process32First.rettype = c_int
## Process32Next
Process32Next = windll.kernel32.Process32Next
Process32Next.argtypes = [ c_void_p , POINTER(PROCESSENTRY32) ]
Process32Next.rettype = c_int