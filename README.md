PySC
====

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

Optional:

--> Includes server-side code for Metasploit and Python SCAPY for delivery of shellcode YMMV
