function Invoke-RawCap {

<#

.SYNOPSIS

Packet sniffing function written in powershell, primarily written to support sniffing on localhost. Only supports PCAP as an output format
and IPv4 for the moment.

Author: Jessey Bullock (@ret2kw)
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Script creates a socket listening on the specified address and then sets the SIO_RCVALL control code[1] so that the socket captures all traffic.
It then manually builds the PCAP and writes it to the specified file. This code was heavily influenced by Get-Packet by rfoust[2].


[1] https://msdn.microsoft.com/en-us/library/windows/desktop/ee309610%28v=vs.85%29.aspx
[2] http://poshcode.org/764

.PARAMETER IPAddress

IP address that you want to capture packets from.

.PARAMETER Filename

The file to write the PCAP of captured packet data to.

.EXAMPLE



#>



[CmdletBinding()] 
Param (

    [Parameter( Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $IPAddress,
    
    [Parameter( Mandatory = $true )]
    [ValidateNotNullOrEmpty()]
    [String]
    $Filename
    
)


    # we are going to setup out global pcap header here

    # pcap magic_number
    [byte[]] $pcap_magic = 0xa1,0xb2,0xc3,0xd4
    [byte[]] $pcap_major = 0x00,0x02
    [byte[]] $pcap_minor = 0x00,0x04 
    [byte[]] $pcap_thiszone = 0x00,0x00,0x00,0x00
    [byte[]] $pcap_sigfigs = 0x00,0x00,0x00,0x00
    # snap length is 65535
    [byte[]] $pcap_snaplen = 0x00,0x00,0xff,0xff
    # we are setting this to RAW PACKETS
    [byte[]] $pcap_network = 0x00,0x00,0x00,0x65

    # pcap global header
    $pcap_global_header = $pcap_magic + $pcap_major + $pcap_minor + $pcap_thiszone + $pcap_sigfigs + $pcap_snaplen + $pcap_network

    # 'initialize' our new pcap with the global header
    set-content -value $pcap_global_header -encoding byte -path $Filename


    function pcap_hdr_t($time, $size, $data) {

        # convert our unix time to bytes and reverse to little endian
        $ts_sec = [BitConverter]::GetBytes($time)
        [Array]::Reverse($ts_sec)
        [byte[]] $ts_usec = 0x00,0x00,0x00,0x00
    
        # take our uint16 $size param and cast it to uint32 and convert to bytes, reversing for endianess
        $incl_len = [BitConverter]::GetBytes([int32]$size)
        [Array]::Reverse($incl_len)
    
        # add our fields together appending the data, incl_len is used twice as we aren't limiting snaplen
        $pcap_hdr = $ts_sec + $ts_usec + $incl_len + $incl_len + $data
        return $pcap_hdr
        
    #end of pcap_hdr_t function
    }


    function create_raw_s ($ip) {

        # vars needed for iocontrol call
        $byteout = new-object byte[] 4
        $bytein = new-object byte[] 4
        $bytein[0] = 1

        Try {
   
            # create a raw socket
            $s = new-object system.net.sockets.socket([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw, [Net.Sockets.ProtocolType]::IP)
            # set socket option saying we want to include the IP header
            $s.setsocketoption("IP","HeaderIncluded",$true)
            # creating a large buffer to prevent packet dropping
            $s.ReceiveBufferSize = 819200
        
            $ipendpoint = new-object system.net.ipendpoint([net.ipaddress]$ip, 0)
            $s.bind($ipendpoint)
            # call iocontrol to set the RVC_ALL to on
            [void]$s.iocontrol([net.sockets.iocontrolcode]::ReceiveAll, $bytein, $byteout)
        
        }
        Catch {
    
            [System.Exception]
            Write-Host "[*] Failed to setup socket, Probably not running as Administrator"
            Exit

        }

        return $s
        
    # end of create_raw_s function
    }

    # create our raw socket and set it up to capture all packets
    $raw_s = create_raw_s($IPAddress)

    # going to pull in 65535 bytes of data which is max for IP
    $data = new-object byte[] 65535
    # var to hold count of packets
    $pkt_n = 1

    while ($true) {

        if (-not $raw_s.Available) {
    
            start-sleep -milliseconds 500
            continue
        }


        # receive a packet
        $rcv = $raw_s.receive($data, 0, $data.length, [net.sockets.socketflags]::None)
        $time = [int][double]::Parse((Get-Date -UFormat %s))
    
        # weird dotnet shit for reading back data
        $MemoryStream = new-object System.IO.MemoryStream($data,0,$rcv)            
        $BinaryReader = new-object System.IO.BinaryReader($MemoryStream)

        # IP header length is a UInt16
        $full_len = new-object byte[] 2
        # seek 2 bytes so we are at the length field
        $BinaryReader.BaseStream.Position = 2
        # want to read in the total length of the IP packet
        $BinaryReader.Read($full_len, 0, 2) | Out-Null
 
        # convert it from network, so like ntohl
        [Array]::Reverse($full_len)
        $full_len = [BitConverter]::ToUInt16($full_len, 0)
    
        [Console]::Out.Write("`rCaptured {0:d} packets..." -f $pkt_n)
    
        # get just the packet data we need
        $pkt_data = new-object byte[] $full_len
    
        $BinaryReader.BaseStream.Position = 0
        $BinaryReader.Read($pkt_data, 0, $full_len) | Out-Null
    
        [byte[]] $pcap = pcap_hdr_t $time $full_len $pkt_data
        
        # write out the pcap entry for the packet
        add-content -value $pcap -encoding byte -path $Filename
	$pkt_n = $pkt_n + 1
    
    #end of while loop
    }

#end of invoke-rawcap function
}

