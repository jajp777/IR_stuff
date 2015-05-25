# heavily influenced by http://poshcode.org/764



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
set-content -value $pcap_global_header -encoding byte -path test.pcap


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

}

# hardcoding localhost for now
$raw_s = create_raw_s("127.0.0.1")

# going to pull in 65535 bytes of data which is max for IP
$data = new-object byte[] 65535

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

    $full_len = new-object byte[] 2
    # seek 2 bytes so we are at the length field
    $BinaryReader.BaseStream.Position = 2
    # want to read in the total length of the IP packet
    $BinaryReader.Read($full_len, 0, 2) | Out-Null
 
    # convert it from network, so like ntohl
    [Array]::Reverse($full_len)
    $full_len = [BitConverter]::ToUInt16($full_len, 0)
    
    Write-Host $full_len
    
    # get just the packet data we need
    $pkt_data = new-object byte[] $full_len
    
    $BinaryReader.BaseStream.Position = 0
    $BinaryReader.Read($pkt_data, 0, $full_len) | Out-Null
    
    [byte[]] $pcap = pcap_hdr_t $time $full_len $pkt_data
        
    add-content -value $pcap -encoding byte -path test.pcap
    
    
}




