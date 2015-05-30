import xml.etree.ElementTree as et
import dateutil.parser
import traceback
import binascii
import argparse
import time
import sys
import os

from ctypes import *



# tags I am interested in
Event = '{http://schemas.microsoft.com/win/2004/08/events/event}Event'
System = '{http://schemas.microsoft.com/win/2004/08/events/event}System'
TimeCreated = '{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated'
EventData = '{http://schemas.microsoft.com/win/2004/08/events/event}EventData'
Data = '{http://schemas.microsoft.com/win/2004/08/events/event}Data'
RenderingInfo = '{http://schemas.microsoft.com/win/2004/08/events/event}RenderingInfo'
Keyword = '{http://schemas.microsoft.com/win/2004/08/events/event}Keyword' 
Execution = '{http://schemas.microsoft.com/win/2004/08/events/event}Execution'


data_xpath = "%s/%s[@Name='Fragment']" % (EventData, Data)
time_xpath = "%s/%s" % (System, TimeCreated)
exec_xpath = "%s/%s" % (System, Execution)

class pcap_hdr_s(Structure):

    _fields_ = [('magic_number', c_uint32),    # magic number
                ('version_major', c_uint16),   # major version number
                ('version_minor', c_uint16),   # minor version number
                ('thiszone', c_int32),         # GMT to local correction
                ('sigfigs', c_uint32),         # accuracy of timestamp
                ('snaplen', c_uint32),         # max length of captured packets, in octets
                ('network', c_uint32)]         # data link type


class pcaprec_hdr_s(Structure):

    _fields_ = [('ts_sec', c_uint32),          # timestamp seconds
                ('ts_usec', c_uint32),         # timestamp microseconds
                ('incl_len', c_uint32),        # number of octets of packet saved in file
                ('orig_len', c_uint32)]        # actual length of packet 


def add_pcap_hdr(systime, data):

    convert = dateutil.parser.parse(systime)
    systime = int(time.mktime(convert.timetuple()))

    r_hdr = pcaprec_hdr_s(systime, 0, len(data), len(data))

    return buffer(r_hdr)[:] + data


def get_packet_data(netxml):
    '''This generator loads and netsh trace xml doc, iterates over events and for each event that has a data fragment and system time element we iterate
        over the keywords telling us what order the packet is (packet start, nothing meaning middle, or packet end). Based on this we return processid
        system time and the raw packet data in binary.'''


    tree = et.parse(netxml)
    print('[*] Parsing trace file %s' % os.path.abspath(netxml))

    root = tree.getroot()

    # var here for packets that span Events
    gdata = False

    for ev in root.iter(Event):
        #print '[*] Iterating events'
        p_s = False
        p_e = False
 
        # xpath to get systemtime and data fragment
        systime = ev.findall(time_xpath)
        data = ev.findall(data_xpath)

        # if we don't have these elements keep looking
        if not systime or not data:
            continue

        data = data[0].text[2:]
        data = binascii.unhexlify(data)
        #print data
        systime = systime[0].attrib['SystemTime']
 
        for keyw in ev.iter(Keyword):
            #print '[*] Iterating keywords'
            if keyw.text == 'PacketStart':
                #print '[*] got a packetstart'
                p_s = True
            if keyw.text == 'PacketEnd':
                #print '[*] got a packetend'
                p_e = True
        
        # if there are keywords packetstart and packetend then we know this is all of the packet data
        if p_s and p_e:
            #print '[*] got a packet start and packet end'
            procid = ev.findall(exec_xpath)[0].attrib['ProcessID']
            # slice off '0x'
            yield {'ProcessID' : procid, 'SystemTime' : systime, 'Data' : data}

        # if this is a packet start but not a packet end append it to gdata and continue
        elif p_s and not p_e:
            #print '[*] got a packet start but no packet end'
            gdata = data
            #print gdata
            continue

        # if it isn't a start packet but is an end packet and already have some packet data then concat and yield
        elif not p_s and p_e and gdata:
            #print '[*] got a packet end but no packet start'
            gdata = gdata + data
            procid = ev.findall(exec_xpath)[0].attrib['ProcessID']
            yield {'ProcessID' : procid, 'SystemTime' : systime, 'Data' : gdata}
            gdata = False

        # if it doesn't have a start or end but we have some gdata append keep appending to gdata
        elif not p_s and not p_e and gdata:
            #print '[*] got a packet with no start or end'
            gdata = gdata + data
            continue

        else:
            print '[*] we shouldn\'t hit this block'
            print p_s,p_e,gdata,data,systime
            sys.exit(-1)
                





if __name__ == "__main__":

    print('\n')    
    parser = argparse.ArgumentParser(description='Script for converting netsh trace .etl files to pcap')
    
    parser.add_argument('--input', action='store', required=True, help='The netsh trace .etl file to process')
    parser.add_argument('--output', action='store', required=True, help='Name of the pcap file to be created')

    args = parser.parse_args()

    trace_file = args.input
    out_file = args.output

    try:
        #write our global header
        with open(out_file, 'wb+') as f_pcap:
            f_pcap.write(pcap_hdr_s(0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            #print('[*] Creating pcap file %s' % out_file)
    except:
        print(traceback.format_exc())

    pkt_n = 0

    # use our generator to pull pkt details
    for p_details in get_packet_data(trace_file):
        sys.stdout.write('\r[*] Processing packet no %d' % pkt_n)
        sys.stdout.flush()
        pkt = add_pcap_hdr(p_details['SystemTime'], p_details['Data'])
        pkt_n += 1
        # now we write out our file
        with open(out_file, 'ab') as f_pcap:
            f_pcap.write(pkt)

    print('\n') 
    print('[*] Done processing, pcap written to %s' % os.path.abspath(out_file))
    print('\n')



