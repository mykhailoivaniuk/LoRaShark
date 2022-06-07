#!/usr/bin/env python3

# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# This script is intended to read raw packets (currently only 802.15.4
# packets prefixed by a length byte) from a serial port and output them
# in pcap format.

import os
import sys
import time
import errno
import serial
import struct
import select
import binascii
import datetime
import argparse
import re
from dataclasses import dataclass

@dataclass
class PacketData:
    frequency: int = 0
    rssi : int = 0
    snr  : int = 0
    bandwidth : int = 0
    data : str = ""
    sf : int = 0
    sw : int = 0x34

class Formatter:
    def __init__(self, out):
        self.out = out

    def fileno(self):
        return self.out.fileno()

    def close(self):
        self.out.close()

class PcapFormatter(Formatter):
    def write_header(self):
        self.out.write(struct.pack("=IHHiIII",
            0xa1b2c3d4,   # magic number
            2,            # major version number
            4,            # minor version number
            0,            # GMT to local correction
            0,            # accuracy of timestamps
            256,          # max length of captured packets, in octets
            270,          # data link type (DLT) - 270 for LoRaTap
        ))
        self.out.flush()

    def write_packet(self, packet : PacketData):
        split_data = packet.data.split(" ")
        if split_data[-1] == "":
            split_data = split_data[:-1]
        data_len = len(split_data) + 15
        # print(f'data: {packet.data}, dataLen: {data_len}, last char in string: {packet.data[-1]}...')
        data_no_spaces = packet.data.replace(" ", '')
        data_bytes = bytes.fromhex(data_no_spaces)
        now = datetime.datetime.now()
        timestamp = int(time.mktime(now.timetuple()))
        self.out.write(struct.pack("=IIII",
            timestamp,        # timestamp seconds
            now.microsecond,  # timestamp microseconds
            data_len,        # number of octets of packet saved in file
            data_len,        # actual length of packet
        ))
        # print(packet.bandwidth // 125000)
        # print(packet.sf)
        self.out.write(struct.pack(">BBHIBBBBBBB",
                            0,     #lt_version
                            0,     # padding
                            16,    # lt_header size
                            packet.frequency,   # frequency
                            packet.bandwidth // 125000,   # bandwidth
                            packet.sf,     #spreading factor
                            packet.rssi,    #rssi // change later with actual value
                            packet.rssi,    #max rssi // change later with actual value
                            packet.rssi,    # current_rssi // change later with actual value
                            packet.snr,     # signal to noise ratio // change later with actual value
                            packet.sw)) #sync word)
                            
        self.out.write(data_bytes)
        self.out.flush()

def open_fifo(name):
    try:
        os.mkfifo(name);
    except FileExistsError:
        pass
    except:
        raise

    # This blocks until the other side of the fifo is opened
    return open(name, 'wb')

def extract_params(hexData, rssiLine, snrLine, bwLine, fLine, sfLine, swLine):
    hexData = re.search("'(.*)'", hexData).group(1).strip()

    snr  = int(re.sub(r'[^0-9]', '', snrLine.split('.')[0]))
    
    neg = 1
    if '-' in rssiLine:
        neg = -1
    
    rssi = neg * int(re.sub(r'[^0-9]', '', rssiLine)) + 139
    if snr < 0:
        rssi *= 4
    bw   = int(re.sub(r'[^0-9]', '', bwLine)) 
    freq = int(re.sub(r'[^0-9]', '', fLine))
    sf   = int(float(re.sub(r'[^0-9]', '', sfLine)))
    sw   = int(re.sub(r'[^0-9]', '', swLine))
    # print("hex data", hexData)
    # print("rssi", rssi)
    # print("snr", snr)
    # print("freq", freq)
    # print("bw", bw)
    # print("sf", sf)
    return hexData, rssi, snr, bw, freq, sf, sw

def wrap_raw_data(hexData, rssiLine, snrLine, bwLine, fLine, sfLine, swLine):
    hexData, rssi, snr, bw, freq, sf, sw = extract_params(hexData, 
                                                          rssiLine, 
                                                          snrLine, 
                                                          bwLine, 
                                                          fLine, 
                                                          sfLine, 
                                                          swLine)
    return PacketData(freq, rssi, snr, bw, hexData, sf, sw)

def main():
    os.system("rm -r /tmp/sharkfin")
    
    pipe = "/tmp/sharkfin"
    os.system("wireshark -k -i /tmp/sharkfin &")
    out = PcapFormatter(open_fifo(pipe))

    # change to correct port
    port = serial.Serial("/dev/tty.usbserial-0001", baudrate=115200)
    out.write_header()
    # dataLine = ""
    # hexData = ""
    
    while True:
        currLine = str(port.readline())
        if "Received packet" in currLine:
            hexData = currLine
            rssiLine = str(port.readline())
            snrLine  = str(port.readline())
            bwLine   = str(port.readline())
            fLine    = str(port.readline())
            sfLine   = str(port.readline())
            swLine       = str(port.readline())
            
            cur_packet = wrap_raw_data(hexData, 
                                       rssiLine, 
                                       snrLine, 
                                       bwLine, 
                                       fLine, 
                                       sfLine, 
                                       swLine)
            out.write_packet(cur_packet)
        

            


if __name__ == '__main__':
    main()