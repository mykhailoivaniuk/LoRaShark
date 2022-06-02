#!/usr/bin/env python3

# AVR / Arduino dynamic memory log analyis script.
#
# Copyright 2014 Matthijs Kooijman <matthijs@stdin.nl>
#
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
            255,          # max length of captured packets, in octets
            270,          # data link type (DLT) - 147
        ))
        self.out.flush()

    def write_packet(self, packet : PacketData):
        split_data = packet.data.split(" ")
        if split_data[-1] == "":
            split_data = split_data[:-1]
        data_len = len(split_data) + 15
        print(f'data: {packet.data}, dataLen: {data_len}, last char in string: {packet.data[-1]}...')
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
        self.out.write(struct.pack(">BBHIBBBBBBB",
                            0,     #lt_version
                            0,     # padding
                            16,    # lt_header size
                            packet.frequency,   # frequency
                            packet.bandwidth // 125,   # bandwidth
                            packet.sf,     #spreading factor
                            packet.rssi,    #rssi // change later with actual value
                            packet.rssi,    #max rssi // change later with actual value
                            packet.rssi,    # current_rssi // change later with actual value
                            packet.snr,     # signal to noise ratio // change later with actual value
                            0x34)) #sync word)
                            
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

def extract_params(dataStr: str):

    freq_start_idx = dataStr.find("freq")
    freq_end_idx   = dataStr[freq_start_idx:].find(',')
    freq           = int(float(dataStr[freq_start_idx + 6 : freq_end_idx + freq_start_idx]) * 1000000)
    
    sf_bw_idx = dataStr.find("datr")
    sf_bw     = re.findall(r'\d+', dataStr[sf_bw_idx + 7: sf_bw_idx + 16])
    
    bandwidth = int(sf_bw[1])
    sf = int(sf_bw[0])
    
    snr_start_idx = dataStr.find("lsnr")
    snr_end_idx   = dataStr[snr_start_idx:].find(",")
    snr           = int(dataStr[snr_start_idx + 6: snr_start_idx + snr_end_idx])
    
    rssi_idx = dataStr.find("rssi")
    rssi_idx_end = dataStr[rssi_idx:].find(',')
    rssi = int(re.findall(r'\d+', dataStr[rssi_idx: rssi_idx_end + rssi_idx])[0])
    print(f"freq: {freq} sf: {sf} bandwidth: {bandwidth} snr: {snr} rssi: {rssi}")
    return freq, sf, bandwidth, snr, rssi

def wrap_raw_data(hexData, rawPacketData):
    freq, sf, bandwidth, snr, rssi = extract_params(rawPacketData)
    return PacketData(freq, rssi, snr, bandwidth, hexData, sf)

def main():
    os.system("rm -r /tmp/sharkfin")
    
    pipe = "/tmp/sharkfin"
    os.system("wireshark -k -i /tmp/sharkfin &")
    out = PcapFormatter(open_fifo(pipe))

    # need to write argument parser for port
    port = serial.Serial("/dev/tty.usbserial-0001", baudrate=115200)
    out.write_header()
    dataLine = ""
    hexData = ""
    packetData = ""
    while True:
        currLine = str(port.readline())
        if "rxPkt:: CRC" in currLine:
            dataLine = str(port.readline())
            startIdx = dataLine.find(")")
            hexData = re.sub('[^a-zA-Z0-9 \n\.]', '', dataLine[startIdx + 3:].strip())
            hexData = hexData.replace("rn", "").strip()

        if not hexData: 
            continue
        
        while '[{"chan"' not in currLine and hexData != "":
            currLine = str(port.readline())

        rawPacketData = currLine
        print(f"Found hexData : {hexData} \nFound packetData = {rawPacketData}")
        cur_packet = wrap_raw_data(hexData, rawPacketData)
        out.write_packet(cur_packet)
            

        

            


if __name__ == '__main__':
    main()