"""
 Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

from lib.gen import GenInts, GenMultipleOfInRange
from lib.test import CreateTestData, RunIntTest
from lib.worker import *
from scapy.all import *
import random
import time

NUM_ITER   = 1     # TODO: Make sure your program can handle larger values
CHUNK_SIZE = 4     # Number of 32-bit values per chunk

# Constants
TYPE_SWITCHML = 0x1234  # Custom EtherType for SwitchML

class SwitchML(Packet):
    name = "SwitchMLPacket"
    fields_desc = [
        ByteField("worker_id", 0),      # Worker rank
        ByteField("chunk_id", 0),       # Chunk identifier within vector
        ByteField("num_workers", 0),    # Total number of workers
        ByteField("flags", 0),          # Control flags (0=data, 1=result)
        IntField("value0", 0),          # First value in chunk
        IntField("value1", 0),          # Second value in chunk
        IntField("value2", 0),          # Third value in chunk
        IntField("value3", 0)           # Fourth value in chunk
    ]

# Bind the custom header to Ethernet
bind_layers(Ether, SwitchML, type=TYPE_SWITCHML)

def AllReduce(iface, rank, data, result):
    """
    Perform in-network all-reduce over ethernet

    :param str  iface: the ethernet interface used for all-reduce
    :param int   rank: the worker's rank
    :param [int] data: the input vector for this worker
    :param [int] result: the output vector

    This function is blocking, i.e. only returns with a result or error
    """
    Log(f"Worker {rank}: Starting AllReduce on {len(data)} elements")

    # Get network information
    my_mac = get_if_hwaddr(iface)
    switch_mac = "ff:ff:ff:ff:ff:ff"  # Use broadcast MAC for now
    num_workers = 3  # This should match NUM_WORKERS in network.py

    # Process data in chunks
    result_idx = 0
    for chunk_start in range(0, len(data), CHUNK_SIZE):
        chunk_id = chunk_start // CHUNK_SIZE
        chunk_data = data[chunk_start:chunk_start + CHUNK_SIZE]

        # Pad chunk to exactly CHUNK_SIZE elements
        while len(chunk_data) < CHUNK_SIZE:
            chunk_data.append(0)

        Log(f"Worker {rank}: Sending chunk {chunk_id} with values {chunk_data[:len(data[chunk_start:chunk_start + CHUNK_SIZE])]}")
        Log(f"Worker {rank}: Using src_mac={my_mac}, dst_mac={switch_mac}, ethertype=0x{TYPE_SWITCHML:04x}")

        # Create and send SwitchML packet
        pkt = Ether(dst=switch_mac, src=my_mac, type=TYPE_SWITCHML) / \
              SwitchML(
                  worker_id=rank,
                  chunk_id=chunk_id,
                  num_workers=num_workers,
                  flags=0,  # Data packet
                  value0=chunk_data[0],
                  value1=chunk_data[1],
                  value2=chunk_data[2],
                  value3=chunk_data[3]
              )

        # Debug: Show the actual packet bytes
        Log(f"Worker {rank}: Packet summary: {pkt.summary()}")
        Log(f"Worker {rank}: Packet length: {len(pkt)} bytes")
        Log(f"Worker {rank}: EtherType in packet: 0x{pkt[Ether].type:04x}")

        sendp(pkt, iface=iface, verbose=False)
        Log(f"Worker {rank}: Packet sent")

        # Add small random delay to avoid packet collisions
        time.sleep(random.uniform(0.001, 0.005))

        # Wait for aggregation result
        def packet_filter(pkt):
            if pkt.haslayer(SwitchML):
                Log(f"Worker {rank}: Received SwitchML packet - chunk_id={pkt[SwitchML].chunk_id}, flags={pkt[SwitchML].flags}, expected_chunk={chunk_id}")
                return (pkt[SwitchML].chunk_id == chunk_id and pkt[SwitchML].flags == 1)
            return False

        Log(f"Worker {rank}: Waiting for response to chunk {chunk_id}")

        # Sniff for response packet with timeout
        pkts = sniff(iface=iface, lfilter=packet_filter, count=1, timeout=10)

        if pkts:
            response_pkt = pkts[0]
            chunk_result = [
                response_pkt[SwitchML].value0,
                response_pkt[SwitchML].value1,
                response_pkt[SwitchML].value2,
                response_pkt[SwitchML].value3
            ]

            Log(f"Worker {rank}: Received response for chunk {chunk_id}: {chunk_result}")

            # Copy result values to output (only up to remaining elements)
            remaining_elements = len(data) - chunk_start
            elements_to_copy = min(CHUNK_SIZE, remaining_elements)

            for i in range(elements_to_copy):
                if result_idx < len(result):
                    result[result_idx] = chunk_result[i]
                    result_idx += 1
        else:
            Log(f"Worker {rank}: ERROR - Timeout waiting for chunk {chunk_id}")
            return False

    Log(f"Worker {rank}: AllReduce completed successfully")
    return True

def main():
    iface = 'eth0'
    rank = GetRankOrExit()
    Log("Started...")
    for i in range(NUM_ITER):
        num_elem = GenMultipleOfInRange(2, 32, 2 * CHUNK_SIZE) # Start with smaller vectors for testing
        data_out = GenInts(num_elem)  # Generate random integers
        data_in = [0] * num_elem  # Initialize result vector
        CreateTestData("eth-iter-%d" % i, rank, data_out)
        success = AllReduce(iface, rank, data_out, data_in)
        if success:
            RunIntTest("eth-iter-%d" % i, rank, data_in, True)
        else:
            Log("AllReduce failed!")
    Log("Done")

if __name__ == '__main__':
    main()
