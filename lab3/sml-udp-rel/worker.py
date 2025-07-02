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
from lib.comm import unreliable_send, unreliable_receive
import socket
import struct
import time
import random
import os

NUM_ITER   = 1     # TODO: Make sure your program can handle larger values
CHUNK_SIZE = 4     # Number of 32-bit values per chunk

# Network configuration
SWITCHML_PORT = 9999      # UDP port for SwitchML protocol
TIMEOUT = 1.0             # Timeout for retransmission in seconds
MAX_RETRIES = 10          # Maximum number of retransmission attempts

def get_worker_mac(rank):
    """Get MAC address for worker"""
    return f"00:00:00:00:01:{rank+1:02x}"

def get_worker_ip(rank):
    """Get IP address for worker"""
    return f"10.0.0.{rank+1}"

def ip_to_int(ip_str):
    """Convert IP string to 32-bit integer"""
    parts = ip_str.split('.')
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])

def mac_to_bytes(mac_str):
    """Convert MAC string to 6 bytes"""
    return bytes.fromhex(mac_str.replace(':', ''))

def calculate_checksum(data):
    """Calculate IP checksum"""
    if len(data) % 2 == 1:
        data += b'\x00'

    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    return (~checksum) & 0xFFFF

def pack_switchml_packet(worker_id, chunk_id, num_workers, flags, values):
    """
    Pack SwitchML data into bytes for UDP transmission
    Format: worker_id(1) + chunk_id(1) + num_workers(1) + flags(1) + value0(4) + value1(4) + value2(4) + value3(4)
    """
    # Ensure we have exactly 4 values, pad with zeros if necessary
    padded_values = values + [0] * (4 - len(values))
    padded_values = padded_values[:4]  # Truncate if more than 4

    # Pack using network byte order (big-endian)
    packet = struct.pack('!BBBBLLLL',
                        worker_id, chunk_id, num_workers, flags,
                        padded_values[0], padded_values[1],
                        padded_values[2], padded_values[3])
    return packet

def unpack_switchml_packet(data):
    """
    Unpack SwitchML packet from bytes
    Returns: (worker_id, chunk_id, num_workers, flags, [value0, value1, value2, value3])
    """
    if len(data) < 20:  # 4 bytes header + 4*4 bytes values
        return None

    # Unpack using network byte order (big-endian)
    unpacked = struct.unpack('!BBBBLLLL', data[:20])
    worker_id, chunk_id, num_workers, flags = unpacked[:4]
    values = list(unpacked[4:])

    return (worker_id, chunk_id, num_workers, flags, values)

def create_raw_udp_packet(src_ip, dst_ip, src_port, dst_port, payload, src_mac, dst_mac):
    """Create a complete Ethernet/IP/UDP packet"""

    # Ethernet header (14 bytes)
    eth_header = struct.pack('!6s6sH',
                            mac_to_bytes(dst_mac),    # Destination MAC
                            mac_to_bytes(src_mac),    # Source MAC
                            0x0800)                   # EtherType (IPv4)

    # IP header (20 bytes)
    version_ihl = 0x45  # Version 4, Header Length 5 (20 bytes)
    tos = 0
    total_length = 20 + 8 + len(payload)  # IP header + UDP header + payload
    identification = random.randint(0, 65535)
    flags_fragment = 0x4000  # Don't fragment
    ttl = 64
    protocol = 17  # UDP
    checksum = 0  # Will calculate later
    src_ip_int = ip_to_int(src_ip)
    dst_ip_int = ip_to_int(dst_ip)

    # Pack IP header without checksum
    ip_header_no_checksum = struct.pack('!BBHHHBBHLL',
                                       version_ihl, tos, total_length,
                                       identification, flags_fragment,
                                       ttl, protocol, 0,
                                       src_ip_int, dst_ip_int)

    # Calculate and insert checksum
    ip_checksum = calculate_checksum(ip_header_no_checksum)
    ip_header = struct.pack('!BBHHHBBHLL',
                           version_ihl, tos, total_length,
                           identification, flags_fragment,
                           ttl, protocol, ip_checksum,
                           src_ip_int, dst_ip_int)

    # UDP header (8 bytes)
    udp_length = 8 + len(payload)
    udp_checksum = 0  # Optional for IPv4, we'll set to 0
    udp_header = struct.pack('!HHHH',
                            src_port, dst_port,
                            udp_length, udp_checksum)

    # Complete packet
    packet = eth_header + ip_header + udp_header + payload
    return packet

def AllReduce(rank, data, result):
    """
    Perform in-network all-reduce over UDP using raw sockets with reliability

    :param int   rank: the worker's rank
    :param [int] data: the input vector for this worker
    :param [int] result: the output vector

    This function is blocking, i.e. only returns with a result or error
    """
    Log(f"Worker {rank}: Starting AllReduce on {len(data)} elements")

    # Get network information
    src_mac = get_worker_mac(rank)
    src_ip = get_worker_ip(rank)
    # Try unicast to switch first to debug
    dst_mac = "00:00:00:00:01:00"  # Switch MAC
    dst_ip = "10.0.0.100"           # Switch IP
    # dst_mac = "ff:ff:ff:ff:ff:ff"  # Broadcast MAC
    # dst_ip = "255.255.255.255"     # Broadcast IP
    src_port = 10000 + rank
    dst_port = SWITCHML_PORT

    Log(f"Worker {rank}: Using {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    Log(f"Worker {rank}: MAC {src_mac} -> {dst_mac}")

    # Determine interface name - in Mininet it's just eth0 inside each host
    interface = "eth0"

    # Create raw socket for sending
    try:
        send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        send_sock.bind((interface, 0))
        Log(f"Worker {rank}: Created raw send socket on {interface}")
    except Exception as e:
        Log(f"Worker {rank}: ERROR - Could not create raw socket: {e}")
        Log(f"Worker {rank}: Make sure interface {interface} exists")
        return False

    # Create UDP socket for receiving
    try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        recv_sock.bind(('', src_port))  # Bind to any address on our port
        # Set non-blocking for use with unreliable_receive
        recv_sock.setblocking(False)
        Log(f"Worker {rank}: Created UDP receive socket on port {src_port}")
    except Exception as e:
        Log(f"Worker {rank}: ERROR - Could not create receive socket: {e}")
        send_sock.close()
        return False

    try:
        num_workers = 3  # This should match NUM_WORKERS in network.py
        result_idx = 0

        # Add initial delay to let all workers start
        time.sleep(0.5)  # Give all workers time to start

        # Process data in chunks
        for chunk_start in range(0, len(data), CHUNK_SIZE):
            chunk_id = chunk_start // CHUNK_SIZE
            chunk_data = data[chunk_start:chunk_start + CHUNK_SIZE]

            # Pad chunk to exactly CHUNK_SIZE elements
            while len(chunk_data) < CHUNK_SIZE:
                chunk_data.append(0)

            Log(f"Worker {rank}: Processing chunk {chunk_id} with values {chunk_data[:len(data[chunk_start:chunk_start + CHUNK_SIZE])]}")

            # Try to send and receive with retransmission
            retry_count = 0
            success = False

            while retry_count < MAX_RETRIES and not success:
                # Create SwitchML payload
                switchml_payload = pack_switchml_packet(
                    worker_id=rank,
                    chunk_id=chunk_id,
                    num_workers=num_workers,
                    flags=0,  # Data packet
                    values=chunk_data
                )

                # Create raw packet
                raw_packet = create_raw_udp_packet(
                    src_ip, dst_ip, src_port, dst_port,
                    switchml_payload, src_mac, dst_mac
                )

                # Send packet using unreliable_send
                Log(f"Worker {rank}: Sending chunk {chunk_id} (attempt {retry_count + 1})")
                try:
                    # Send packet directly for now
                    bytes_sent = send_sock.send(raw_packet)
                    Log(f"Worker {rank}: Sent chunk {chunk_id} (attempt {retry_count + 1}, {bytes_sent} bytes)")
                except Exception as e:
                    Log(f"Worker {rank}: ERROR - Failed to send packet: {e}")
                    retry_count += 1
                    continue

                # Wait for response with timeout
                start_time = time.time()

                while time.time() - start_time < TIMEOUT:
                    try:
                        # Try to receive response
                        response_data, addr = recv_sock.recvfrom(1024)

                        Log(f"Worker {rank}: Received response from {addr}")

                        # Unpack response
                        response = unpack_switchml_packet(response_data)
                        if response is None:
                            Log(f"Worker {rank}: ERROR - Invalid response packet")
                            continue

                        resp_worker_id, resp_chunk_id, resp_num_workers, resp_flags, chunk_result = response

                        # Verify this is the response we're expecting
                        if resp_chunk_id == chunk_id and resp_flags == 1:
                            Log(f"Worker {rank}: Received valid response for chunk {chunk_id}: {chunk_result}")

                            # Copy result values to output
                            remaining_elements = len(data) - chunk_start
                            elements_to_copy = min(CHUNK_SIZE, remaining_elements)

                            for i in range(elements_to_copy):
                                if result_idx < len(result):
                                    result[result_idx] = chunk_result[i]
                                    result_idx += 1

                            success = True
                            break
                        else:
                            Log(f"Worker {rank}: Ignoring response: chunk_id={resp_chunk_id}, flags={resp_flags}")

                    except socket.error:
                        # No data available, continue waiting
                        time.sleep(0.01)
                    except Exception as e:
                        Log(f"Worker {rank}: ERROR - Exception receiving response: {e}")
                        break

                if not success:
                    retry_count += 1
                    if retry_count < MAX_RETRIES:
                        Log(f"Worker {rank}: Timeout for chunk {chunk_id}, retrying...")
                    else:
                        Log(f"Worker {rank}: ERROR - Max retries reached for chunk {chunk_id}")
                        return False

            # Add small delay between chunks
            time.sleep(0.05)

        Log(f"Worker {rank}: AllReduce completed successfully")
        return True

    finally:
        send_sock.close()
        recv_sock.close()

def main():
    rank = GetRankOrExit()
    Log("Started...")
    for i in range(NUM_ITER):
        num_elem = GenMultipleOfInRange(2, 32, 2 * CHUNK_SIZE) # Start with smaller vectors for testing
        data_out = GenInts(num_elem)  # Generate random integers
        data_in = [0] * num_elem  # Initialize result vector
        CreateTestData("udp-iter-%d" % i, rank, data_out)
        success = AllReduce(rank, data_out, data_in)
        if success:
            RunIntTest("udp-iter-%d" % i, rank, data_in, True)
        else:
            Log("AllReduce failed!")
    Log("Done")

if __name__ == '__main__':
    main()
