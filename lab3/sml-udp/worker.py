"""
 Debug version that processes only one chunk to isolate the aggregation issue
 """

from lib.gen import GenInts, GenMultipleOfInRange
from lib.test import CreateTestData, RunIntTest
from lib.worker import *
import socket
import struct
import time
import random
import os

NUM_ITER   = 1
CHUNK_SIZE = 4

# Network configuration
SWITCHML_PORT = 9999

def get_worker_mac(rank):
    return f"00:00:00:00:01:{rank+1:02x}"

def get_worker_ip(rank):
    return f"10.0.0.{rank+1}"

def ip_to_int(ip_str):
    parts = ip_str.split('.')
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])

def mac_to_bytes(mac_str):
    return bytes.fromhex(mac_str.replace(':', ''))

def calculate_checksum(data):
    if len(data) % 2 == 1:
        data += b'\x00'

    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    return (~checksum) & 0xFFFF

def pack_switchml_packet(worker_id, chunk_id, num_workers, flags, values):
    padded_values = values + [0] * (4 - len(values))
    padded_values = padded_values[:4]

    packet = struct.pack('!BBBBLLLL',
                        worker_id, chunk_id, num_workers, flags,
                        padded_values[0], padded_values[1],
                        padded_values[2], padded_values[3])
    return packet

def unpack_switchml_packet(data):
    if len(data) < 20:
        return None

    unpacked = struct.unpack('!BBBBLLLL', data[:20])
    worker_id, chunk_id, num_workers, flags = unpacked[:4]
    values = list(unpacked[4:])

    return (worker_id, chunk_id, num_workers, flags, values)

def create_raw_udp_packet(src_ip, dst_ip, src_port, dst_port, payload, src_mac, dst_mac):
    # Ethernet header (14 bytes)
    eth_header = struct.pack('!6s6sH',
                            mac_to_bytes(dst_mac),
                            mac_to_bytes(src_mac),
                            0x0800)

    # IP header (20 bytes)
    version_ihl = 0x45
    tos = 0
    total_length = 20 + 8 + len(payload)
    identification = random.randint(0, 65535)
    flags_fragment = 0x4000
    ttl = 64
    protocol = 17
    checksum = 0
    src_ip_int = ip_to_int(src_ip)
    dst_ip_int = ip_to_int(dst_ip)

    ip_header_no_checksum = struct.pack('!BBHHHBBHLL',
                                       version_ihl, tos, total_length,
                                       identification, flags_fragment,
                                       ttl, protocol, 0,
                                       src_ip_int, dst_ip_int)

    ip_checksum = calculate_checksum(ip_header_no_checksum)
    ip_header = struct.pack('!BBHHHBBHLL',
                           version_ihl, tos, total_length,
                           identification, flags_fragment,
                           ttl, protocol, ip_checksum,
                           src_ip_int, dst_ip_int)

    # UDP header (8 bytes)
    udp_length = 8 + len(payload)
    udp_checksum = 0
    udp_header = struct.pack('!HHHH',
                            src_port, dst_port,
                            udp_length, udp_checksum)

    packet = eth_header + ip_header + udp_header + payload
    return packet

def AllReduce(rank, data, result):
    """Process ALL chunks, not just the first one"""
    Log(f"Worker {rank}: Processing ALL chunks")

    # Get network information
    src_mac = get_worker_mac(rank)
    src_ip = get_worker_ip(rank)
    dst_mac = "ff:ff:ff:ff:ff:ff"
    dst_ip = "255.255.255.255"
    src_port = 10000 + rank
    dst_port = SWITCHML_PORT

    Log(f"Worker {rank}: Processing {len(data)} values in chunks of {CHUNK_SIZE}")

    interface = "eth0"

    # Create raw socket for sending
    try:
        send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        send_sock.bind((interface, 0))
        Log(f"Worker {rank}: Created raw send socket on {interface}")
    except Exception as e:
        Log(f"Worker {rank}: ERROR - Could not create raw socket: {e}")
        return False

    # Create UDP socket for receiving
    try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        recv_sock.bind(('', src_port))
        recv_sock.settimeout(10.0)  # Shorter timeout since we know it works
        Log(f"Worker {rank}: Created UDP receive socket on port {src_port}")
    except Exception as e:
        Log(f"Worker {rank}: ERROR - Could not create receive socket: {e}")
        send_sock.close()
        return False

    try:
        num_workers = 3
        num_chunks = (len(data) + CHUNK_SIZE - 1) // CHUNK_SIZE  # Ceiling division

        # Staggered delay based on rank
        delay = 1.0 + (rank * 0.5)
        Log(f"Worker {rank}: Waiting {delay} seconds before sending...")
        time.sleep(delay)

        # Process each chunk
        for chunk_id in range(num_chunks):
            start_idx = chunk_id * CHUNK_SIZE
            end_idx = min(start_idx + CHUNK_SIZE, len(data))
            chunk_values = data[start_idx:end_idx]

            # Pad chunk to 4 values if needed
            while len(chunk_values) < 4:
                chunk_values.append(0)

            Log(f"Worker {rank}: Sending chunk {chunk_id} with values {chunk_values}")

            # Create SwitchML payload
            switchml_payload = pack_switchml_packet(
                worker_id=rank,
                chunk_id=chunk_id,
                num_workers=num_workers,
                flags=0,
                values=chunk_values
            )

            # Create raw packet
            raw_packet = create_raw_udp_packet(
                src_ip, dst_ip, src_port, dst_port,
                switchml_payload, src_mac, dst_mac
            )

            # Send packet
            try:
                bytes_sent = send_sock.send(raw_packet)
                Log(f"Worker {rank}: Sent packet for chunk {chunk_id} ({bytes_sent} bytes)")
            except Exception as e:
                Log(f"Worker {rank}: ERROR - Failed to send packet for chunk {chunk_id}: {e}")
                return False

            # Wait for aggregation result
            Log(f"Worker {rank}: Waiting for response to chunk {chunk_id}")

            try:
                response_data, addr = recv_sock.recvfrom(1024)
                Log(f"Worker {rank}: Received response from {addr}")

                # Unpack response
                response = unpack_switchml_packet(response_data)
                if response is None:
                    Log(f"Worker {rank}: ERROR - Invalid response packet for chunk {chunk_id}")
                    return False

                resp_worker_id, resp_chunk_id, resp_num_workers, resp_flags, chunk_result = response

                # Verify this is the response we're expecting
                if resp_chunk_id == chunk_id and resp_flags == 1:
                    Log(f"Worker {rank}: Received valid response for chunk {chunk_id}: {chunk_result}")

                    # Copy aggregated values back to result array
                    for i in range(min(len(chunk_values), 4)):
                        if start_idx + i < len(result):
                            result[start_idx + i] = chunk_result[i]

                    Log(f"Worker {rank}: Updated result indices {start_idx}-{start_idx + len(chunk_values) - 1}")

                else:
                    Log(f"Worker {rank}: ERROR - Wrong response: chunk_id={resp_chunk_id}, flags={resp_flags}")
                    return False

            except socket.timeout:
                Log(f"Worker {rank}: ERROR - Timeout waiting for chunk {chunk_id}")
                return False
            except Exception as e:
                Log(f"Worker {rank}: ERROR - Exception receiving response for chunk {chunk_id}: {e}")
                return False

            # Small delay between chunks to avoid overwhelming the switch
            time.sleep(0.1)

        Log(f"Worker {rank}: Completed processing all {num_chunks} chunks")
        Log(f"Worker {rank}: Final result: {result}")
        return True

    finally:
        send_sock.close()
        recv_sock.close()

def main():
    rank = GetRankOrExit()
    Log("Started DEBUG worker...")

    # Create fake test data for verification
    data_out = [100, 200, 300, 400, 500, 600, 700, 800]  # Fixed test data
    data_in = [0] * len(data_out)  # Initialize result vector

    CreateTestData("udp-iter-0", rank, data_out)
    success = AllReduce(rank, data_out, data_in)
    if success:
        RunIntTest("udp-iter-0", rank, data_in, True)
    else:
        Log("AllReduce failed!")
    Log("Done")

if __name__ == '__main__':
    main()
