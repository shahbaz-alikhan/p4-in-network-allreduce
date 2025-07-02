# SwitchML Implementation - Level 2 & 3 Documentation

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Level 2: In-network AllReduce over UDP](#level-2-in-network-allreduce-over-udp)
4. [Level 3: In-network AllReduce over UDP with Reliability](#level-3-in-network-allreduce-over-udp-with-reliability)
5. [Running the Implementation](#running-the-implementation)
6. [Debugging Guide](#debugging-guide)
7. [Implementation Details](#implementation-details)
8. [Known Issues and Limitations](#known-issues-and-limitations)
9. [Future Improvements](#future-improvements)

## Overview

This project implements a simplified version of SwitchML, an in-network aggregation protocol for accelerating distributed machine learning. The implementation includes:

- **Level 2**: Basic in-network AllReduce over UDP
- **Level 3**: In-network AllReduce over UDP with reliability (packet loss handling)

### Key Concepts

**AllReduce**: A collective operation where N workers each contribute a vector, and all workers receive the element-wise sum of all vectors.

**In-network Aggregation**: The P4-programmable switch performs the aggregation, reducing network traffic and latency.

**Chunking**: Large vectors are divided into chunks of 4 values (32-bit integers) for processing.

## Architecture

```
┌─────────┐     ┌─────────┐     ┌─────────┐
│Worker 0 │     │Worker 1 │     │Worker 2 │
│10.0.0.1 │     │10.0.0.2 │     │10.0.0.3 │
└────┬────┘     └────┬────┘     └────┬────┘
     │               │               │
     └───────────────┴───────────────┘
                     │
              ┌──────┴──────┐
              │  P4 Switch  │
              │  10.0.0.100 │
              └─────────────┘
```

### Components

1. **Workers** (`worker.py`): Python processes that send data chunks and receive aggregated results
2. **P4 Switch** (`p4/main.p4`): Performs in-network aggregation using P4 programmable data plane
3. **Control Plane** (`network.py`): Configures the network topology and switch behavior

## Level 2: In-network AllReduce over UDP

### Overview
Level 2 implements basic AllReduce over UDP without reliability guarantees. Workers send chunks to the switch, which aggregates and broadcasts results.

### Implementation Details

#### Worker Implementation (`worker.py`)

```python
def AllReduce(rank, data, result):
    # Network configuration
    src_ip = get_worker_ip(rank)
    dst_ip = "255.255.255.255"  # Broadcast
    src_port = 10000 + rank
    dst_port = 9999  # SwitchML port

    # Process data in chunks
    for chunk_start in range(0, len(data), CHUNK_SIZE):
        # Pack SwitchML packet
        switchml_payload = pack_switchml_packet(
            worker_id=rank,
            chunk_id=chunk_id,
            num_workers=num_workers,
            flags=0,  # Data packet
            values=chunk_data
        )

        # Create and send raw UDP packet
        raw_packet = create_raw_udp_packet(...)
        send_sock.send(raw_packet)

        # Wait for broadcast response
        response_data, addr = recv_sock.recvfrom(1024)
```

#### P4 Switch Implementation (`main.p4`)

```p4
// Key data structures
register<bit<32>>(256) agg_value0-3;  // Aggregation storage
register<bit<8>>(256) agg_count;      // Worker count

action perform_aggregation() {
    // Read current values
    agg_value0.read(current_val0, reg_index);
    // ... read other values ...

    // Add new values
    current_val0 = current_val0 + hdr.switchml.value0;
    // ... add other values ...

    // Increment count
    current_count = current_count + 1;

    // Check if all workers contributed
    if (current_count == hdr.switchml.num_workers) {
        // Broadcast result
        meta.is_last_worker = 1;
        // Reset for next round
        agg_count.write(reg_index, 0);
    }
}
```

### Packet Format

```
SwitchML Header (20 bytes):
┌─────────────┬──────────┬─────────────┬───────┐
│ worker_id   │ chunk_id │ num_workers │ flags │
│ (1 byte)    │ (1 byte) │ (1 byte)    │(1 byte)│
├─────────────┴──────────┴─────────────┴───────┤
│ value0 (4 bytes)                              │
├───────────────────────────────────────────────┤
│ value1 (4 bytes)                              │
├───────────────────────────────────────────────┤
│ value2 (4 bytes)                              │
├───────────────────────────────────────────────┤
│ value3 (4 bytes)                              │
└───────────────────────────────────────────────┘
```

### Level 2 Workflow

1. **Worker sends chunk**: Each worker sends its chunk data to the switch
2. **Switch aggregates**: Switch adds values to running sum, increments counter
3. **Check completion**: If counter equals number of workers, aggregation complete
4. **Broadcast result**: Switch multicasts result to all workers
5. **Reset state**: Clear aggregation registers for next chunk

### Limitations of Level 2

- No packet loss handling
- No duplicate detection
- Assumes reliable, congestion-free network
- System hangs if any packet is lost

## Level 3: In-network AllReduce over UDP with Reliability

### Overview
Level 3 adds reliability through timeout/retransmission, duplicate detection, and result caching.

### Key Additions Over Level 2

#### 1. Worker-side Reliability (`worker.py`)

```python
# Configuration
TIMEOUT = 1.0        # Timeout in seconds
MAX_RETRIES = 10     # Maximum retry attempts

# Retry loop for each chunk
while retry_count < MAX_RETRIES and not success:
    # Send packet
    bytes_sent = send_sock.send(raw_packet)

    # Wait with timeout
    start_time = time.time()
    while time.time() - start_time < TIMEOUT:
        try:
            response_data, addr = recv_sock.recvfrom(1024)
            # Validate response
            if resp_chunk_id == chunk_id and resp_flags == 1:
                success = True
                break
        except socket.error:
            time.sleep(0.01)

    if not success:
        retry_count += 1
        Log(f"Timeout for chunk {chunk_id}, retrying...")
```

#### 2. Switch-side Reliability (`main.p4`)

```p4
// Additional registers for reliability
register<bit<8>>(256) worker_bitmap;    // Track which workers sent
register<bit<32>>(256) result_value0-3; // Store results
register<bit<1>>(256) result_ready;     // Result availability

action perform_aggregation() {
    // Check for duplicate using bitmap
    bit<8> worker_mask = (bit<8>)1 << (bit<8>)hdr.switchml.worker_id;
    if ((current_bitmap & worker_mask) != 0) {
        // Retransmission detected
        meta.is_retransmission = 1;
        result_ready.read(ready, reg_index);
        meta.aggregation_complete = ready;
    } else {
        // New contribution
        current_bitmap = current_bitmap | worker_mask;
        // ... perform aggregation ...

        // If complete, store results
        if (worker_count == hdr.switchml.num_workers) {
            result_value0.write(reg_index, current_val0);
            // ... store other values ...
            result_ready.write(reg_index, 1);
        }
    }
}

// Unicast response for retransmissions
action unicast_result() {
    // Load stored results
    // Swap addresses for unicast
    // Send back to requesting worker
}
```

### Reliability Mechanisms

1. **Timeout and Retransmission**
   - Workers retry after 1 second timeout
   - Maximum 10 retries per chunk
   - Exponential backoff (optional enhancement)

2. **Duplicate Detection**
   - Bitmap tracks which workers contributed
   - Prevents double-counting on retransmission
   - Per-chunk tracking

3. **Result Caching**
   - Completed results stored in registers
   - Available for unicast to retransmitting workers
   - Cleared when safe (next chunk processing starts)

4. **Progress Guarantee**
   - Workers only proceed after receiving current chunk result
   - Prevents workers from getting out of sync

### Level 3 Workflow

1. **Worker sends chunk with retry**:
   ```
   Send → Wait (1s) → Timeout? → Retry
                 ↓
              Response → Next chunk
   ```

2. **Switch processes packet**:
   ```
   Packet arrives → Check bitmap
                         ↓
               New? → Aggregate → Complete? → Store & Broadcast
                ↓                      ↓
            Duplicate              Not complete → Drop
                ↓
            Result ready? → Unicast stored result
   ```

3. **Handling packet loss scenarios**:
   - **Lost request**: Worker timeout → Retransmit
   - **Lost broadcast response**: Worker timeout → Retransmit → Switch sends unicast
   - **Multiple losses**: Each worker independently retries until success

## Running the Implementation

### Prerequisites
- Ubuntu 20.04 VM with P4 environment
- Python 3.8+
- Mininet with P4 support

### Setup
```bash
# Install P4 environment (if not already done)
bash ./install_p4_env.sh

# Navigate to appropriate level directory
cd lab3/sml-udp-rel  # For Level 3
# or
cd lab3/sml-udp      # For Level 2
```

### Running Tests

1. **Start the network**:
   ```bash
   sudo ./start.sh
   ```

2. **From Mininet CLI, run workers**:
   ```
   mininet> py net.run_workers()
   ```

3. **Check results**:
   ```bash
   # Worker logs
   cat logs/w*.log

   # Test results
   cat logs/test/test-udp-iter-0/result-rank-*.txt

   # Switch logs (for debugging)
   cat logs/p4s.s1.log
   ```

### Manual Testing

1. **Open worker terminals**:
   ```
   mininet> xterm w0 w1 w2
   ```

2. **Run workers manually** (in each xterm):
   ```bash
   python worker.py 0  # For worker 0
   python worker.py 1  # For worker 1
   python worker.py 2  # For worker 2
   ```

## Debugging Guide

### Common Issues and Solutions

1. **Workers hang waiting for response**
   - Check if switch is receiving packets: `tcpdump -i s1-eth1`
   - Verify multicast group configuration in `network.py`
   - Check P4 program compilation: `cat logs/p4s.s1.log`

2. **Incorrect aggregation results**
   - Check bitmap implementation for duplicate detection
   - Verify register initialization (should be 0)
   - Ensure atomic operations in P4 code

3. **Packet parsing errors**
   - Verify packet format matches between worker and switch
   - Check endianness (network byte order)
   - Debug with packet dumps: `tcpdump -XX`

### Debugging Tools

1. **Packet Capture**:
   ```bash
   # Capture on switch interface
   sudo tcpdump -i s1-eth1 -w capture.pcap

   # Analyze with Wireshark
   wireshark capture.pcap
   ```

2. **P4 Debugging**:
   - Enable verbose logging in BMv2
   - Add debug tables in P4 code
   - Use `p4s.s1.log` for switch behavior

3. **Worker Debugging**:
   - Add extensive logging with `Log()` function
   - Print packet contents before sending
   - Log all timeout/retry events

### Performance Tuning

1. **Timeout Values**:
   - Adjust `TIMEOUT` based on network latency
   - Consider adaptive timeout

2. **Chunk Size**:
   - Larger chunks = fewer packets but larger buffers
   - Current: 4 values per chunk

3. **Retry Strategy**:
   - Implement exponential backoff
   - Adjust `MAX_RETRIES` based on loss rate

## Implementation Details

### Network Configuration

```python
# network.py key configurations
NUM_WORKERS = 3

# IP allocation
def getWorkerIP(wid):
    return "10.0.0.%d" % (wid + 1)

# Multicast group for broadcast
sw.addMulticastGroup(mgid=1, ports=[1, 2, 3])
```

### Raw Socket Usage

Workers use raw sockets to control packet headers:
```python
# Send socket (raw)
send_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)

# Receive socket (UDP)
recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
```

### P4 Register Management

```p4
// Register allocation per chunk
// Max 256 chunks supported
register<bit<32>>(256) agg_value0;
register<bit<32>>(256) agg_value1;
register<bit<32>>(256) agg_value2;
register<bit<32>>(256) agg_value3;
```

## Known Issues and Limitations

1. **Broadcast Limitations**
   - Currently using unicast to switch IP (10.0.0.100)
   - True broadcast requires additional network configuration

2. **Scalability**
   - Limited to 8 workers (bitmap is 8 bits)
   - Fixed chunk size of 4 values
   - Maximum 256 chunks (register size)

3. **Hardware Constraints**
   - No multiplication/division in P4
   - Single register access per packet
   - Limited branching in deparser

4. **Missing Features**
   - No congestion control
   - No adaptive timeout
   - No compression/quantization

## Future Improvements

### 1. Multi-slot Implementation (Bonus B2)
- Multiple chunks in flight
- Sliding window protocol
- Better bandwidth utilization

### 2. Recirculation (Bonus B3)
- Process 16 values per packet (4x improvement)
- Virtual pipeline stages
- Increased throughput

### 3. Production Features
- Congestion control
- Adaptive retry strategy
- Dynamic worker joining/leaving
- Fault tolerance for switch failure

### 4. Performance Optimizations
- Larger chunk sizes
- Pipeline parallelism
- RDMA integration

### 5. Security Enhancements
- Authentication
- Encryption
- Byzantine fault tolerance

## References

1. [SwitchML Paper](https://www.usenix.org/system/files/nsdi21-sapio.pdf)
2. [P4 Language Specification](https://p4.org/p4-spec/docs/P4-16-v-1.2.3.html)
3. [BMv2 Simple Switch Documentation](https://github.com/p4lang/behavioral-model/blob/main/docs/simple_switch.md)
4. [NVIDIA NCCL AllReduce](https://docs.nvidia.com/deeplearning/nccl/user-guide/docs/usage/collectives.html)
