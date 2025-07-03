/*
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
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER BEINGS IN THE SOFTWARE.
 */

#include <core.p4>
#include <v1model.p4>

// Headers
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

header switchml_t {
    bit<8>  worker_id;      // Worker rank
    bit<8>  chunk_id;       // Chunk identifier within vector
    bit<8>  num_workers;    // Total number of workers
    bit<8>  flags;          // Control flags (0=data, 1=result)
    bit<32> value0;         // First value in chunk
    bit<32> value1;         // Second value in chunk
    bit<32> value2;         // Third value in chunk
    bit<32> value3;         // Fourth value in chunk
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    udp_t      udp;
    switchml_t switchml;
}

struct metadata {
    bit<1>  is_last_worker;
}

// Parser
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;  // IPv4
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17: parse_udp;  // UDP
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            9999: parse_switchml;
            default: accept;
        }
    }

    state parse_switchml {
        packet.extract(hdr.switchml);
        transition accept;
    }
}

// Checksum verification
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

// Ingress processing
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // Registers for aggregation - use larger space to avoid conflicts
    register<bit<32>>(1024) agg_value0;
    register<bit<32>>(1024) agg_value1;
    register<bit<32>>(1024) agg_value2;
    register<bit<32>>(1024) agg_value3;
    register<bit<8>>(1024)  agg_count;

    // Session ID to avoid conflicts between runs - use worker_id + timestamp-like value
    register<bit<32>>(1024) session_id;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action perform_aggregation() {
    // All workers should use the same index for the same chunk
    bit<32> reg_index = (bit<32>)hdr.switchml.chunk_id;

    // Read current values
    bit<32> current_val0;
    bit<32> current_val1;
    bit<32> current_val2;
    bit<32> current_val3;
    bit<8>  current_count;

    agg_value0.read(current_val0, reg_index);
    agg_value1.read(current_val1, reg_index);
    agg_value2.read(current_val2, reg_index);
    agg_value3.read(current_val3, reg_index);
    agg_count.read(current_count, reg_index);

    // Add new values
    current_val0 = current_val0 + hdr.switchml.value0;
    current_val1 = current_val1 + hdr.switchml.value1;
    current_val2 = current_val2 + hdr.switchml.value2;
    current_val3 = current_val3 + hdr.switchml.value3;
    current_count = current_count + 1;

    // Write back
    agg_value0.write(reg_index, current_val0);
    agg_value1.write(reg_index, current_val1);
    agg_value2.write(reg_index, current_val2);
    agg_value3.write(reg_index, current_val3);
    agg_count.write(reg_index, current_count);

    // Check if all workers have contributed
    if (current_count == hdr.switchml.num_workers) {
        // Update packet with aggregated values
        hdr.switchml.value0 = current_val0;
        hdr.switchml.value1 = current_val1;
        hdr.switchml.value2 = current_val2;
        hdr.switchml.value3 = current_val3;
        hdr.switchml.flags = 1;  // Mark as result

        // Reset for next round
        agg_value0.write(reg_index, 0);
        agg_value1.write(reg_index, 0);
        agg_value2.write(reg_index, 0);
        agg_value3.write(reg_index, 0);
        agg_count.write(reg_index, 0);

        meta.is_last_worker = 1;
    } else {
        meta.is_last_worker = 0;
    }
}

    action multicast_result() {
    // Prepare for broadcast response
    standard_metadata.mcast_grp = 1;

    // Set switch as source
    hdr.ipv4.srcAddr = 0x0a000064;  // 10.0.0.100
    hdr.ethernet.srcAddr = 0x000000000100;
    hdr.udp.srcPort = 9999;

    // Don't set destination addresses here - let egress handle it
    // Individual worker addresses will be set in egress based on port

    // Update IP header fields
    hdr.ipv4.ttl = 64;

    // Update IP total length (20 IP + 8 UDP + 20 SwitchML = 48)
    hdr.ipv4.totalLen = 48;

    // Update UDP length (8 bytes header + 20 bytes SwitchML)
    hdr.udp.length = 28;
}

    apply {
        if (hdr.ipv4.isValid() && hdr.udp.isValid() &&
            hdr.switchml.isValid() && hdr.switchml.flags == 0) {
            perform_aggregation();
            if (meta.is_last_worker == 1) {
                multicast_result();
            } else {
                drop();
            }
        } else {
            drop();
        }
    }
}

// Egress processing
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        // For multicast packets, set individual worker addresses
        // Check if this is a multicast packet by looking at mcast_grp
        if (standard_metadata.mcast_grp == 1) {
            // This is a multicast packet, set destination based on egress port
            if (standard_metadata.egress_port == 1) {
                // Worker 0 - port 1
                hdr.ipv4.dstAddr = 0x0a000001;      // 10.0.0.1
                hdr.ethernet.dstAddr = 0x000000000101; // 00:00:00:00:01:01
                hdr.udp.dstPort = 10000;
            } else if (standard_metadata.egress_port == 2) {
                // Worker 1 - port 2
                hdr.ipv4.dstAddr = 0x0a000002;      // 10.0.0.2
                hdr.ethernet.dstAddr = 0x000000000102; // 00:00:00:00:01:02
                hdr.udp.dstPort = 10001;
            } else if (standard_metadata.egress_port == 3) {
                // Worker 2 - port 3
                hdr.ipv4.dstAddr = 0x0a000003;      // 10.0.0.3
                hdr.ethernet.dstAddr = 0x000000000103; // 00:00:00:00:01:03
                hdr.udp.dstPort = 10002;
            }
        }
    }
}

// Checksum computation
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

// Deparser
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.switchml);
    }
}

// Switch instantiation
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
