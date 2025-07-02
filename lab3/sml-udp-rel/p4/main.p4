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
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
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
    bit<1>  is_retransmission;
    bit<1>  aggregation_complete;
    bit<8>  worker_bitmap;
    bit<32> chunk_result0;
    bit<32> chunk_result1;
    bit<32> chunk_result2;
    bit<32> chunk_result3;
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

    // Registers for aggregation (one per chunk position)
    register<bit<32>>(256) agg_value0;
    register<bit<32>>(256) agg_value1;
    register<bit<32>>(256) agg_value2;
    register<bit<32>>(256) agg_value3;

    // Register to track which workers have contributed (bitmap)
    register<bit<8>>(256)  worker_bitmap;

    // Registers to store final results for retransmissions
    register<bit<32>>(256) result_value0;
    register<bit<32>>(256) result_value1;
    register<bit<32>>(256) result_value2;
    register<bit<32>>(256) result_value3;
    register<bit<1>>(256)  result_ready;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action perform_aggregation() {
        bit<32> reg_index = (bit<32>)hdr.switchml.chunk_id;

        // Read current worker bitmap
        bit<8> current_bitmap;
        worker_bitmap.read(current_bitmap, reg_index);

        // Check if this worker already contributed
        bit<8> worker_mask = (bit<8>)1 << (bit<8>)hdr.switchml.worker_id;
        if ((current_bitmap & worker_mask) != 0) {
            // Worker already contributed, this is a retransmission
            meta.is_retransmission = 1;

            // Check if result is ready
            bit<1> ready;
            result_ready.read(ready, reg_index);
            meta.aggregation_complete = ready;

            // If ready, load results into metadata
            if (ready == 1) {
                result_value0.read(meta.chunk_result0, reg_index);
                result_value1.read(meta.chunk_result1, reg_index);
                result_value2.read(meta.chunk_result2, reg_index);
                result_value3.read(meta.chunk_result3, reg_index);
            }
        } else {
            // New contribution
            meta.is_retransmission = 0;

            // Mark this worker as contributed
            current_bitmap = current_bitmap | worker_mask;
            worker_bitmap.write(reg_index, current_bitmap);

            // Read current values
            bit<32> current_val0;
            bit<32> current_val1;
            bit<32> current_val2;
            bit<32> current_val3;

            agg_value0.read(current_val0, reg_index);
            agg_value1.read(current_val1, reg_index);
            agg_value2.read(current_val2, reg_index);
            agg_value3.read(current_val3, reg_index);

            // Add new values
            current_val0 = current_val0 + hdr.switchml.value0;
            current_val1 = current_val1 + hdr.switchml.value1;
            current_val2 = current_val2 + hdr.switchml.value2;
            current_val3 = current_val3 + hdr.switchml.value3;

            // Write back
            agg_value0.write(reg_index, current_val0);
            agg_value1.write(reg_index, current_val1);
            agg_value2.write(reg_index, current_val2);
            agg_value3.write(reg_index, current_val3);

            // Count number of workers that have contributed
            bit<8> worker_count = 0;

            // Count bits set in bitmap (unrolled loop)
            if ((current_bitmap & 0x01) != 0) worker_count = worker_count + 1;
            if ((current_bitmap & 0x02) != 0) worker_count = worker_count + 1;
            if ((current_bitmap & 0x04) != 0) worker_count = worker_count + 1;
            if ((current_bitmap & 0x08) != 0) worker_count = worker_count + 1;
            if ((current_bitmap & 0x10) != 0) worker_count = worker_count + 1;
            if ((current_bitmap & 0x20) != 0) worker_count = worker_count + 1;
            if ((current_bitmap & 0x40) != 0) worker_count = worker_count + 1;
            if ((current_bitmap & 0x80) != 0) worker_count = worker_count + 1;

            // Check if all workers have contributed
            if (worker_count == hdr.switchml.num_workers) {
                // Store results for future retransmissions
                result_value0.write(reg_index, current_val0);
                result_value1.write(reg_index, current_val1);
                result_value2.write(reg_index, current_val2);
                result_value3.write(reg_index, current_val3);
                result_ready.write(reg_index, 1);

                // Store in metadata for immediate use
                meta.chunk_result0 = current_val0;
                meta.chunk_result1 = current_val1;
                meta.chunk_result2 = current_val2;
                meta.chunk_result3 = current_val3;

                meta.is_last_worker = 1;
                meta.aggregation_complete = 1;

                // Do NOT reset aggregation registers here - they might be needed for retransmissions
                // The clear_old_state action will handle cleanup when appropriate
            } else {
                meta.is_last_worker = 0;
                meta.aggregation_complete = 0;
            }
        }

        // Store bitmap for later use
        meta.worker_bitmap = current_bitmap;
    }

    action multicast_result() {
        // Update packet with aggregated values
        hdr.switchml.value0 = meta.chunk_result0;
        hdr.switchml.value1 = meta.chunk_result1;
        hdr.switchml.value2 = meta.chunk_result2;
        hdr.switchml.value3 = meta.chunk_result3;
        hdr.switchml.flags = 1;  // Mark as result

        // Prepare for broadcast response
        standard_metadata.mcast_grp = 1;

        // For broadcast, we need to send back to the source port of each worker
        // But since it's multicast, we can't customize per-worker
        // So we swap ports - workers sent FROM their port TO 9999
        // Switch sends FROM 9999 TO their port
        bit<16> temp_port = hdr.udp.srcPort;
        hdr.udp.srcPort = hdr.udp.dstPort;
        hdr.udp.dstPort = temp_port;

        // Set switch as source
        hdr.ipv4.srcAddr = 0x0a000064;  // 10.0.0.100
        hdr.ethernet.srcAddr = 0x000000000100;

        // Keep destination as broadcast
        hdr.ipv4.dstAddr = 0xffffffff;  // 255.255.255.255
        hdr.ethernet.dstAddr = 0xffffffffffff;

        // Update IP header fields
        hdr.ipv4.ttl = 64;

        // Fix IP total length - it needs to include IP header + UDP header + payload
        hdr.ipv4.totalLen = 20 + 8 + 20;  // 48 bytes total

        // Update UDP length (8 bytes header + 20 bytes SwitchML)
        hdr.udp.length = 28;
    }

    action unicast_result() {
        // Update packet with stored values
        hdr.switchml.value0 = meta.chunk_result0;
        hdr.switchml.value1 = meta.chunk_result1;
        hdr.switchml.value2 = meta.chunk_result2;
        hdr.switchml.value3 = meta.chunk_result3;
        hdr.switchml.flags = 1;  // Mark as result

        // Swap addresses for unicast response
        bit<48> temp_mac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = temp_mac;

        bit<32> temp_ip = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = temp_ip;

        bit<16> temp_port = hdr.udp.srcPort;
        hdr.udp.srcPort = hdr.udp.dstPort;
        hdr.udp.dstPort = temp_port;

        // Send back to ingress port
        standard_metadata.egress_spec = standard_metadata.ingress_port;

        // Update IP header fields
        hdr.ipv4.ttl = 64;
    }

    action clear_old_state() {
        // Clear state for chunks that are definitely complete
        // This is a simplified version - in production you'd track acknowledgments
        bit<32> reg_index = (bit<32>)hdr.switchml.chunk_id;

        // Only clear state for chunks that are at least 2 chunks behind
        if (reg_index >= 2) {
            bit<32> old_index = reg_index - 2;

            // Clear the old chunk's state
            worker_bitmap.write(old_index, 0);
            result_ready.write(old_index, 0);
            result_value0.write(old_index, 0);
            result_value1.write(old_index, 0);
            result_value2.write(old_index, 0);
            result_value3.write(old_index, 0);
            agg_value0.write(old_index, 0);
            agg_value1.write(old_index, 0);
            agg_value2.write(old_index, 0);
            agg_value3.write(old_index, 0);
        }
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.udp.isValid() &&
            hdr.switchml.isValid() && hdr.switchml.flags == 0) {

            // Initialize metadata
            meta.is_retransmission = 0;
            meta.is_last_worker = 0;
            meta.aggregation_complete = 0;
            meta.chunk_result0 = 0;
            meta.chunk_result1 = 0;
            meta.chunk_result2 = 0;
            meta.chunk_result3 = 0;

            perform_aggregation();

            if (meta.is_retransmission == 1) {
                if (meta.aggregation_complete == 1) {
                    // Result is ready, send unicast response
                    unicast_result();
                } else {
                    // Aggregation not complete yet, drop
                    drop();
                }
            } else {
                if (meta.is_last_worker == 1) {
                    // This was the last worker, multicast result
                    multicast_result();
                    // Try to clear old state
                    clear_old_state();
                } else {
                    // Not the last worker yet, drop
                    drop();
                }
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
        // For multicast packets, we need to update the destination
        if (standard_metadata.instance_type == 1) {
            // This is a cloned packet from multicast
            // The egress port determines the destination
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
