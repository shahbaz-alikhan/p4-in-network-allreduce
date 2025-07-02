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

// Constants
const bit<16> TYPE_SWITCHML = 0x1234;  // Custom EtherType for SwitchML

// Headers
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
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
    switchml_t switchml;
}

struct metadata {
    bit<32> aggregation_count;
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
            TYPE_SWITCHML: parse_switchml;
            default: accept;
        }
    }

    state parse_switchml {
        packet.extract(hdr.switchml);
        transition accept;
    }
}

// Checksum verification (not needed for this lab)
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

// Ingress processing
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // Registers for aggregation (one per chunk position)
    register<bit<32>>(256) agg_value0;  // Aggregation for position 0
    register<bit<32>>(256) agg_value1;  // Aggregation for position 1
    register<bit<32>>(256) agg_value2;  // Aggregation for position 2
    register<bit<32>>(256) agg_value3;  // Aggregation for position 3
    register<bit<8>>(256)  agg_count;   // Count of aggregated workers per chunk

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action perform_aggregation() {
        // Calculate register index based on chunk_id
        bit<32> reg_index = (bit<32>)hdr.switchml.chunk_id;

        // Atomic aggregation operation
        @atomic {
            // Read current aggregation values and count
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

            // Add incoming values to aggregation
            current_val0 = current_val0 + hdr.switchml.value0;
            current_val1 = current_val1 + hdr.switchml.value1;
            current_val2 = current_val2 + hdr.switchml.value2;
            current_val3 = current_val3 + hdr.switchml.value3;
            current_count = current_count + 1;

            // Write back aggregated values
            agg_value0.write(reg_index, current_val0);
            agg_value1.write(reg_index, current_val1);
            agg_value2.write(reg_index, current_val2);
            agg_value3.write(reg_index, current_val3);
            agg_count.write(reg_index, current_count);

            // Check if this is the last worker
            if (current_count == hdr.switchml.num_workers) {
                // Prepare response packet with aggregated values
                hdr.switchml.value0 = current_val0;
                hdr.switchml.value1 = current_val1;
                hdr.switchml.value2 = current_val2;
                hdr.switchml.value3 = current_val3;
                hdr.switchml.flags = 1;  // Mark as result

                // Set broadcast MAC for multicast response
                hdr.ethernet.dstAddr = 0xffffffffffff;
                hdr.ethernet.srcAddr = 0x000000000100;  // Switch MAC

                // Reset aggregation for next round
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
    }

    action multicast_result() {
        // Set multicast group to broadcast to all workers
        standard_metadata.mcast_grp = 1;
    }

    apply {
        if (hdr.switchml.isValid() && hdr.switchml.flags == 0) {
            // This is a data packet, perform aggregation
            perform_aggregation();

            if (meta.is_last_worker == 1) {
                // Multicast the result to all workers
                multicast_result();
            } else {
                // Drop intermediate packets
                drop();
            }
        } else {
            // Drop non-SwitchML packets
            drop();
        }
    }
}

// Egress processing
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

// Checksum computation (not needed for this lab)
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

// Deparser
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
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
