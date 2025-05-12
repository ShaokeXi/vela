#include <core.p4>
#include <psa.p4>

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> l4_port_t;

// Headers
header ethernet_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header tcp_t {
    l4_port_t src_port;
    l4_port_t dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
}

// Custom type for flow identification
@p4runtime_translation("p4.org/psa/v1/FlowID_t", 32)
type bit<32> FlowID_t;

struct metadata_t {
    FlowID_t vip_id;
}

// Empty metadata for resubmit/recirculate
struct empty_t {}

// Parser
parser IngressParserImpl(
    packet_in pkt,
    out headers_t hdr,
    inout metadata_t meta,
    in psa_ingress_parser_input_metadata_t istd,
    in empty_t resubmit_meta,
    in empty_t recirculate_meta) {

    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
}

// Deparser
control IngressDeparserImpl(
    packet_out pkt,
    out empty_t clone_i2e_meta,
    out empty_t resubmit_meta,
    out empty_t normal_meta,
    inout headers_t hdr,
    in metadata_t meta,
    in psa_ingress_output_metadata_t istd) {

    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
    }
}

control EgressDeparserImpl(
    packet_out pkt,
    out empty_t clone_e2e_meta,
    out empty_t recirculate_meta,
    inout headers_t hdr,
    in metadata_t meta,
    in psa_egress_output_metadata_t istd,
    in psa_egress_deparser_input_metadata_t edstd) {

    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
    }
}

parser EgressParserImpl(
    packet_in pkt,
    out headers_t hdr,
    inout metadata_t meta,
    in psa_egress_parser_input_metadata_t istd,
    in empty_t normal_meta,
    in empty_t clone_i2e_meta,
    in empty_t clone_e2e_meta) {

    state start {
        transition accept;
    }
}

// Ingress control
control ingress(
    inout headers_t hdr,
    inout metadata_t meta,
    in psa_ingress_input_metadata_t istd,
    inout psa_ingress_output_metadata_t ostd) {

    // Registers as defined in Figure 4
    Register<bit<32>, bit<32>>(4096) DipCntr;    // Connection counter per destination IP
    Register<bit<32>, bit<32>>(4) MinDip;        // IP with minimum load
    Register<bit<32>, bit<32>>(4) MinLoad;       // Minimum load value

    // Action to route packet and update counters
    action route_and_update_cntrs() {
        // Read and increment connection counter for destination IP
        bit<32> cntr = DipCntr.read((bit<32>)hdr.ipv4.dst_addr) + 1;
        DipCntr.write((bit<32>)hdr.ipv4.dst_addr, cntr);

        // Read minimum load for current VIP
        bit<32> min_load = MinLoad.read((bit<32>)meta.vip_id);
        bit<32> min_dip = MinDip.read((bit<32>)meta.vip_id);

        // Update minimum load tracking
        if (cntr < min_load) {
            MinLoad.write((bit<32>)meta.vip_id, cntr);
            MinDip.write((bit<32>)meta.vip_id, hdr.ipv4.dst_addr);
        } else if (hdr.ipv4.dst_addr == min_dip) {
            MinLoad.write((bit<32>)meta.vip_id, cntr);
        }
    }

    // Action to set destination IP
    action setDip(bit<32> dip) {
        hdr.ipv4.dst_addr = dip;
        route_and_update_cntrs();
    }

    // Action for no operation
    action nop() {}

    // Connection table
    table connTbl {
        key = {
            hdr.ipv4.src_addr: exact;
        }
        actions = {
            setDip;
            nop;
        }
        default_action = nop;
        size = 1024;
    }

    apply {
        // Set VIP ID based on destination IP (as shown in line 28 of Figure 4)
        meta.vip_id = (FlowID_t)(hdr.ipv4.dst_addr & 0x03);

        // Apply connection table
        connTbl.apply();
    }
}

// Egress control
control egress(
    inout headers_t hdr,
    inout metadata_t meta,
    in psa_egress_input_metadata_t istd,
    inout psa_egress_output_metadata_t ostd) {
    apply { }
}

// Switch package instantiation
IngressPipeline(IngressParserImpl(), ingress(), IngressDeparserImpl()) ip;
EgressPipeline(EgressParserImpl(), egress(), EgressDeparserImpl()) ep;
PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;