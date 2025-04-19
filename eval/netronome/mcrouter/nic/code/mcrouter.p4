#define ETHERTYPE_IPV4      0x0800
#define ETHERTYPE_ARP       0x0806
#define UDP_PROTOCOL        0x11
#define TCP_PROTOCOL        0x06
#define IPV4_VERSION        0x04

header_type intrinsic_metadata_t {
    fields {
        ingress_global_tstamp : 48;
    }
}

header_type eth_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etype : 16;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset :4;
        res : 3;
        ecn : 3;
        ctrl : 6;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
    }
}

header_type int_hdr_t {
    fields {
        tx_ts: 32;
        exec: 32;
    }
}

header eth_t eth;
header ipv4_t ipv4;
header udp_t udp;
header tcp_t tcp;
header int_hdr_t int_hdr;
metadata intrinsic_metadata_t intrinsic_metadata;


parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(eth);
    return select(latest.etype) {
        ETHERTYPE_IPV4 : parse_ipv4;
        ETHERTYPE_ARP: ingress;        
    }
}

parser parse_ipv4 {
    extract(ipv4);
    return select(ipv4.protocol) {
        TCP_PROTOCOL : parse_tcp;
        UDP_PROTOCOL : parse_udp;
        default : parse_int;
    }
}

parser parse_udp {
    extract(udp);
    return parse_int;
}

parser parse_tcp {
    extract(tcp);
    return parse_int;
}

parser parse_int {
    extract(int_hdr);
    return ingress;
}

primitive_action route();
primitive_action calc_idle_time();
primitive_action record_end_time();

action do_route() {
	route();
    record_end_time();
}

action do_forward(port) {
    calc_idle_time();
	modify_field(standard_metadata.egress_spec, port);
}

action do_drop() {
	drop();
}

table router {
    reads {
        ipv4.protocol : exact;
    }
	actions {
		do_route;
	}
}

table forward {
	reads {
		eth.dstAddr : exact;
	}
	actions {
		do_forward;
		do_drop;
	}
}

control ingress 
{
    apply(router);
    apply(forward);
}