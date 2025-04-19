/*
 * Headers
 */

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
        srcPort: 16;
        dstPort: 16;
        seqNo: 32;
        ackNo: 32;
        len: 4;
        res: 3;
        enc: 3;
        ctrl: 6;
        window: 16;
        checksum: 16;
        urgent_ptr: 16;
    }
}

header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        length_ : 16;
        checksum : 16;
    }
}

header_type int_hdr_t {
    fields {
        opt: 32;                                // message operation
        idle: 32;                               // workload estimator
        bucket: 32;                             // bucket index
        index: 32;                              // entry index
        flag: 32;                               // 1: overloaded, 0: available
        cnt: 32;                                // throughput estimator
    }
}

header_type memcached_hdr_t {
    fields {
        opt: 32;                                // message operation
        idle: 32;                               // workload estimator
        bucket: 32;                             // bucket index
        index: 32;                              // entry index
        flag: 32;                               // 1: overloaded, 0: available
        cnt: 32;                                // throughput estimator
        key: 32;                                // memcached key
    }
}

header_type state_meta_t {
    fields {    
        state : 32;                             // state
        ip : 32;                                // ip used for NAT
        port : 16;                              // port used for NAT
        hit_count : 32;                         // number of hits since connection was made
        incoming_port : 1;                      // trusted = 0, untrusted = 1
    }
}
metadata state_meta_t state_meta;

/*
 * Parsers
 */

metadata intrinsic_metadata_t intrinsic_metadata;

parser start {
    return parse_ethernet;
}

/*
 * Ethernet
 */

#define ETHERTYPE_IPV4 0x0800
#define MIGRATION_CTRL 0x0900

header eth_t eth;

parser parse_ethernet {
    extract(eth);
    return select(latest.etype) {
        ETHERTYPE_IPV4 : parse_ipv4;
        MIGRATION_CTRL : parse_ipv4;
        default : ingress;
    }
}

/*
 * IPv4
 */

#define IP_PROTOCOLS_TCP 6
#define IP_PROTOCOLS_UDP 17

header ipv4_t ipv4;

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.protocol) {
        IP_PROTOCOLS_TCP : parse_tcp;
        IP_PROTOCOLS_UDP : parse_udp;
        default: parse_int;
    }
}

/*
 * TCP
 */

header tcp_t tcp;
parser parse_tcp {
    extract(tcp);
    return parse_int;
}

/*
 * UDP
 */

header udp_t udp;

parser parse_udp {
    extract(udp);
    return parse_memcached;
}

/*
 * INT
 */

header int_hdr_t int_hdr;

parser parse_int {
    extract(int_hdr);
    return ingress;
}

/*
 * MEMCACHED
 */
header memcached_hdr_t memcached_hdr;
parser parse_memcached {
    extract(memcached_hdr);
    return ingress;
}

primitive_action netcache();
primitive_action lookup_state();
primitive_action migrate_state();
primitive_action calc_idle_time();
primitive_action record_end_time();

action do_migrate() {
    calc_idle_time();
    migrate_state();
    record_end_time();
}

action do_lookup(incoming_port) {
    calc_idle_time();
    modify_field(state_meta.incoming_port, incoming_port);
    lookup_state();
    record_end_time();
}

action do_netcache(incoming_port) {
    calc_idle_time();
    modify_field(state_meta.incoming_port, incoming_port);
    netcache();
    record_end_time();
}

action do_drop() {
    drop();
}

action to_wire(port) {
    modify_field(standard_metadata.egress_spec, port);
}

table forward {
	reads {
		eth.etype: exact;
        ipv4.protocol: exact;
	}
	actions {
        do_netcache;
		do_lookup;
        do_migrate;
		do_drop;
        to_wire;
	}
}

control ingress {
	apply(forward);
}