#define MY_PROTOCOL_1 0x0801
#define MY_PROTOCOL_2 0x0802
#define MY_PROTOCOL_3 0x0803
#define MY_PROTOCOL_4 0x0804
#define MY_PROTOCOL_5 0x0805
#define MY_PROTOCOL_6 0x0806

header_type eth_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etype : 16;
    }
}

header_type myhdr_1_t {
    fields {
        mtype: 16;
        value: 32;
        other: 80;
    }
}

header_type myhdr_2_t {
    fields {
        mtype: 16;
        value: 32;
        other: 80;
    }
}

header_type myhdr_3_t {
    fields {
        mtype: 16;
        value: 32;
        other: 80;
    }
}

header_type myhdr_4_t {
    fields {
        mtype: 16;
        value: 32;
        other: 80;
    }
}

header_type myhdr_5_t {
    fields {
        mtype: 16;
        value: 32;
        other: 80;
    }
}

header_type myhdr_6_t {
    fields {
        mtype: 16;
        value: 32;
        other: 80;
    }
}

header eth_t eth;
header myhdr_1_t myhdr_1;
header myhdr_2_t myhdr_2;
header myhdr_3_t myhdr_3;
header myhdr_4_t myhdr_4;
header myhdr_5_t myhdr_5;
header myhdr_6_t myhdr_6;
primitive_action mem_simulator();

// counter tbl_hits {
//     type: packets;
//     instance_count: 7;
// }

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(eth);
    return select(latest.etype) {
        MY_PROTOCOL_1 : parse_myhdr_1;
        default : ingress;
    }
}

parser parse_myhdr_1 {
	extract(myhdr_1);
	return select(latest.mtype) {
        MY_PROTOCOL_2 : parse_myhdr_2;
        default : ingress;
    }
}

parser parse_myhdr_2 {
    extract(myhdr_2);
    return select(latest.mtype) {
        MY_PROTOCOL_3 : parse_myhdr_3;
        default : ingress;
    }
}

parser parse_myhdr_3 {
    extract(myhdr_3);
    return select(latest.mtype) {
        MY_PROTOCOL_4 : parse_myhdr_4;
        default : ingress;
    }
}

parser parse_myhdr_4 {
    extract(myhdr_4);
    return select(latest.mtype) {
        MY_PROTOCOL_5 : parse_myhdr_5;
        default : ingress;
    }
}

parser parse_myhdr_5 {
    extract(myhdr_5);
    return select(latest.mtype) {
        MY_PROTOCOL_6 : parse_myhdr_6;
        default : ingress;
    }
}

parser parse_myhdr_6 {
    extract(myhdr_6);
    return ingress;
}

action do_forward(prt) {
    // count(tbl_hits, id);
	modify_field(standard_metadata.egress_spec, prt);
    mem_simulator();
}

action do_drop() {
    drop();
}

table forward_0 {
    reads {
        eth.dstAddr : exact;
    }
    actions {
        do_forward;
        do_drop;
    }
}

table forward_1 {
    reads {
        myhdr_1.value : exact;
    }
    actions {
        do_forward;
        do_drop;
    }
}

table forward_2 {
    reads {
        myhdr_2.value : exact;
    }
    actions {
        do_forward;
        do_drop;
    }
}

table forward_3 {
    reads {
        myhdr_3.value : exact;
    }
    actions {
        do_forward;
        do_drop;
    }
}

table forward_4 {
    reads {
        myhdr_4.value : exact;
    }
    actions {
        do_forward;
        do_drop;
    }
}

table forward_5 {
    reads {
        myhdr_5.value : exact;
    }
    actions {
        do_forward;
        do_drop;
    }
}

table forward_6 {
    reads {
        myhdr_6.value : exact;
    }
    actions {
        do_forward;
        do_drop;
    }
}

control ingress {
    if (valid(myhdr_6)) {
        apply(forward_6);
    }
    else if (valid(myhdr_5)) {
        apply(forward_5);
    }
    else if (valid(myhdr_4)) {
        apply(forward_4);
    }
    else if (valid(myhdr_3)) {
        apply(forward_3);
    }
    else if (valid(myhdr_2)) {
        apply(forward_2);
    }
    else if (valid(myhdr_1)) {
        apply(forward_1);
    }
    else {
        apply(forward_0);
    }
}