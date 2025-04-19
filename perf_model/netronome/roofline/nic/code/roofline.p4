// Roofline
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
        tstamp : 48;
        info : 64;
    }
}

header eth_t eth;
metadata intrinsic_metadata_t intrinsic_metadata;
// primitive_action single_me();
// primitive_action single_me_mem();
// primitive_action single_thread();
// primitive_action ordinary();
// primitive_action ordinary_mem();
// primitive_action mem_cache();
// primitive_action mem_opt();
primitive_action alu_opt();

parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(eth);
    return ingress;
}

action do_forward(prt) {
	modify_field(standard_metadata.egress_spec, prt);
    // single_me();
    // single_me_mem();
    // single_thread();
    // ordinary();
    // ordinary_mem();
    // mem_cache();
    // mem_opt();
    alu_opt();
}

table forward {
	reads {
		eth.dstAddr : exact;
	}
	actions {
		do_forward;
	}
}

control ingress {
	apply(forward);
}