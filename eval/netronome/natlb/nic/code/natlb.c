#include <nfp/mem_atomic.h>
#include <pif_plugin.h>
#include <pif_headers.h>
#include <nfp_override.h>
#include <pif_common.h>
#include <std/hash.h>
#include <nfp/me.h>


#define MIN_CURRENT_PORT_VALUE          1025
#define MAX_CURRENT_PORT_VALUE          0xFFFF
#define MAX_NUM_PUBLIC_IPS              32           /* 1,048,576 ports available */
#define BUCKET_SIZE                     16
#define STATE_TABLE_SIZE                0xFFFFF       /* 16,777,200 state table entries available */
#define STATE_TABLE_CACHE               0xFFF
#define VIP_NUM                         4096
#define LB_NUM                          256
#define CALC_BIT_TO_SET_CLR(A,k)        (A = (1 << (k % 32)) )
#define IP_ADDR(a, b, c, d)             ((a << 24) | (b << 16) | (c << 8) | d)
#define MAX_NUM_PORTS                   2048
#define TO_CPU                          1
#define TO_NIC                          0
#define TO_CACHE                        1
#define TO_MEM                          0

typedef struct bucket_entry_info {
    uint32_t flowid;
    uint32_t ip;
    uint32_t port;
    uint32_t public_private;            /* 0=none 1=public, 2=private */
    uint32_t hit_count;                 /* for timeouts */
} bucket_entry_info;


typedef struct bucket_entry {
    uint32_t key[3];                    /* ip1, ip2, ports */
    bucket_entry_info bucket_entry_info_value;
} bucket_entry;


typedef struct bucket_list {
    struct bucket_entry entry[BUCKET_SIZE];
} bucket_list;


typedef struct balancer {
    uint32_t cntr;
    uint32_t lock;
    uint32_t vip;
    uint32_t state[3];
} balancer;


__export __addr40 __imem uint32_t num_conn = 0;
__export __addr40 __imem uint32_t num_lb_process;
__export __addr40 __imem uint32_t cur_public_ip = 0;
__export __addr40 __imem uint32_t controller_clear_lock = 0;

__export __addr40 __imem uint32_t ip_per_lb = 8;
__export __addr40 __imem uint32_t num_used_public_ips = 32;

__export __addr40 __imem balancer lbs[LB_NUM];
__export __addr40 __imem uint32_t vip_cntrs[VIP_NUM];

__export __addr40 __imem uint32_t cur_port[MAX_NUM_PUBLIC_IPS];
__export __addr40 __imem uint32_t public_ips[MAX_NUM_PUBLIC_IPS];
__export __addr40 __emem uint32_t ports[MAX_NUM_PUBLIC_IPS][MAX_NUM_PORTS];
__export __addr40 __emem bucket_list state_hashtable[STATE_TABLE_SIZE];
__export __addr40 __imem bucket_list state_hashtable_cache[STATE_TABLE_CACHE];
__export __addr40 __imem uint32_t state_hashtable_locks[STATE_TABLE_SIZE >> 5];
__export __addr40 __imem uint32_t state_hashtable_locks_cache[STATE_TABLE_CACHE >> 5];

/* NAT Counters */
volatile __declspec(imem, export) uint32_t int_ext_hits = 0;
volatile __declspec(imem, export) uint32_t int_ext_drop = 0;
volatile __declspec(imem, export) uint32_t int_ext_miss = 0;
volatile __declspec(imem, export) uint32_t ext_int_drop = 0;
volatile __declspec(imem, export) uint32_t num_cache_pkt = 0;
volatile __declspec(imem, export) uint32_t num_mem_pkt = 0;
volatile __declspec(imem, export) uint32_t bucket_full_drop = 0;
volatile __declspec(imem, export) uint32_t controller_pkt_drop = 0;
volatile __declspec(imem, export) uint32_t no_port_available_drop = 0;
volatile __declspec(imem, export) uint32_t num_connection = 0;


/* Debug */
__export __addr40 __imem uint32_t nf_chain_dbg[4];
__declspec(ctm) uint64_t end_time;
__declspec(ctm) uint64_t start_time;
__declspec(ctm) uint32_t idle_time;

int pif_plugin_record_end_time(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    uint64_t delta, ctime;
    __xread uint64_t ptime;
    __xwrite uint64_t time_wr;
    PIF_PLUGIN_int_hdr_T *int_hdr = pif_plugin_hdr_get_int_hdr(headers);

    mem_read64(&ptime, &start_time, 1 << 3);
    ctime = me_tsc_read();
    delta = ctime - ptime;
    time_wr = ctime;
    mem_write64(&time_wr, &end_time, 1 << 3);
    PIF_HEADER_SET_int_hdr___exec(int_hdr, delta & 0xffffffff);

    return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_calc_idle_time(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    uint64_t delta, ctime;
    __xread uint64_t ptime;
    __xwrite uint64_t start;
    __xwrite uint32_t diff;
    PIF_PLUGIN_int_hdr_T *int_hdr = pif_plugin_hdr_get_int_hdr(headers);

    mem_read64(&ptime, &end_time, 1 << 3);
    ctime = me_tsc_read();
    delta = ctime - ptime;
    diff = delta & 0xffffffff;
    mem_write32(&diff, &idle_time, 1 << 2);
    start = ctime;
    mem_write64(&start, &start_time, 1 << 3);
    PIF_HEADER_SET_int_hdr___tx_ts(int_hdr, delta & 0xffffffff);

    return PIF_PLUGIN_RETURN_FORWARD;
}

int state_update(PIF_PLUGIN_ipv4_T *ipv4, PIF_PLUGIN_tcp_T *tcp, uint32_t hv, uint32_t pubIP, uint16_t pubPort, uint32_t flowid)
{
    uint32_t response_hash_key[3];
    volatile uint32_t response_hash_value;

    __addr40 uint32_t *key_addr;
    __xrw uint32_t tmp = 1;
    __xrw uint32_t key_val_rw[3];
    __xwrite bucket_entry_info tmp_b_info;
    __addr40 __mem bucket_entry_info *b_info;

    uint32_t i = 0;
    
    key_val_rw[0] = ipv4->srcAddr;
    key_val_rw[1] = ipv4->dstAddr;
    key_val_rw[2] = (tcp->srcPort << 16) | tcp->dstPort;

    for (; i < BUCKET_SIZE; i++)
    {
        if (ipv4->diffserv == TO_CACHE)
        {
            if (state_hashtable_cache[hv].entry[i].key[0] == 0)
            {
                b_info = &state_hashtable_cache[hv].entry[i].bucket_entry_info_value;
                key_addr = state_hashtable_cache[hv].entry[i].key;
                break;
            }
        }
        else
        {
            if (state_hashtable[hv].entry[i].key[0] == 0)
            {
                b_info = &state_hashtable[hv].entry[i].bucket_entry_info_value;
                key_addr = state_hashtable[hv].entry[i].key;
                break;
            }
        }

    }
    /* If bucket full, drop */
    if (i == BUCKET_SIZE)
    {
        mem_incr32((__mem void *)&bucket_full_drop);
        return PIF_PLUGIN_RETURN_DROP;
    }

    tmp_b_info.flowid = flowid;
    tmp_b_info.ip = pubIP;
    tmp_b_info.port = pubPort;
    tmp_b_info.public_private = 1;
    tmp_b_info.hit_count = 1;

    mem_write_atomic(&tmp_b_info, b_info, sizeof(tmp_b_info));
    mem_write_atomic(key_val_rw, key_addr, sizeof(key_val_rw));

    return PIF_PLUGIN_RETURN_FORWARD;
}

int get_public_port(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    __gpr uint32_t my_public_ip = cur_public_ip;
    __xrw uint32_t my_cur_port_xrw;
    __xrw uint32_t my_cur_ip_xrw;
    __xrw uint32_t bit_to_set_xrw;
    __xrw uint32_t init_ip;
    __xwrite uint32_t min_port_num = MIN_CURRENT_PORT_VALUE;
    __xwrite uint32_t reset_cur_ip_wr = 0;
    __gpr uint32_t bit_to_set;
    __xread uint32_t num_ip;

    uint32_t all_ports_used = 0;

    do
    {
        mem_incr32(&all_ports_used);

        if (all_ports_used > 0xFFFF)
        {
           mem_incr32((__mem void *)&no_port_available_drop);
           return PIF_PLUGIN_RETURN_DROP;
        }

        /* get the in-use bit field offset, next port to test is in cur_port */
        my_cur_port_xrw = 1;
        mem_test_add(&my_cur_port_xrw, &cur_port[my_public_ip], 1 << 2);

        if (my_cur_port_xrw > MAX_CURRENT_PORT_VALUE - 1)
            mem_write_atomic(&min_port_num, &cur_port[my_public_ip], 1 << 2);

        /* If we have a valid port number, try to set in_use */
        CALC_BIT_TO_SET_CLR(bit_to_set, my_cur_port_xrw);
        bit_to_set_xrw = bit_to_set;
        mem_test_set(&bit_to_set_xrw, &ports[my_public_ip][my_cur_port_xrw/32], 1 << 2);

        if (!(bit_to_set & bit_to_set_xrw))
        {
            /* init ip here */
            mem_read_atomic(&init_ip, &public_ips[my_public_ip], 1 << 2);
            if (init_ip == 0)
            {
                init_ip = IP_ADDR(10, 0, 0, 1) + my_public_ip;
                mem_write_atomic(&init_ip, &public_ips[my_public_ip], 1 << 2);
            }
            pif_plugin_meta_set__state_meta__ip(headers, init_ip);
            pif_plugin_meta_set__state_meta__port(headers, my_cur_port_xrw);
            break;
        }

    } while (1);

    mem_read32(&num_ip, &num_used_public_ips, 1 << 2);
    if (num_ip > 1) {
        my_public_ip += 1;
        if (my_public_ip > num_ip - 1)
            my_public_ip = 0;
        my_cur_ip_xrw = my_public_ip;
        mem_write_atomic(&my_cur_ip_xrw, &cur_public_ip, 1 << 2);
    }

    return PIF_PLUGIN_RETURN_FORWARD;
}


void load_balance(EXTRACTED_HEADERS_T *headers, uint32_t flowid)
{
    uint32_t group_id, tmp_dip, ip;
    __xrw uint32_t vip_cnt;
    __xrw uint32_t lock = 1;
    __xread balancer lb_rd;
    __xwrite balancer lb_wr;
    __xread uint32_t num_lb;
    __xread uint32_t num_ip;
    
    mem_incr32((__mem void *)&num_lb_process);

    tmp_dip = flowid & 0xfff;
    group_id = flowid & 0xff;

    vip_cnt = 1;
    mem_test_add(&vip_cnt, &vip_cntrs[tmp_dip], 1 << 2);

    mem_test_set(&lock, &lbs[group_id].lock, 1 << 2);
    while(lock == 1)
        mem_test_set(&lock, &lbs[group_id].lock, 1 << 2);
    
    mem_read_atomic(&lb_rd, &lbs[group_id], sizeof(balancer));
    lb_wr = lb_rd;
    if (vip_cnt < lb_rd.cntr)
    {
        lb_wr.cntr = vip_cnt;
        lb_wr.vip = tmp_dip;
    }
    else
    {
        if (tmp_dip == lb_rd.vip)
        {
            lb_wr.cntr = vip_cnt;
        }
        else if (group_id && lb_rd.vip == 0)
        {
            lb_wr.vip = tmp_dip;
            lb_wr.cntr = vip_cnt;
        }
    }

    lb_wr.lock = 0;
    mem_write_atomic(&lb_wr, &lbs[group_id], sizeof(balancer));

    return;
}


int pif_plugin_lookup_state(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    PIF_PLUGIN_eth_T *eth;
    PIF_PLUGIN_ipv4_T *ipv4;
    PIF_PLUGIN_tcp_T *tcp;
    volatile uint32_t origin_hash, hash_value;
    uint32_t hash_key[3], i, pubIP;
    uint32_t flowid;
	uint16_t pubPort;
    __gpr uint32_t bit_to_set;
    __addr40 uint32_t *key_addr;
	__xrw uint32_t hash_key_r[3];
    __xrw uint32_t bit_to_set_xrw;
    __addr40 bucket_entry_info *b_info;
    __xread uint32_t flag;

    eth = pif_plugin_hdr_get_eth(headers);
    ipv4 = pif_plugin_hdr_get_ipv4(headers);
    tcp = pif_plugin_hdr_get_tcp(headers);

    /* TODO: Add another field to indicate direction ?*/
    hash_key[0] = ipv4->srcAddr;
    hash_key[1] = ipv4->dstAddr;
    hash_key[2] = (tcp->srcPort << 16) | tcp->dstPort;
    flowid = tcp->seqNo;
	
    origin_hash = hash_me_crc32((void *)hash_key, sizeof(hash_key), 1);
    if (ipv4->diffserv == TO_CACHE)
    {
        hash_value = origin_hash & (STATE_TABLE_CACHE);
        mem_incr32((__mem void *)&num_cache_pkt);
    }
    else
    {
        hash_value = origin_hash & (STATE_TABLE_SIZE);
        mem_incr32((__mem void *)&num_mem_pkt);
    }
    
    for (i = 0; i < BUCKET_SIZE; i++)
    {
		/* TODO: Read whole bunch at a time */
        if (ipv4->diffserv == TO_CACHE)
            key_addr = state_hashtable_cache[hash_value].entry[i].key;
        else
            key_addr = state_hashtable[hash_value].entry[i].key;
		mem_read_atomic(hash_key_r, key_addr, sizeof(hash_key_r));
		
        if (hash_key_r[0] == 0) 
        {
            continue;
        }
        
        if (hash_key_r[0] == hash_key[0] &&
            hash_key_r[1] == hash_key[1] &&
            hash_key_r[2] == hash_key[2])
        {
            /* Hit */
            __xrw uint32_t count;

            if (ipv4->diffserv == TO_CACHE)
                b_info = &state_hashtable_cache[hash_value].entry[i].bucket_entry_info_value;
            else
                b_info = &state_hashtable[hash_value].entry[i].bucket_entry_info_value;
            pif_plugin_meta_set__state_meta__ip(headers, b_info->ip);
            pif_plugin_meta_set__state_meta__port(headers, b_info->port);

            count = 1;
            mem_test_add(&count, &b_info->hit_count, 1 << 2);
            if (count == 0xFFFFFFFF - 1)
            {
                /* Never incr to 0 or 2^32 */
                count = 2;
                mem_add32(&count, &b_info->hit_count, 1 << 2);
            }
            else if (count == 0xFFFFFFFF)
            {
                mem_incr32(&b_info->hit_count);
            }
            mem_incr32((__mem void *)&int_ext_hits);

            if (ipv4->ttl == TO_NIC)
            {
                load_balance(headers, b_info->flowid);
                // Send to the wire
                PIF_HEADER_SET_eth___dstAddr___1(eth, 0x2211);
            }

            return PIF_PLUGIN_RETURN_FORWARD;
        }
    }

    if (pif_plugin_meta_get__state_meta__incoming_port(headers) == 1) 
    {  
        /* Ext_Int_Miss -> Drop */
        mem_incr32((__mem void *)&ext_int_drop);
        return PIF_PLUGIN_RETURN_DROP;
    } 
    else
    {
        /* Int_Ext_Miss -> Assign port and update state table */
        CALC_BIT_TO_SET_CLR(bit_to_set, hash_value);
        bit_to_set_xrw = bit_to_set;
        if (ipv4->diffserv == TO_CACHE)
            mem_test_set(&bit_to_set_xrw, &state_hashtable_locks_cache[hash_value / 32], 1 << 2);
        else
            mem_test_set(&bit_to_set_xrw, &state_hashtable_locks[hash_value / 32], 1 << 2);
        if (!(bit_to_set & bit_to_set_xrw))
        {
            mem_incr32((__mem void *)&int_ext_miss);

            if (get_public_port(headers, match_data) == PIF_PLUGIN_RETURN_DROP)
            { 
                return PIF_PLUGIN_RETURN_DROP;
            }

            pubIP = pif_plugin_meta_get__state_meta__ip(headers);
            pubPort = pif_plugin_meta_get__state_meta__port(headers);
            
            if (state_update(ipv4, tcp, hash_value, pubIP, pubPort, flowid) == PIF_PLUGIN_RETURN_DROP)
            {
                return PIF_PLUGIN_RETURN_DROP;
            }
            if (ipv4->diffserv == TO_CACHE)
                mem_test_clr(&bit_to_set_xrw, &state_hashtable_locks_cache[hash_value / 32], 1 << 2);
            else
                mem_test_clr(&bit_to_set_xrw, &state_hashtable_locks[hash_value / 32], 1 << 2);

        }
        else
        {
            mem_incr32((__mem void *)&int_ext_drop);
            return PIF_PLUGIN_RETURN_DROP;
        }
    }

    return PIF_PLUGIN_RETURN_FORWARD;
}