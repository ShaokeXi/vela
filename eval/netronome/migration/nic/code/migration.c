#include <stdint.h>
#include <memory.h>
#include <nfp/me.h>
#include <std/hash.h>
#include <pif_common.h>
#include <pif_plugin.h>
#include <pif_headers.h>
#include <nfp_override.h>
#include <nfp/mem_atomic.h>

#define MIN_CURRENT_PORT_VALUE          1025
#define MAX_CURRENT_PORT_VALUE          0xFFFF
#define MAX_NUM_PUBLIC_IPS              4096        /* 1,048,576 ports available */
#define BUCKET_SIZE                     16
#define MEM_TABLE_SIZE                  0xFFFF
#define STATE_TABLE_SIZE                0xFFFFF     /* 16,777,200 state table entries available */
#define CALC_BIT_TO_SET_CLR(A,k)        (A = (1 << (k % 32)) )
#define IP_ADDR(a, b, c, d)             ((a << 24) | (b << 16) | (c << 8) | d)
#define MAX_NUM_PORTS                   2048
#define SKETCH_MASK                     0x3FF
#define VIP_MASK                        0x1FFF
#define LB_MASK                         0xFFF
#define true                            1
#define false                           0
#define PIF_32_BIT_XFR_LW               32
#define PIF_32_BIT_XFR_BYTES            ((PIF_32_BIT_XFR_LW) * 4)
#define IDLE_UPDATE_THRESHOLD           1000000

typedef struct bucket_state {
    uint32_t state;                     /* 0=invalid, 1=valid */
    uint32_t espec;                     /* vf:0x30X, pf:0x00X */
} bucket_state;


typedef struct bucket_entry_info {
    bucket_state bState;
    uint32_t ip;
    uint32_t port;
    uint32_t hit_count;                 /* for timeouts */
} bucket_entry_info;


typedef struct bucket_entry {
    uint32_t key[3];                    /* ip1, ip2, ports */
    bucket_entry_info bucket_entry_info_value;
} bucket_entry;


typedef struct bucket_list {
    struct bucket_entry entry[BUCKET_SIZE];
} bucket_list;


struct heavy_hitter {
    uint32_t bucket;
    uint32_t index;
    uint32_t count;
};


typedef struct balancer {
    uint32_t cntr;
    uint32_t lock;
    uint32_t vip;
    uint32_t state;
} balancer;


// typedef struct monitor
// {
//     uint64_t idle_time;
//     uint64_t last_update;
// } monitor;

enum {
    STABLE,
    OVERLOAD,
    AVAILABLE
};

enum {
    INVALID,
    VALID,
    TO_CPU,
    TO_NIC,
    INITIAL
};

enum {
    CTRL_RD_BATCH = 1233,
	CTRL_MONITOR,
	CTRL_TO_CPU,
    CTRL_EVICT,
	CTRL_TO_NIC,
    CTRL_OFFLOAD,
    CTRL_PIGGYBACK,
    CTRL_FLAG,
    PKT_TO_CPU,
    PKT_TO_NIC,
    PKT_INIT
};

/* NAT */
__export __addr40 __imem uint32_t cur_port[MAX_NUM_PUBLIC_IPS];
__export __addr40 __imem uint32_t public_ips[MAX_NUM_PUBLIC_IPS];
__export __addr40 __emem uint32_t ports[MAX_NUM_PUBLIC_IPS][MAX_NUM_PORTS];
__export __addr40 __emem bucket_list state_hashtable[STATE_TABLE_SIZE];
__export __addr40 __emem bucket_list state_memtable[MEM_TABLE_SIZE];
__export __addr40 __imem uint32_t state_hashtable_locks[STATE_TABLE_SIZE >> 5];
__export __addr40 __imem uint32_t state_memtable_locks[MEM_TABLE_SIZE >> 5];
__export __addr40 __imem uint32_t cur_public_ip = 0;
__export __addr40 __imem uint32_t num_used_public_ips = 32;

/* LB */
__export __addr40 __imem balancer lbs[LB_MASK+1];
__export __addr40 __imem uint32_t vip_cntrs[VIP_MASK+1];

/* NAT Counters */
volatile __declspec(imem, export) uint32_t int_ext_hits = 0;
volatile __declspec(imem, export) uint32_t int_ext_drop = 0;
volatile __declspec(imem, export) uint32_t int_ext_miss = 0;
volatile __declspec(imem, export) uint32_t ext_int_drop = 0;
volatile __declspec(imem, export) uint32_t pkt_to_cpu = 0;
volatile __declspec(imem, export) uint32_t pkt_to_nic = 0;
volatile __declspec(imem, export) uint32_t migrate_read = 0;
volatile __declspec(imem, export) uint32_t migrate_to_cpu = 0;
volatile __declspec(imem, export) uint32_t migrate_to_nic = 0;
volatile __declspec(imem, export) uint32_t migrate_evict = 0;
volatile __declspec(imem, export) uint32_t migrate_offload = 0;
volatile __declspec(imem, export) uint32_t migrate_flag = 0;
volatile __declspec(imem, export) uint32_t piggyback = 0;
volatile __declspec(imem, export) uint32_t pkt_init = 0;
volatile __declspec(imem, export) uint32_t bucket_full_drop = 0;
volatile __declspec(imem, export) uint32_t no_port_available_drop = 0;
volatile __declspec(imem, export) uint32_t state_nat = 0;

/* MEMCACHED Counters */
volatile __declspec(imem, export) uint32_t mem_ext_hits = 0;
volatile __declspec(imem, export) uint32_t mem_ext_drop = 0;
volatile __declspec(imem, export) uint32_t mem_ext_miss = 0;
volatile __declspec(imem, export) uint32_t ext_mem_drop = 0;
volatile __declspec(imem, export) uint32_t mem_pkt_to_cpu = 0;
volatile __declspec(imem, export) uint32_t mem_pkt_to_nic = 0;
volatile __declspec(imem, export) uint32_t mem_migrate_read = 0;
volatile __declspec(imem, export) uint32_t mem_migrate_to_cpu = 0;
volatile __declspec(imem, export) uint32_t mem_migrate_to_nic = 0;
volatile __declspec(imem, export) uint32_t mem_migrate_evict = 0;
volatile __declspec(imem, export) uint32_t mem_migrate_offload = 0;
volatile __declspec(imem, export) uint32_t mem_migrate_flag = 0;
volatile __declspec(imem, export) uint32_t mem_piggyback = 0;
volatile __declspec(imem, export) uint32_t mem_pkt_init = 0;
volatile __declspec(imem, export) uint32_t mem_bucket_full_drop = 0;
volatile __declspec(imem, export) uint32_t state_mem = 0;

/* LB Counters */
volatile __declspec(imem, export) uint32_t state_lb = 0;

/* Local Sketch in CTM */
__declspec(ctm, export scope(island)) uint32_t mem_sketch[3][SKETCH_MASK+1];
__declspec(ctm, export scope(island)) uint32_t nat_sketch[3][SKETCH_MASK+1];
__declspec(ctm, export scope(island)) struct heavy_hitter mem_sketch_hitter[128];
__declspec(ctm, export scope(island)) struct heavy_hitter nat_sketch_hitter[128];
// __declspec(ctm, export scope(island)) struct heavy_hitter eviction[128];
__declspec(ctm) uint64_t end_time;
__declspec(ctm) uint32_t idle_time;
// __declspec(ctm, shared) monitor me_monitor;

/* Debug */
__export __mem uint32_t flag;
__export __mem uint32_t espec_num = 8;
// __export __mem uint32_t expiration = 75000000 * 60;
__export __mem uint32_t dbg_migrate[16];

int pif_plugin_record_end_time(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    __xwrite uint64_t ctime;

    ctime = me_tsc_read();
    mem_write64(&ctime, &end_time, 1 << 3);

    return PIF_PLUGIN_RETURN_FORWARD;
}


int pif_plugin_calc_idle_time(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    uint64_t delta, ctime;
    __xread uint64_t ptime;
    // __xread monitor m_rd;
    // __xwrite monitor m_wr;
    __xwrite uint32_t diff;
    // PIF_PLUGIN_int_hdr_T *int_hdr = pif_plugin_hdr_get_int_hdr(headers);

    /* Get the time at parsing from the intrinsic metadata timestamp
     * Note that we do this in two parts __0 being the 32 lsbs and __1 the 16
     * msbs
     */
    // ptime = pif_plugin_meta_get__intrinsic_metadata__ingress_global_tstamp__0(headers);
    // ptime |= ((uint64_t)pif_plugin_meta_get__intrinsic_metadata__ingress_global_tstamp__1(headers)) << 32;
    mem_read64(&ptime, &end_time, 1 << 3);
    // mem_read_atomic(&m_rd, &me_monitor, 1 << 4);
    ctime = me_tsc_read();
    delta = ctime - ptime;
    diff = delta & 0xffffffff;
    mem_write32(&diff, &idle_time, 1 << 2);
    // if (ctime - m_rd.last_update > IDLE_UPDATE_THRESHOLD)
    // {
    //     m_wr.last_update = ctime;
    //     m_wr.idle_time = delta;
    //     mem_write_atomic(&m_wr, &me_monitor, 1 << 4);
    // }
    // else if (delta < m_rd.idle_time)
    // {
    //     m_wr.last_update = m_rd.last_update;
    //     m_wr.idle_time = delta;
    //     mem_write_atomic(&m_wr, &me_monitor, 1 << 4);
    // }
    // PIF_HEADER_SET_int_hdr___info(int_hdr, CTRL_IDLE);
    // PIF_HEADER_SET_int_hdr___idle(int_hdr, delta & 0xffffffff);

    return PIF_PLUGIN_RETURN_FORWARD;
}


int state_update(PIF_PLUGIN_ipv4_T *ipv4, PIF_PLUGIN_tcp_T *tcp, uint32_t hv, uint32_t pubIP, uint16_t pubPort)
{
    uint32_t response_hash_key[3];
    volatile uint32_t response_hash_value;

    __addr40 uint32_t *key_addr;
    __xread uint32_t tmp_r;
    __xrw uint32_t key_val_rw[3];
    __xwrite bucket_entry_info tmp_b_info;
    __addr40 __emem bucket_entry_info *b_info;

    uint32_t i = 0;
    
    key_val_rw[0] = ipv4->srcAddr;
    key_val_rw[1] = ipv4->dstAddr;
    key_val_rw[2] = (tcp->srcPort << 16) | tcp->dstPort;

    for (; i < BUCKET_SIZE; i++)
    {
        if (state_hashtable[hv].entry[i].key[0] == 0)
        {
            b_info = &state_hashtable[hv].entry[i].bucket_entry_info_value;
            key_addr = state_hashtable[hv].entry[i].key;
            break;
        }
    }
    /* If bucket full, drop */
    if (i == BUCKET_SIZE)
    {
        mem_incr32((__mem void *)&bucket_full_drop);
        return PIF_PLUGIN_RETURN_DROP;
    }

    tmp_b_info.bState.state = INITIAL;
    tmp_b_info.ip = pubIP;
    tmp_b_info.port = pubPort;
    mem_read32(&tmp_r, &espec_num, 1 << 2);
    tmp_b_info.bState.espec = (hv & (tmp_r - 1)) | 0x300;
    tmp_b_info.hit_count = 1;

    mem_write_atomic(&tmp_b_info, b_info, sizeof(tmp_b_info));
    mem_write_atomic(key_val_rw, key_addr, sizeof(key_val_rw));

    return PIF_PLUGIN_RETURN_FORWARD;
}


int mem_state_update(PIF_PLUGIN_memcached_hdr_T *memcached, uint32_t hv, uint32_t pubIP, uint16_t pubPort)
{
    __addr40 uint32_t *key_addr;
    __xread uint32_t tmp_r;
    __xrw uint32_t key_val_rw;
    __xwrite bucket_entry_info tmp_b_info;
    __addr40 __emem bucket_entry_info *b_info;

    uint32_t i = 0;
    
    key_val_rw = memcached->key;

    for (; i < BUCKET_SIZE; i++)
    {
        if (state_memtable[hv].entry[i].key[0] == 0)
        {
            b_info = &state_memtable[hv].entry[i].bucket_entry_info_value;
            key_addr = state_memtable[hv].entry[i].key;
            break;
        }
    }
    /* If bucket full, drop */
    if (i == BUCKET_SIZE)
    {
        mem_incr32((__mem void *)&bucket_full_drop);
        return PIF_PLUGIN_RETURN_DROP;
    }

    tmp_b_info.bState.state = INITIAL;
    tmp_b_info.ip = pubIP;
    tmp_b_info.port = pubPort;
    mem_read32(&tmp_r, &espec_num, 1 << 2);
    tmp_b_info.bState.espec = (hv & (tmp_r - 1)) | 0x300;
    tmp_b_info.hit_count = 1;

    mem_write_atomic(&tmp_b_info, b_info, sizeof(tmp_b_info));
    mem_write_atomic(&key_val_rw, key_addr, sizeof(key_val_rw));

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
    
    tmp_dip = flowid & VIP_MASK;    
    group_id = flowid & LB_MASK;

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

    mem_incr32((__mem void *)&state_lb);

    return;
}


int pif_plugin_lookup_state(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    PIF_PLUGIN_ipv4_T *ipv4;
    PIF_PLUGIN_tcp_T *tcp;
    PIF_PLUGIN_int_hdr_T *int_hdr;

    volatile uint32_t update;
    volatile uint32_t hash_value, hv[3];
    uint32_t espec;
    uint32_t hash_key[3], i, pubIP;
	uint16_t pubPort;
    __gpr uint32_t bit_to_set;
    __addr40 uint32_t *key_addr;
	__xrw uint32_t hash_key_r[3];
    __xrw uint32_t bit_to_set_xrw;
    __addr40 bucket_entry_info *b_info;
    int tid = __ctx() + 8 * ((__ME() & 0x0f) - 4);

    __xread uint32_t sig;
    __addr40 bucket_entry_info *tmp_b;
    __xrw uint32_t count, tmp_v;
    __xrw uint32_t sketch_count, sketch_min;
    __xread struct heavy_hitter hitter_rd;
    __xwrite struct heavy_hitter hitter_wr;

    ipv4 = pif_plugin_hdr_get_ipv4(headers);
    tcp = pif_plugin_hdr_get_tcp(headers);
    int_hdr = pif_plugin_hdr_get_int_hdr(headers);

    hash_key[0] = ipv4->srcAddr;
    hash_key[1] = ipv4->dstAddr;
    hash_key[2] = (tcp->srcPort << 16) | tcp->dstPort;
	
    hash_value = hash_me_crc32((void *)hash_key, sizeof(hash_key), 1);
    hash_value &= (STATE_TABLE_SIZE);
    
    mem_incr32((__mem void *)&state_nat);

    for (i = 0; i < BUCKET_SIZE; i++)
    {
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
            mem_read32(&sig, &flag, 1 << 2);
            /* Hit */
            b_info = &state_hashtable[hash_value].entry[i].bucket_entry_info_value;
            if (b_info->bState.state == VALID)
            {
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
            
                hv[0] = hash_value & SKETCH_MASK;
                hv[1] = hash_me_crc32((void *)hash_key, sizeof(hash_key), 222) & SKETCH_MASK;
                hv[2] = hash_me_crc32((void *)hash_key, sizeof(hash_key), 333) & SKETCH_MASK;

                /* Update CTM Sketch */
                mem_read32(&sketch_count, &nat_sketch[0][hv[0]], 1 << 2);
                sketch_count += 1;
                mem_write32(&sketch_count, &nat_sketch[0][hv[0]], 1 << 2);
                sketch_min = sketch_count;
                mem_read32(&sketch_count, &nat_sketch[1][hv[1]], 1 << 2);
                sketch_count += 1;
                mem_write32(&sketch_count, &nat_sketch[1][hv[1]], 1 << 2);
                sketch_min = sketch_min > sketch_count ? sketch_count : sketch_min;
                mem_read32(&sketch_count, &nat_sketch[2][hv[2]], 1 << 2);
                sketch_count += 1;
                mem_write32(&sketch_count, &nat_sketch[2][hv[2]], 1 << 2);
                sketch_min = sketch_min > sketch_count ? sketch_count : sketch_min;
                mem_read32(&sketch_count, &nat_sketch_hitter[tid].count, 1 << 2);
                if (sketch_count < sketch_min)
                {
                    hitter_wr.count = sketch_min;
                    hitter_wr.bucket = hash_value;
                    hitter_wr.index = i;
                    mem_write32(&hitter_wr, &nat_sketch_hitter[tid], sizeof(hitter_wr));
                }

                /* Update Migration Queue */
                // if (sig == OVERLOAD)
                // {
                //     mem_read32(&hitter_rd, &eviction[tid], sizeof(hitter_rd));
                //     if (hitter_rd.count == 0)
                //     {
                //         update = true;
                //     }
                //     else
                //     {
                //         tmp_b = &state_hashtable[hitter_rd.bucket].entry[hitter_rd.index].bucket_entry_info_value;
                //         mem_read32(&tmp_v, &tmp_b->state, 1 << 2);
                //         if (tmp_v == INVALID)
                //         {
                //             update = true;
                //         }
                //     }
                //     if (update == true)
                //     {
                //         mem_read32(&hitter_rd, &sketch_hitter[tid], sizeof(hitter_rd));
                //         hitter_wr = hitter_rd;
                //         mem_write32(&hitter_wr, &eviction[tid], sizeof(hitter_wr));
                //         tmp_b = &state_hashtable[hitter_rd.bucket].entry[hitter_rd.index].bucket_entry_info_value;
                //         mem_read32(&tmp_v, &tmp_b->espec, 1 << 2);
                //         tmp_v |= 0x300;
                //         mem_write32(&tmp_v, &tmp_b->espec, 1 << 2);
                //         tmp_v = TO_CPU;
                //         mem_write32(&tmp_v, &tmp_b->state, 1 << 2);
                //         mem_incr32((__mem void *)&new_migrate);
                //     }
                //     mem_incr32(&dbg_migrate[6]);
                // }
                load_balance(headers, hash_value);
            }
            else if (b_info->bState.state == TO_CPU)
            {
                mem_incr32((__mem void *)&pkt_to_cpu);
                PIF_HEADER_SET_int_hdr___opt(int_hdr, PKT_TO_CPU);
            }
            else if (b_info->bState.state == TO_NIC)
            {
                /* Block matching by ping-pong packets */
                mem_incr32((__mem void *)&pkt_to_nic);
                PIF_HEADER_SET_int_hdr___opt(int_hdr, PKT_TO_NIC);
            }
            else if (b_info->bState.state == INVALID)
            {
                /* Piggyback heavy hitter of the current thread */
                PIF_HEADER_SET_int_hdr___opt(int_hdr, CTRL_PIGGYBACK);
                // PIF_HEADER_SET_int_hdr___bucket(int_hdr, eviction[tid].bucket);
                // PIF_HEADER_SET_int_hdr___index(int_hdr, eviction[tid].index);
                PIF_HEADER_SET_int_hdr___idle(int_hdr, idle_time);
                PIF_HEADER_SET_int_hdr___bucket(int_hdr, nat_sketch_hitter[tid].bucket);
                PIF_HEADER_SET_int_hdr___index(int_hdr, nat_sketch_hitter[tid].index);
                mem_incr32((__mem void *)&piggyback);
            }
            else if (b_info->bState.state == INITIAL)
            {
                PIF_HEADER_SET_int_hdr___opt(int_hdr, PKT_INIT);
                PIF_HEADER_SET_int_hdr___bucket(int_hdr, hash_value);
                PIF_HEADER_SET_int_hdr___index(int_hdr, i);
                PIF_HEADER_SET_int_hdr___idle(int_hdr, hash_key[0]);
                PIF_HEADER_SET_int_hdr___flag(int_hdr, hash_key[1]);
                PIF_HEADER_SET_int_hdr___cnt(int_hdr, hash_key[2]);
                pif_plugin_meta_set__standard_metadata__egress_spec(headers, b_info->bState.espec);
                mem_incr32((__mem void *)&pkt_init);
                return PIF_PLUGIN_RETURN_FORWARD;
            }

            /* Set the egress port */
            PIF_HEADER_SET_int_hdr___flag(int_hdr, sig);
            pif_plugin_meta_set__standard_metadata__egress_spec(headers, b_info->bState.espec);
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
            
            if (state_update(ipv4, tcp, hash_value, pubIP, pubPort) == PIF_PLUGIN_RETURN_DROP)
            {
                return PIF_PLUGIN_RETURN_DROP;
            }
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


int pif_plugin_netcache(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    PIF_PLUGIN_ipv4_T *ipv4;
    PIF_PLUGIN_udp_T *udp;
    PIF_PLUGIN_memcached_hdr_T *memcached;

    volatile uint32_t hash_value, hv[3];
    uint32_t espec;
    uint32_t i, pubIP;
	uint16_t pubPort;
    uint32_t hash_key;
    __gpr uint32_t bit_to_set;
    __addr40 uint32_t *key_addr;
	__xrw uint32_t hash_key_r[3];
    __xrw uint32_t bit_to_set_xrw;
    __addr40 bucket_entry_info *b_info;
    int tid = __ctx() + 8 * ((__ME() & 0x0f) - 4);

    uint32_t sketch_min;
    __xread uint32_t sig;
    __addr40 bucket_entry_info *tmp_b;
    __xrw uint32_t count, tmp_v;
    __xrw uint32_t sketch_count;
    __xread struct heavy_hitter hitter_rd;
    __xwrite struct heavy_hitter hitter_wr;

    ipv4 = pif_plugin_hdr_get_ipv4(headers);
    udp = pif_plugin_hdr_get_udp(headers);
    memcached = pif_plugin_hdr_get_memcached_hdr(headers);
	
    hash_key = memcached->key;
    hash_value = hash_me_crc32((void *)&hash_key, 1 << 2, 1);
    hash_value &= (MEM_TABLE_SIZE);
    
    mem_incr32((__mem void *)&state_mem);

    for (i = 0; i < BUCKET_SIZE; i++)
    {
		key_addr = state_memtable[hash_value].entry[i].key;
		mem_read_atomic(hash_key_r, key_addr, sizeof(hash_key_r));
		
        if (hash_key_r[0] == 0) 
        {
            continue;
        }
        
        if (hash_key_r[0] == hash_key)
        {
            mem_read32(&sig, &flag, 1 << 2);
            /* Hit */
            b_info = &state_memtable[hash_value].entry[i].bucket_entry_info_value;
            if (b_info->bState.state == VALID)
            {
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
                mem_incr32((__mem void *)&mem_ext_hits);
            
                hv[0] = hash_value & SKETCH_MASK;
                hv[1] = hash_me_crc32((void *)&hash_key, 1 << 2, 222) & SKETCH_MASK;
                hv[2] = hash_me_crc32((void *)&hash_key, 1 << 2, 333) & SKETCH_MASK;

                /* Update CTM Sketch */
                mem_read32(&sketch_count, &mem_sketch[0][hv[0]], 1 << 2);
                sketch_count += 1;
                mem_write32(&sketch_count, &mem_sketch[0][hv[0]], 1 << 2);
                sketch_min = sketch_count;
                mem_read32(&sketch_count, &mem_sketch[1][hv[1]], 1 << 2);
                sketch_count += 1;
                mem_write32(&sketch_count, &mem_sketch[1][hv[1]], 1 << 2);
                sketch_min = sketch_min > sketch_count ? sketch_count : sketch_min;
                mem_read32(&sketch_count, &mem_sketch[2][hv[2]], 1 << 2);
                sketch_count += 1;
                mem_write32(&sketch_count, &mem_sketch[2][hv[2]], 1 << 2);
                sketch_min = sketch_min > sketch_count ? sketch_count : sketch_min;
                mem_read32(&sketch_count, &mem_sketch_hitter[tid].count, 1 << 2);
                if (sketch_count < sketch_min)
                {
                    hitter_wr.count = sketch_min;
                    hitter_wr.bucket = hash_value;
                    hitter_wr.index = i;
                    mem_write32(&hitter_wr, &mem_sketch_hitter[tid], sizeof(hitter_wr));
                }
            }
            else if (b_info->bState.state == TO_CPU)
            {
                mem_incr32((__mem void *)&mem_pkt_to_cpu);
                PIF_HEADER_SET_memcached_hdr___opt(memcached, PKT_TO_CPU);
            }
            else if (b_info->bState.state == TO_NIC)
            {
                /* Block matching by ping-pong packets */
                mem_incr32((__mem void *)&mem_pkt_to_nic);
                PIF_HEADER_SET_memcached_hdr___opt(memcached, PKT_TO_NIC);
            }
            else if (b_info->bState.state == INVALID)
            {
                /* Piggyback heavy hitter of the current thread */
                PIF_HEADER_SET_memcached_hdr___opt(memcached, CTRL_PIGGYBACK);
                PIF_HEADER_SET_memcached_hdr___idle(memcached, idle_time);
                PIF_HEADER_SET_memcached_hdr___bucket(memcached, mem_sketch_hitter[tid].bucket);
                PIF_HEADER_SET_memcached_hdr___index(memcached, mem_sketch_hitter[tid].index);
                mem_incr32((__mem void *)&mem_piggyback);
            }
            else if (b_info->bState.state == INITIAL)
            {
                PIF_HEADER_SET_memcached_hdr___opt(memcached, PKT_INIT);
                PIF_HEADER_SET_memcached_hdr___bucket(memcached, hash_value);
                PIF_HEADER_SET_memcached_hdr___index(memcached, i);
                PIF_HEADER_SET_memcached_hdr___idle(memcached, hash_key);
                PIF_HEADER_SET_memcached_hdr___flag(memcached, 0);
                PIF_HEADER_SET_memcached_hdr___cnt(memcached, 0);
                pif_plugin_meta_set__standard_metadata__egress_spec(headers, b_info->bState.espec);
                mem_incr32((__mem void *)&mem_pkt_init);
                return PIF_PLUGIN_RETURN_FORWARD;
            }

            /* Set the egress port */
            PIF_HEADER_SET_memcached_hdr___flag(memcached, sig);
            pif_plugin_meta_set__standard_metadata__egress_spec(headers, b_info->bState.espec);
            return PIF_PLUGIN_RETURN_FORWARD;
        }
    }

    if (pif_plugin_meta_get__state_meta__incoming_port(headers) == 1)
    {  
        /* Ext_Int_Miss -> Drop */
        mem_incr32((__mem void *)&ext_mem_drop);
        return PIF_PLUGIN_RETURN_DROP;
    } 
    else 
    { 
        /* Int_Ext_Miss -> Assign port and update state table */
        CALC_BIT_TO_SET_CLR(bit_to_set, hash_value);
        bit_to_set_xrw = bit_to_set;
        mem_test_set(&bit_to_set_xrw, &state_memtable_locks[hash_value / 32], 1 << 2);
        if (!(bit_to_set & bit_to_set_xrw))
        {
            mem_incr32((__mem void *)&mem_ext_miss);
            pubIP = pubPort = 0;
            if (mem_state_update(memcached, hash_value, pubIP, pubPort) == PIF_PLUGIN_RETURN_DROP)
            {
                return PIF_PLUGIN_RETURN_DROP;
            }
            mem_test_clr(&bit_to_set_xrw, &state_memtable_locks[hash_value / 32], 1 << 2);
        }
        else
        {
            mem_incr32((__mem void *)&mem_ext_drop);
            return PIF_PLUGIN_RETURN_DROP;
        }
    }

    return PIF_PLUGIN_RETURN_FORWARD;
}


// void mu_copy(__mem void *src, __mem void *dst, int size)
// {
//     int cnt = 0;
//     __xread uint32_t r_data;
//     __xwrite uint32_t w_data;
//     __mem uint8_t *srcPtr = (__mem uint8_t *)src;
//     __mem uint8_t *dstPtr = (__mem uint8_t *)dst;

//     while (size)
//     {
//         mem_read32(&r_data, (__mem void *)srcPtr, 1 << 2);
//         w_data = r_data;
//         mem_write32(&w_data, (__mem void *)dstPtr, 1 << 2);
//         size -= 4;
//         srcPtr += 4;
//         dstPtr += 4;
//         mem_incr32(&dbg_migrate[4]);
//     }

//     return;
// }

int pif_plugin_migrate_state(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    uint32_t espec, opt;
    __xread uint32_t state_rd;
    __xwrite bucket_state state_wr;
    __xwrite bucket_entry entry_wr = {0};
    PIF_PLUGIN_ipv4_T *ipv4;
    PIF_PLUGIN_int_hdr_T *int_hdr;
    PIF_PLUGIN_memcached_hdr_T *memcached;
    __addr40 bucket_entry_info *tmp_b;
    __addr40 bucket_entry *b_info;
 
    ipv4 = pif_plugin_hdr_get_ipv4(headers);
    if (ipv4->protocol == 6)
    {
        int_hdr = pif_plugin_hdr_get_int_hdr(headers);
        opt = int_hdr->opt;
        tmp_b = &state_hashtable[int_hdr->bucket].entry[int_hdr->index].bucket_entry_info_value;
    }
    else if (ipv4->protocol == 17)
    {
        memcached = pif_plugin_hdr_get_memcached_hdr(headers);
        opt = memcached->opt;
        tmp_b = &state_memtable[memcached->bucket].entry[memcached->index].bucket_entry_info_value;
    }

    if (opt == CTRL_MONITOR)
    {
        /* Read one single state */
        int tid = __ctx() + 8 * ((__ME() & 0x0f) - 4);
        if (ipv4->protocol == 6)
        {
            mem_read32(&state_rd, (__mem void *)&state_nat, 1 << 2);
            PIF_HEADER_SET_int_hdr___cnt(int_hdr, state_rd);
            PIF_HEADER_SET_int_hdr___idle(int_hdr, idle_time);
            PIF_HEADER_SET_int_hdr___bucket(int_hdr, nat_sketch_hitter[tid].bucket);
            PIF_HEADER_SET_int_hdr___index(int_hdr, nat_sketch_hitter[tid].index);
        }
        else if (ipv4->protocol == 17)
        {
            mem_read32(&state_rd, (__mem void *)&state_mem, 1 << 2);
            PIF_HEADER_SET_memcached_hdr___cnt(memcached, state_rd);
            PIF_HEADER_SET_memcached_hdr___idle(memcached, idle_time);
            PIF_HEADER_SET_memcached_hdr___bucket(memcached, mem_sketch_hitter[tid].bucket);
            PIF_HEADER_SET_memcached_hdr___index(memcached, mem_sketch_hitter[tid].index);
        }
        /* Read entire states of the whole island */
        // int ctm_len, mu_len, ev_len;
        // __mem __addr40 uint8_t *payload;
        // __mem __addr40 uint8_t *evictPtr = (__mem __addr40 uint8_t *)eviction;
        // ev_len = sizeof(struct heavy_hitter) * 96;
        // if (pkt.p_is_split) { /* payload split to MU */
        //     mu_len = pkt.p_len - (256 << pkt.p_ctm_size) + pkt.p_offset;
        // }
        // else { /* no data in MU */
        //     mu_len = 0;
        // }
        // ctm_len = pkt.p_len - pif_pkt_info_spec.pkt_pl_off - mu_len;
        // state_wr = ctm_len;
        // mem_write32(&state_wr, &dbg_migrate[2], 1 << 2);
        // state_wr = mu_len;
        // mem_write32(&state_wr, &dbg_migrate[3], 1 << 2);
        // payload = pkt.p_offset + (__mem __addr40 uint8_t *)pkt_ctm_ptr40(__ISLAND, pkt.p_pnum, 0);
        // payload += pif_pkt_info_spec.pkt_pl_off;
        // mu_copy(evictPtr, payload, ctm_len);
        // payload = (__addr40 void *)((uint64_t)pkt.p_muptr << 11);
        // payload += 256 << pkt.p_ctm_size;
        // evictPtr += ctm_len;
        // ev_len -= ctm_len;
        // mu_copy(evictPtr, payload, ev_len);

        mem_incr32((__mem void *)&migrate_read);
    }
    else if (opt == CTRL_TO_CPU)
    {
        state_wr.state = TO_CPU;
        state_wr.espec = tmp_b->bState.espec | 0x300;
        mem_write_atomic(&state_wr, &tmp_b->bState, sizeof(bucket_state));
        mem_incr32((__mem void *)&migrate_to_cpu);
    }
    else if (opt == CTRL_EVICT)
    {
        /* Heavy hitter evict */
        state_wr.state = INVALID;
        state_wr.espec = tmp_b->bState.espec | 0x300;
        mem_write_atomic(&state_wr, &tmp_b->bState, sizeof(bucket_state));
        mem_incr32((__mem void *)&migrate_evict);
    }
    else if (opt == CTRL_TO_NIC)
    {
        state_wr.state = TO_NIC;
        // state_wr.espec = tmp_b->bState.espec & 0x3;
        mem_write_atomic(&state_wr.state, &tmp_b->bState.state, 1 << 2);
        mem_incr32((__mem void *)&migrate_to_nic);
    }
    else if (opt == CTRL_OFFLOAD)
    {
        state_wr.state = VALID;
        state_wr.espec = tmp_b->bState.espec & 0x3;
        mem_write_atomic(&state_wr, &tmp_b->bState, sizeof(bucket_state));
        mem_incr32((__mem void *)&migrate_offload);
    }
    else if (opt == CTRL_FLAG)
    {
        state_wr.state = int_hdr->flag;
        mem_write32(&state_wr.state, &flag, 1 << 2);
        mem_incr32((__mem void *)&migrate_flag);
    }

    /* Set the flag and the egress port */
    mem_read32(&state_rd, &flag, 1 << 2);
    if (ipv4->protocol == 6)
        PIF_HEADER_SET_int_hdr___flag(int_hdr, state_rd);
    else
        PIF_HEADER_SET_memcached_hdr___flag(memcached, state_rd);

    espec = pif_plugin_meta_get__standard_metadata__ingress_port(headers);
    pif_plugin_meta_set__standard_metadata__egress_spec(headers, espec);
    mem_incr32((__mem void *)&dbg_migrate[1]);
    
    return PIF_PLUGIN_RETURN_FORWARD;
}