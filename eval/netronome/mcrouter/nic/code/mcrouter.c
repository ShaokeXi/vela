#include <stdint.h>
#include <memory.h>
#include <nfp/me.h>
#include <std/hash.h>
#include <pif_common.h>
#include <pif_plugin.h>
#include <pif_headers.h>
#include <nfp_override.h>
#include <nfp/mem_atomic.h>

#define BUCKET_SIZE                     16
#define MEM_TABLE_FAST                  0x600
#define MEM_TABLE_SIZE                  0x70000
#define CALC_BIT_TO_SET_CLR(A,k)        (A = (1 << (k % 32)) )
#define true                            1
#define false                           0
#define PIF_32_BIT_XFR_LW               32
#define PIF_32_BIT_XFR_BYTES            ((PIF_32_BIT_XFR_LW) * 4)
#define IDLE_UPDATE_THRESHOLD           1000000
#define KEY_LEN                         32
#define LOOP                            2
#define TO_CPU                          1

typedef struct bucket_entry {
    uint32_t keys[KEY_LEN];
} bucket_entry;

typedef struct bucket_list {
    struct bucket_entry entry[BUCKET_SIZE];
} bucket_list;

__export __addr40 __imem bucket_list itable_fast[MEM_TABLE_FAST];
__export __addr40 __emem bucket_list itable_large[MEM_TABLE_SIZE];
// __export __addr40 __imem uint32_t itable_fast_locks[MEM_TABLE_FAST >> 5];
// __export __addr40 __imem uint32_t itable_large_locks[MEM_TABLE_SIZE >> 5];

/* MEMCACHED Counters */
volatile __declspec(imem, export) uint32_t mem_fast_new = 0;
volatile __declspec(imem, export) uint32_t mem_fast_hits = 0;
volatile __declspec(imem, export) uint32_t mem_fast_miss = 0;
volatile __declspec(imem, export) uint32_t mem_new = 0;
volatile __declspec(imem, export) uint32_t mem_hits = 0;
volatile __declspec(imem, export) uint32_t mem_miss = 0;
volatile __declspec(imem, export) uint32_t mem_to_cpu = 0;
volatile __declspec(imem, export) uint32_t mem_to_nic = 0;

__declspec(ctm) uint64_t end_time;
__declspec(ctm) uint32_t idle_time;
// __declspec(ctm, shared) monitor me_monitor;

/* Debug */
__export __mem uint32_t flag;
__export __mem uint32_t espec_num = 8;
__export __mem uint32_t key_bucket = 0x400;
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

int pif_plugin_route(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    PIF_PLUGIN_eth_T *eth;
    PIF_PLUGIN_ipv4_T *ipv4;

    uint32_t hash_value;
    uint32_t i, j, k;
    __xread uint32_t bucket_num;
    __xrw struct bucket_entry entry;
    __addr40 __mem uint32_t *bucket;

    eth = pif_plugin_hdr_get_eth(headers);
    ipv4 = pif_plugin_hdr_get_ipv4(headers);

    if (ipv4->ttl == TO_CPU)
    {
        mem_incr32((__mem void *)&mem_to_cpu);
        return PIF_PLUGIN_RETURN_FORWARD;
    }

	mem_read32(&bucket_num, &key_bucket, 1 << 2);
    hash_value = ipv4->dstAddr;
    hash_value %= bucket_num;

    if (hash_value < MEM_TABLE_FAST)
    {
        for (k = 0; k < LOOP; k++)
        {
            for (i = 0; i < BUCKET_SIZE; i++)
            {
                if (itable_fast[hash_value].entry[i].keys[0] == 0)
                {
                    itable_fast[hash_value].entry[i].keys[0] = ipv4->srcAddr;
                    mem_incr32((__mem void *)&mem_fast_new);
                    break;
                }
                else if (itable_fast[hash_value].entry[i].keys[0] == ipv4->srcAddr)
                {
                    if (mem_fast_hits & 1)
                    {
                        for (j = 0; j < KEY_LEN; j++)
                        {
                            entry.keys[j] = ipv4->srcAddr;
                        }
                        bucket = &itable_fast[hash_value].entry[i].keys[0];
                        mem_write_atomic(&entry, bucket, sizeof(bucket_entry) >> 2);
                        mem_write_atomic(&entry.keys[8], &bucket[8], sizeof(bucket_entry) >> 2);
                        mem_write_atomic(&entry.keys[16], &bucket[16], sizeof(bucket_entry) >> 2);
                        mem_write_atomic(&entry.keys[24], &bucket[24], sizeof(bucket_entry) >> 2);
                    }
                    else
                    {
                        bucket = &itable_fast[hash_value].entry[i].keys[0];
                        mem_read_atomic(&entry, bucket, sizeof(bucket_entry) >> 2);
                        mem_read_atomic(&entry.keys[8], &bucket[8], sizeof(bucket_entry) >> 2);
                        mem_read_atomic(&entry.keys[16], &bucket[16], sizeof(bucket_entry) >> 2);
                        mem_read_atomic(&entry.keys[24], &bucket[24], sizeof(bucket_entry) >> 2);
                    }
                    mem_incr32((__mem void *)&mem_fast_hits);
                    break;
                }
                else if (j == BUCKET_SIZE - 1)
                {
                    mem_incr32((__mem void *)&mem_fast_miss);
                }
            }
        }
    }
    else
    {
        for (k = 0; k < LOOP; k++)
        {
            for (i = 0; i < BUCKET_SIZE; i++)
            {
                if (itable_large[hash_value].entry[i].keys[0] == 0)
                {
                    itable_large[hash_value].entry[i].keys[0] = ipv4->srcAddr;
                    mem_incr32((__mem void *)&mem_new);
                    break;
                }
                else if (itable_large[hash_value].entry[i].keys[0] == ipv4->srcAddr)
                {
                    if (mem_hits & 1)
                    {
                        for (j = 0; j < KEY_LEN; j++)
                            entry.keys[j] = ipv4->srcAddr;
                        bucket = &itable_large[hash_value].entry[i].keys[0];
                        mem_write_atomic(&entry, bucket, sizeof(bucket_entry) >> 2);
                        mem_write_atomic(&entry.keys[8], &bucket[8], sizeof(bucket_entry) >> 2);
                        mem_write_atomic(&entry.keys[16], &bucket[16], sizeof(bucket_entry) >> 2);
                        mem_write_atomic(&entry.keys[24], &bucket[24], sizeof(bucket_entry) >> 2);
                    }
                    else
                    {
                        bucket = &itable_large[hash_value].entry[i].keys[0];
                        mem_read_atomic(&entry, bucket, sizeof(bucket_entry) >> 2);
                        mem_read_atomic(&entry.keys[8], &bucket[8], sizeof(bucket_entry) >> 2);
                        mem_read_atomic(&entry.keys[16], &bucket[16], sizeof(bucket_entry) >> 2);
                        mem_read_atomic(&entry.keys[24], &bucket[24], sizeof(bucket_entry) >> 2);
                    }
                    mem_incr32((__mem void *)&mem_hits);
                    break;
                }
                else if (j == BUCKET_SIZE - 1)
                {
                    mem_incr32((__mem void *)&mem_miss);
                }
            }
        }
    }
    
    PIF_HEADER_SET_eth___dstAddr___1(eth, 0x2211);
    mem_incr32((__mem void *)&mem_to_nic);
    
    return PIF_PLUGIN_RETURN_FORWARD;
}