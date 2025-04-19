#ifndef __FLOW_H__
#define __FLOW_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_flow.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#define MAX_FNAME                   256
#define TIMEVAL_TO_MSEC(t)  		((t.tv_sec * 1000) + (t.tv_usec / 1000))
#define TO_THROUGHPUT(packets, s) 	((packets) / (s) / 1000000)
#define TO_BANDWIDTH(bytes, s) 		((bytes) * 8.0 / (s) / 1000000000)
#define MAX_RULE                    0x8000

enum pktinfo
{
    PLEN = 0,
    SRCIP,
    DSTIP,
    SRCPORT,
    DSTPORT,
    PROTO,
    FLOWID,
    _N_FLD
};

extern int nb_queue;
extern int all_flow;
extern char pktfile[MAX_FNAME];
extern struct index_bucket *host_itable;
extern uint32_t key_bucket;
extern uint32_t *index_remap_table;

int dpdk_init(char *app_name);
int mcrouter_main_loop(__rte_unused void *dummy);

#endif