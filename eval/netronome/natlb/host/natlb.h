#ifndef __NATLB__
#define __NATLB__

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_ring.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_hash_crc.h>
#include <rte_errno.h>
#include <rte_jobstats.h>
#include <rte_timer.h>
#include <rte_alarm.h>
#include <rte_pause.h>
#include "pcap.h"

#define MAX_ETHPORTS 				16
#define MIN_PKT_SIZE 				64
#define MAX_PKT_SIZE 				1518
#define BUF_SIZE 					2048
#define NB_MBUF 					1024
#define MEMPOOL_CACHE_SIZE 			256
#define BURST_SIZE 					32
#define MAX_MBUFS_PER_PORT 			16384
#define MBUF_SIZE 					(BUF_SIZE + RTE_PKTMBUF_HEADROOM)
#define TIMEVAL_TO_MSEC(t)  		((t.tv_sec * 1000) + (t.tv_usec / 1000))
#define PRT_NUM						9
#define OFF_MF 						0x2000
#define OFF_MASK 					0x1fff
#define RING_BUF_SIZE 				16384
#define PCAP_MAGIC_NUMBER   		0xa1b2c3d4
#define PCAP_MAJOR_VERSION  		2
#define PCAP_MINOR_VERSION  		4
#ifndef BIG_ENDIAN
#define BIG_ENDIAN      			0x4321
#endif
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN   			0x1234
#endif
#define true    					1
#define false   					0

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#define RX_PTHRESH 					8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 					8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 					4 /**< Default values of RX write-back threshold reg. */

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#define TX_PTHRESH 					36 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH					0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH					0  /**< Default values of TX write-back threshold reg. */

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT	128
#define RTE_TEST_TX_DESC_DEFAULT	128

#define MAX_RX_QUEUE_PER_LCORE 		16

#define GROUP_NUM                   256
#define DIP_NUM                     4096
#define TIMEVAL_TO_MSEC(t)  		((t.tv_sec * 1000) + (t.tv_usec / 1000))
#define TO_THROUGHPUT(packets, s) 	((packets) / (s) / 1000000)
#define TO_BANDWIDTH(bytes, s) 		((bytes) * 8.0 / (s) / 1000000000)

struct core_stats
{
	uint32_t recv_pkts;
	uint64_t recv_bytes;
	uint32_t send_pkts;
} __rte_cache_aligned;

enum
{
	INVALID, /* not on this device */
	VALID, /* on this device */
	TRANSIENT_N2C,
	TRANSIENT_C2N,
	INITIAL_INVALID,
	INITIAL_VALID,
	UNINITIATED
};

enum
{
	OPT,
	IDLE,
	BUCKET,
	INDEX,
	FLAG,
	COUNT,
	COUNT_TS_0,
	COUNT_TS_1,
	_NLD
};

struct real_server {
    uint32_t dip;
    uint16_t dport;
    rte_atomic32_t counter;
};

struct stat_load {
	uint32_t rs_id;
    uint32_t counter;
    rte_spinlock_t lock;
    struct real_server *rs;
};

extern volatile int force_quit;
extern int nic_flag;
extern int app_cores;
extern int nb_ports;
extern int delay;
extern uint16_t nb_rxd;
extern uint16_t nb_txd;
extern int exec_time;
extern uint32_t interval;

/* packet memory pools for storing packet bufs */
extern struct rte_mempool *pktmbuf_pool[PRT_NUM];
extern struct rte_mempool *ctrlmbuf_pool[PRT_NUM];
extern struct rte_eth_dev_tx_buffer *tx_buffer[PRT_NUM];
extern int dropped[PRT_NUM];

/* CPU Usage */
extern struct core_stats lcore_stats[MAX_ETHPORTS];

int natlb_main_loop(void);
#endif