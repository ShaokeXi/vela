#ifndef __MIGRATE__
#define __MIGRATE__

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
#define MBUF_INVALID_PORT 			UINT8_MAX
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
#define FLOW_NUM					1500000
#define PCAP_MAGIC_NUMBER   		0xa1b2c3d4
#define PCAP_MAJOR_VERSION  		2
#define PCAP_MINOR_VERSION  		4
#ifndef BIG_ENDIAN
#define BIG_ENDIAN      			0x4321
#endif
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN   			0x1234
#endif
#define SKETCH_ROW					3
#define SKETCH_COL					1024
#define CTRL_UPDATE_FREQ			5
#define LARGE_FLOW_THRESHOLD		100
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


struct core_stats
{
	struct rte_timer fwd_timer;
	struct rte_jobstats fwd_job;
	struct rte_jobstats idle_job;
	struct rte_jobstats_context jobs_context;
	struct timeval prev_tv;
	uint32_t hitter_update;
	uint32_t new_state;
	uint32_t del_state;
	uint32_t del_error;
	uint32_t evict_error;
	uint32_t recv_pkts;
	uint64_t recv_bytes;
	uint32_t send_pkts;
	uint32_t to_cpu;
	uint32_t to_nic;
	uint32_t count;
} __rte_cache_aligned;


typedef struct nicIdx
{
	uint32_t bucket;
	uint32_t index;
} nicIdx;

typedef struct flow
{
	uint32_t srcAddr;
	uint32_t dstAddr;
	uint32_t ports;
} flow;

typedef struct state
{
	flow addr;
	nicIdx nic;
	int opt;
	int status;
	int heavy;				/* Large flow: true; small flow: false */
	int ctrlCnt;			/* The number of sent ctrl packets */
	uint32_t count;
} state;

typedef struct sketch
{
	uint32_t tbl[SKETCH_ROW][SKETCH_COL];
} sketch;

typedef struct monitor
{
	uint64_t idle_sample;
	uint64_t idle_time;
	uint64_t nic_cur_count;
	uint64_t nic_last_count;
	uint64_t nic_cur_update;
	uint64_t nic_last_update;
	uint64_t cpu_cur_count;
	uint64_t cpu_last_count;
	uint64_t cpu_last_update;
} monitor;

typedef struct controller
{
	int nicTblSize;
	int nicGrpSize;
	rte_atomic32_t nicFlowCnt;
	rte_atomic32_t nicFlowAlloc;
	rte_atomic32_t nicGrpCnt;
	rte_atomic32_t cpuFlowCnt;
	rte_atomic32_t cpuGrpCnt;
	rte_atomic32_t totalFlowCnt;
} controller;

typedef struct iStateGrp
{
	int id;
	int cnt;
	int status;
	int *states;
} iStateGrp;

enum
{
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

enum
{
	STABLE,
	OVERLOAD,
	AVAILABLE
};

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

extern volatile int force_quit;
extern int nic_flag;
extern int app_cores;
extern int nb_ports;
extern int delay;
extern char ctrlType[32];
extern uint16_t nb_rxd;
extern uint16_t nb_txd;
extern int exec_time;
extern uint32_t interval;

/* packet memory pools for storing packet bufs */
extern struct rte_mempool *pktmbuf_pool[PRT_NUM];
extern struct rte_mempool *ctrlmbuf_pool[PRT_NUM];
extern struct rte_eth_dev_tx_buffer *tx_buffer[PRT_NUM];
extern int dropped[PRT_NUM];

/* State Management */
extern struct rte_hash *elemTbl;
extern struct rte_hash *flowTbl;
extern int elemMap[FLOW_NUM];
extern state flowStore[FLOW_NUM];
// extern struct rte_ring *elemRings[PRT_NUM];
// extern state elemMsgs[PRT_NUM][RING_BUF_SIZE];
// extern int elemCntrs[PRT_NUM];
extern sketch prtSketch[PRT_NUM];
extern state heavyHitter[PRT_NUM];
extern state evictHitter[PRT_NUM];
extern FILE *dbgFile;
extern float ratio;
extern int udp;

/* iPipe State Management */
#define GRP_NUM	4096
const int grpNum;
extern iStateGrp stateGrp[GRP_NUM];

/* Monitoring */
extern monitor prtMon[PRT_NUM];
const char nic_status_map[3][32];
extern controller mCtrl;

/* CPU Usage */
extern struct core_stats lcore_stats[MAX_ETHPORTS];

char* read_symbol(const char* symbol, int offset, int size);
void write_symbol(const char* symbol, int offset, int size, int var);
uint32_t cms_update(sketch* cms, const flow* key);
int send_ctrl_pkt(int port_id, uint32_t offset, uint32_t *info);
int vela_main_loop(void);
int vela_fwd_loop(void);
int ipipe_main_loop(void);
int ipipe_fwd_loop(void);
int recv_loop_vela(void);
int recv_loop_ipipe(void);
int gallium_main_loop(void);
int gallium_fwd_loop(void);
int recv_loop_gallium(void);
int ctrl_loop_vela(void);
int ctrl_loop_ipipe(void);
int ctrl_loop_gallium(void);
int ctrl_loop_latency_test(void);
#endif