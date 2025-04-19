#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include "migrate.h"

/* device info */
struct rte_eth_dev_info dev_info[MAX_ETHPORTS];
/* port configure */
struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode	= 	ETH_MQ_RX_RSS,
		.max_rx_pkt_len = 	ETHER_MAX_LEN,
		.split_hdr_size = 	0,
		.header_split   = 	0, /**< Header Split disabled */
		.hw_ip_checksum = 	1, /**< IP checksum offload enabled */
		.hw_vlan_filter = 	0, /**< VLAN filtering disabled */
		.jumbo_frame    = 	0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 	1, /**< CRC stripped by hardware */
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = 	NULL,
			.rss_hf = 	ETH_RSS_TCP | ETH_RSS_UDP |
					ETH_RSS_IP | ETH_RSS_L2_PAYLOAD
		},
	},	
	.txmode = {
		.mq_mode = 		ETH_MQ_TX_NONE,
	},
};
/* rx configure */
const struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = 		RX_PTHRESH, /* RX prefetch threshold reg */
		.hthresh = 		RX_HTHRESH, /* RX host threshold reg */
		.wthresh = 		RX_WTHRESH, /* RX write-back threshold reg */
	},
	.rx_free_thresh = 	    32,
};
/* tx configure */
const struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = 		TX_PTHRESH, /* TX prefetch threshold reg */
		.hthresh = 		TX_HTHRESH, /* TX host threshold reg */
		.wthresh = 		TX_WTHRESH, /* TX write-back threshold reg */
	},
	.tx_free_thresh = 		0, /* Use PMD default values */
	.tx_rs_thresh = 		0, /* Use PMD default values */
	/*
	 * As the example won't handle mult-segments and offload cases,
	 * set the flag by default.
	 */
	.txq_flags = 			0x0,
};

volatile int force_quit;
int nic_flag = OVERLOAD;
int app_cores = 8;
int nb_ports;
int delay = 0;
char ctrlType[32];
uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
int exec_time = 10;
uint32_t interval = 1000;

/* packet memory pools for storing packet bufs */
struct rte_mempool *pktmbuf_pool[PRT_NUM] = {NULL};
struct rte_mempool *ctrlmbuf_pool[PRT_NUM] = {NULL};
struct rte_eth_dev_tx_buffer *tx_buffer[PRT_NUM];
int dropped[PRT_NUM] = {0};

/* State Management */
struct rte_hash *elemTbl;
struct rte_hash *flowTbl;
int elemMap[FLOW_NUM];
state flowStore[FLOW_NUM];
sketch prtSketch[PRT_NUM];
state heavyHitter[PRT_NUM];
state evictHitter[PRT_NUM];
FILE *dbgFile;
float ratio = 1;
int udp = false;

/* iPipe State Management */
#define GRP_NUM	4096
const int grpNum = GRP_NUM;
iStateGrp stateGrp[GRP_NUM];

/* Monitoring */
monitor prtMon[PRT_NUM] = {{0}};
const char nic_status_map[3][32] = {
	"STABLE", "OVERLOAD", "AVAILABLE"
};
controller mCtrl = {
	.nicTblSize = 1000000,
	.nicGrpSize = 4096,
};
struct core_stats lcore_stats[MAX_ETHPORTS];
static void *fwd_main_loop;

static struct rte_hash *create_hash_table(const char *tablename, uint32_t entry_num, uint32_t init_num, uint32_t key_len)
{

	struct rte_hash *hash_table;
	struct rte_hash_parameters hash_params = {0};

	hash_params.entries = entry_num;
	hash_params.key_len = key_len;
	hash_params.hash_func = rte_jhash;
	hash_params.hash_func_init_val = init_num;

	hash_params.name = tablename;
	hash_params.socket_id = rte_socket_id();
	hash_params.extra_flag = 0;
	// hash_params.key_mode = RTE_HASH_KEY_MODE_DUP;

	/* Find if the hash table was created before */
	hash_table = rte_hash_find_existing(hash_params.name);
	if (hash_table != NULL)
	{
		return hash_table;
	}
	else
	{
		hash_table = rte_hash_create(&hash_params);
		if (!hash_table)
		{
			printf("create hash_table[%s] failed!\n", hash_params.name);
			return NULL;
		}
	}

	return hash_table;
}

static void check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 			100 /* 100ms */
#define MAX_CHECK_TIME 			90 /* 9s (90 * 100ms) in total */

	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == 0) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

#define ETHER_TYPE_CTRL	0x0900
static void ctrlmbuf_init(struct rte_mempool *mp,
		__rte_unused void *opaque_arg,
		void *_m,
		__rte_unused unsigned i)
{
    struct rte_mbuf *m = _m;
	uint32_t mbuf_size, buf_len, priv_size;

    const uint8_t dmac[6] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x10};

	priv_size = rte_pktmbuf_priv_size(mp);
	mbuf_size = sizeof(struct rte_mbuf) + priv_size;
	buf_len = rte_pktmbuf_data_room_size(mp);

	RTE_ASSERT(RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) == priv_size);
	RTE_ASSERT(mp->elt_size >= mbuf_size);
	RTE_ASSERT(buf_len <= UINT16_MAX);

	memset(m, 0, mbuf_size);
	/* start of buffer is after mbuf structure and priv data */
	m->priv_size = priv_size;
	m->buf_addr = (char *)m + mbuf_size;
	m->buf_physaddr = rte_mempool_virt2phy(mp, m) + mbuf_size;
	m->buf_len = (uint16_t)buf_len;

	/* keep some headroom between start of buffer and data */
	m->data_off = RTE_MIN(RTE_PKTMBUF_HEADROOM, (uint16_t)m->buf_len);

	/* init some constant fields */
	m->pool = mp;
	m->nb_segs = 1;
	m->port = MBUF_INVALID_PORT;
	rte_mbuf_refcnt_set(m, 1);
	m->next = NULL;

    /* ether hdr */
    uint8_t *ptr = (uint8_t *)m->buf_addr + m->data_off;
    struct ether_hdr *ether = (struct ether_hdr *)ptr;
    ether->ether_type = rte_cpu_to_be_16(ETHER_TYPE_CTRL);
    // rte_memcpy(ether->s_addr.addr_bytes, smac, 6);
    rte_memcpy(ether->d_addr.addr_bytes, dmac, 6);
    /* ipv4 hdr */
    struct ipv4_hdr *ipv4 = (struct ipv4_hdr *)&ether[1];
	ipv4->version_ihl = 4 << 4 | 5;

    if (!udp)
	{
		/* tcp hdr */
		ipv4->next_proto_id = 6;
    	struct tcp_hdr *tcp = (struct tcp_hdr *)&ipv4[1];
    	tcp->tcp_flags = 0x02;
	}
	else
	{
		ipv4->next_proto_id = 17;
	}
}

static void flush_tx_error_callback(struct rte_mbuf **unsent, uint16_t count, void *userdata)
{
	int i;
	int *dropped = (int *)userdata;
	*dropped += count;
    /* free the mbufs which failed from transmit */
    for (i = 0; i < count; i++)
        rte_pktmbuf_free(unsent[i]);
}

static void nic_init(int nb_ports)
{
    int portid, ret;
    /* set up mempool for each port */
    for (portid = 0; portid < nb_ports; portid++)
	{
        char name[RTE_MEMPOOL_NAMESIZE];
        uint32_t nb_mbuf = NB_MBUF, rx_q = 0, tx_q = 0;
        sprintf(name, "mbuf_pool-%d", portid);
        /* create the mbuf pool */
        pktmbuf_pool[portid] =
            rte_mempool_create(name, nb_mbuf,
            MBUF_SIZE, MEMPOOL_CACHE_SIZE,
            sizeof(struct rte_pktmbuf_pool_private),
            rte_pktmbuf_pool_init, NULL,
            rte_pktmbuf_init, NULL,
            rte_socket_id(), MEMPOOL_F_SP_PUT |
            MEMPOOL_F_SC_GET);

        if (pktmbuf_pool[portid] == NULL)
            rte_exit(EXIT_FAILURE, "Cannot init mbuf pool, errno: %d\n",
                    rte_errno);

		/* create ctrl mbuf pool */
		sprintf(name, "cmbuf_pool-%d", portid);
		ctrlmbuf_pool[portid] = 
			rte_mempool_create(name, nb_mbuf,
            MBUF_SIZE, MEMPOOL_CACHE_SIZE,
            sizeof(struct rte_pktmbuf_pool_private),
            rte_pktmbuf_pool_init, NULL,
            ctrlmbuf_init, NULL,
            rte_socket_id(), MEMPOOL_F_SP_PUT |
            MEMPOOL_F_SC_GET);
		
		if (ctrlmbuf_pool[portid] == NULL)
            rte_exit(EXIT_FAILURE, "Cannot init ctrlmbuf pool, errno: %d\n",
                    rte_errno);

		/* tx buffer */
		tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
			RTE_ETH_TX_BUFFER_SIZE(BURST_SIZE), 0,
			rte_eth_dev_socket_id(portid));
		if (tx_buffer[portid] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n", portid);
		rte_eth_tx_buffer_init(tx_buffer[portid], BURST_SIZE);
		ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],
			flush_tx_error_callback,
			&dropped[portid]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			"Cannot set error callback for tx buffer on port %u\n", portid);

        /* init port */
        printf("Initializing port %u... ", (unsigned) portid);
        fflush(stdout);
        /* hard-coded one tx queue and one rx queue port */
        ret = rte_eth_dev_configure(portid, 1, 1, &port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
                    ret, (unsigned) portid);

        fflush(stdout);

        /* check port capabilities */
        rte_eth_dev_info_get(portid, &dev_info[portid]);

        ret = rte_eth_rx_queue_setup(portid, rx_q, nb_rxd,
                            rte_eth_dev_socket_id(portid), &rx_conf,
                            pktmbuf_pool[portid]);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                    "rte_eth_rx_queue_setup:err=%d, port=%u, queueid: %d\n",
                    ret, (unsigned) portid, rx_q);

        fflush(stdout);
        ret = rte_eth_tx_queue_setup(portid, tx_q, nb_txd,
                            rte_eth_dev_socket_id(portid), &tx_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                    "rte_eth_tx_queue_setup:err=%d, port=%u, queueid: %d\n",
                    ret, (unsigned) portid, tx_q);

        /* Start device */
        ret = rte_eth_dev_start(portid);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
                    ret, (unsigned) portid);

        printf("done: \n");
        rte_eth_promiscuous_enable(portid);
    }
    check_all_ports_link_status(nb_ports, 0xFFFFFFFF);

	/* Create migration management table */
	char tbl_name[RTE_MEMPOOL_NAMESIZE];
	snprintf(tbl_name, sizeof(tbl_name), "hash_elemTbl");
	elemTbl = create_hash_table(tbl_name, FLOW_NUM, 111, sizeof(nicIdx));
	char tbl_name2[RTE_MEMPOOL_NAMESIZE];
	snprintf(tbl_name2, sizeof(tbl_name2), "hash_flowTbl");
	flowTbl = create_hash_table(tbl_name2, FLOW_NUM, 222, sizeof(flow));

	int i;
	for(i = 0; i < grpNum; i++)
	{
		stateGrp[i].status = UNINITIATED;
		stateGrp[i].states = rte_malloc(NULL, sizeof(int) * FLOW_NUM / grpNum, RTE_CACHE_LINE_SIZE);
	}

	rte_atomic32_init(&mCtrl.totalFlowCnt);
	rte_atomic32_init(&mCtrl.cpuFlowCnt);
	rte_atomic32_init(&mCtrl.nicFlowCnt);
	rte_atomic32_init(&mCtrl.nicFlowAlloc);
	rte_atomic32_init(&mCtrl.cpuGrpCnt);
	rte_atomic32_init(&mCtrl.nicGrpCnt);

	/* Initialize flow store */
	for (i = 0; i < FLOW_NUM; i++)
	{
		memset(&flowStore[i], 0, sizeof(state));
	}

	/* Create log file */
	dbgFile = fopen("migrate.log", "a");
    if (dbgFile == NULL) {
        perror("Failed to open file");
        return;
    }
}

static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

// static uint32_t rand_32bit()
// {
//     uint32_t high = rand() & 0xFFFF;
//     uint32_t low = rand() & 0xFFFF;

//     return (high << 16) | low;
// }

#define RTSYM "/opt/netronome/bin/nfp-rtsym"
char* read_symbol(const char* symbol, int offset, int size)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "%s -l %d %s:%d", RTSYM, size, symbol, offset);

    FILE* pipe = popen(cmd, "r");
    if (!pipe) {
        fprintf(stderr, "popen() failed\n");
        return NULL;
    }

    char* output = (char*)malloc(1024 * sizeof(char));
    if (!output) {
        fprintf(stderr, "malloc() failed\n");
        pclose(pipe);
        return NULL;
    }
    memset(output, 0, 1024);

    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        strncat(output, buffer, 1023 - strlen(output));
    }

    pclose(pipe);

    return output;
}

void write_symbol(const char* symbol, int offset, int size, int var)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "%s -l %d %s:%d %d", RTSYM, size, symbol, offset, var);

    FILE* pipe = popen(cmd, "r");
    if (!pipe) {
        fprintf(stderr, "popen() failed\n");
        return;
    }

    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        printf("%s", buffer);
    }

    pclose(pipe);
}

uint32_t cms_update(sketch* cms, const flow* key)
{
    uint32_t minCount = UINT32_MAX;
	uint32_t hv[SKETCH_ROW];
	int i;
	
	for(i = 0; i < SKETCH_ROW; i++)
	{
		hv[i] = rte_hash_crc(key, sizeof(flow), i) & (SKETCH_COL - 1);
		if (cms->tbl[i][hv[i]]++ < minCount)
			minCount = cms->tbl[i][hv[i]];
	}

    return minCount;
}


int send_ctrl_pkt(int port_id, uint32_t offset, uint32_t *info)
{
	struct rte_mbuf *pkt = rte_pktmbuf_alloc(ctrlmbuf_pool[port_id]);
	if (pkt == NULL) rte_exit(EXIT_FAILURE, "Cannot allocate mbuf\n");
	pkt->data_len = 96;
	pkt->pkt_len = 96;
	
	uint8_t *ptr = (uint8_t *)pkt->buf_addr + pkt->data_off;
	uint32_t *int_hdr = (uint32_t *)(ptr + offset);
	// printf("evict bucket: 0x%08X, index: 0x%08X\n", st[i]->bucket, st[i]->index);

	int i;
	for(i = 0; i < _NLD; i++)
		int_hdr[i] = info[i];

	int nb_tx = rte_eth_tx_burst(port_id, 0, &pkt, 1);
	if (nb_tx != 1) {
		rte_pktmbuf_free(pkt);
	}

	return nb_tx;
}


static int launch_one_lcore(void *arg __rte_unused)
{
    int cid = rte_lcore_id();

	if (strcmp(ctrlType, "vela") == 0)
	{
		// cid == (app_cores + 1) ? ctrl_loop_vela() : recv_loop_vela();
		cid == (app_cores + 1) ? ctrl_loop_vela() : vela_main_loop();
		// cid == (app_cores + 1) ? ctrl_loop_latency_test() : vela_main_loop();
	}
	else if (strcmp(ctrlType, "ipipe") == 0)
	{
		// cid == (app_cores + 1) ? ctrl_loop_ipipe() : recv_loop_ipipe();
		cid == (app_cores + 1) ? ctrl_loop_ipipe() : ipipe_main_loop();
	}
	else if (strcmp(ctrlType, "gallium") == 0)
	{
		// cid == (app_cores + 1) ? ctrl_loop_gallium() : recv_loop_gallium();
		cid == (app_cores + 1) ? ctrl_loop_gallium() : gallium_main_loop();
	}
	
    return 0;
}


#define BURST_TX_DRAIN_US 10 /* TX drain every ~100us */
int main(int argc, char **argv)
{
	int i, ret;
	uint8_t portid;
	char corebuf[8];
	char *eptr;

	srand(time(NULL));

    for (i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-n") == 0)
		{
		    app_cores = atoi(argv[i+1]);
		}
		if (strcmp(argv[i], "-d") == 0)
		{
			delay = atoi(argv[i+1]);
		}
		if (strcmp(argv[i], "-c") == 0)
		{
			strncpy(ctrlType, argv[i+1], sizeof(ctrlType));
			if (strcmp(ctrlType, "vela") == 0)
			{
				fwd_main_loop = &vela_fwd_loop;
			}
			else if (strcmp(ctrlType, "ipipe") == 0)
			{
				fwd_main_loop = &ipipe_fwd_loop;
			}
			else if (strcmp(ctrlType, "gallium") == 0)
			{
				fwd_main_loop = &gallium_fwd_loop;
			}
		}
		if (strcmp(argv[i], "-s") == 0)
		{
			ratio = strtof(argv[i+1], &eptr);
			mCtrl.nicTblSize = (int)(mCtrl.nicTblSize * ratio);
			mCtrl.nicGrpSize = (int)(mCtrl.nicGrpSize * ratio);
		}
		if (strcmp(argv[i], "-u") == 0)
		{
			udp = true;
		}
    }

	snprintf(corebuf, 8, "0-%d", app_cores+1);

	/* init EAL */
    char *v[] = {
		"",
        "-l",
        corebuf,
        "-m",
        "4096",
        ""
    };
    const int c = 5;
	ret = rte_eal_init(c, v);

	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

	rte_timer_subsystem_init();

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	nb_ports = rte_eth_dev_count();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

    // run init processure
    nic_init(nb_ports);

	double hz = rte_get_timer_hz();
	uint64_t drain_tsc = (hz + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

	unsigned lcore_id;
	struct core_stats *cstat;
	RTE_LCORE_FOREACH(lcore_id)
	{
		cstat = &lcore_stats[lcore_id];
		if (rte_jobstats_context_init(&cstat->jobs_context) != 0)
			rte_panic("Jobs stats context for core %u init failed\n", lcore_id);

		/* Add fwd job.
		 * Set fixed period by setting min = max = initial period. Set target to
		 * zero as it is irrelevant for this job. */
		rte_jobstats_init(&cstat->fwd_job, "fwd", drain_tsc, drain_tsc, drain_tsc, 0);

		rte_timer_init(&cstat->fwd_timer);
		ret = rte_timer_reset(&cstat->fwd_timer, drain_tsc, PERIODICAL, lcore_id, fwd_main_loop, NULL);

		if (ret < 0)
		{
			rte_exit(1, "Failed to reset migration job timer for lcore %u: %s",
					lcore_id, rte_strerror(-ret));
		}
	}

	/* launch per-lcore init on every lcore */
    rte_eal_mp_remote_launch(launch_one_lcore, NULL, SKIP_MASTER);

    // sleep(exec_time);
    // force_quit = true;

	rte_eal_mp_wait_lcore();
	for (portid = 0; portid < nb_ports; portid++)
	{
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}

	return ret;
}