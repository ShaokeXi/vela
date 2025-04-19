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
#include "mcrouter.h"

/* device info */
struct rte_eth_dev_info dev_info[MAX_ETHPORTS];
/* port configure */
struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode	= 	ETH_MQ_RX_RSS,
		.max_rx_pkt_len = 	ETHER_MAX_LEN,
		.split_hdr_size = 	0,
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
};

#define KEY_LEN         32
#define LOOP            10
#define ENTRY_NUM       16
#define KEY_MAX_BUCKET  0x100000
#define MAX_FNAME       256

struct entry
{
	uint32_t keys[KEY_LEN];
};

struct index_bucket
{
	struct entry entries[ENTRY_NUM];
};


struct key_element
{
	uint32_t key[KEY_LEN];
	uint32_t hash_index;
};

volatile int force_quit;
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

struct core_stats lcore_stats[MAX_ETHPORTS];
struct index_bucket *host_itable = NULL;
uint32_t key_bucket = 0x100000;
static char key_file[MAX_FNAME];

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
}

static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

static void create_key_buffer()
{
	long int host_itable_size = KEY_MAX_BUCKET * sizeof(struct index_bucket);
	host_itable = rte_zmalloc("indexTable", host_itable_size, 0);
	if (host_itable == NULL)
	{
		printf("Failed to allocate memory for host_itable\n");
		exit(-1);
	}

    /* Set the key buffer to the DPA heap memory. */
	FILE *fp = fopen(key_file, "rb");
	if (fp == NULL) {
		printf("Failed to open key file\n");
		exit(-1);
	}
	
	int host_set = 0, host_loss = 0;
	uint32_t hash_mask = key_bucket - 1;
	size_t batch_size = 1024;
	uint32_t elements[batch_size][5];
	while (1) {
		size_t read_count = fread(elements, sizeof(elements[0]), batch_size, fp);
		if (read_count == 0) {
			break;
		}
		uint32_t i, j;
		for (j = 0; j < read_count; j++) {
			uint32_t key_index = elements[j][4] & hash_mask;
			for (i = 0; i < ENTRY_NUM; i++) {
				if (host_itable[key_index].entries[i].keys[0] == 0) {
					memcpy(host_itable[key_index].entries[i].keys, elements[j], sizeof(elements[j]));
					host_set++;
					break;
				} else if (i == ENTRY_NUM - 1) {
					host_loss++;
				}
			}
		}
	}
	printf("Host set %d keys, lost %d keys\n", host_set, host_loss);
	fclose(fp);
	
	return;
}

struct group_stat {
	uint64_t count;
	uint16_t group_id;
};

static void mcrouter_main_loop()
{
	unsigned portid;
	struct ether_hdr *eth;
	struct ipv4_hdr *ipv4;
	struct rte_mbuf *pkts_burst[BURST_SIZE];
	uint32_t core, nb_rx, time_cnt = 0;
	int send;
	uint32_t i, j, k, m;

	uint64_t new_counter = 0, hit_counter = 0, miss_counter = 0;

	core = rte_lcore_id();
	portid = core - 1;

	uint64_t total_busy_cycles = 0;
	uint64_t total_idle_cycles = 0;
	uint64_t last_stat_time = rte_get_tsc_cycles();
	uint64_t stat_interval_cycles = rte_get_timer_hz(); // 1 second
	uint64_t last_end_cycles = last_stat_time;

	uint32_t hash_mask = key_bucket - 1;
	struct key_element km;
	while (!force_quit)
	{
		uint64_t start_cycles = rte_get_tsc_cycles();
		nb_rx = rte_eth_rx_burst(portid, 0, pkts_burst, BURST_SIZE);

		for (i = 0; i < nb_rx; i++)
		{
			// per-packet processing
			rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i], void *));
			uint8_t *ptr = (uint8_t *)pkts_burst[i]->buf_addr + pkts_burst[i]->data_off;
			eth = (struct ether_hdr *)ptr;
			eth->d_addr.addr_bytes[0] = 0x22;
			ptr += sizeof(struct ether_hdr);
			ipv4 = (struct ipv4_hdr *)ptr;

			if (ipv4->next_proto_id == 0x06)
			{
				ipv4->next_proto_id = 17;
				uint32_t key_index = ipv4->dst_addr & hash_mask;
				for (k = 0; k < LOOP; k++)
				{
					for (j = 0; j < ENTRY_NUM; j++)
					{
						if (host_itable[key_index].entries[j].keys[0] == 0)
						{
							host_itable[key_index].entries[j].keys[0] = ipv4->src_addr;
							new_counter++;
							break;
						}
						else if (host_itable[key_index].entries[j].keys[0] == ipv4->src_addr)
						{
							if (hit_counter & 1)
							{
								// Update
								for (m = 1; m < KEY_LEN; m++)
									host_itable[key_index].entries[j].keys[m] = km.key[m];
							}
							else
							{
								// Get
								for (m = 1; m < KEY_LEN; m++)
									km.key[m] = host_itable[key_index].entries[j].keys[m];
							}
							hit_counter++;
							break;
						}
						else if (j == ENTRY_NUM - 1)
						{
							miss_counter++;
						}
					}
				}
			}
			// rte_pktmbuf_free(pkts_burst[i]);
			send = rte_eth_tx_buffer(portid, 0, tx_buffer[portid], pkts_burst[i]);
			if (send)
			{
				lcore_stats[portid].send_pkts += nb_rx;
			}
			lcore_stats[portid].recv_bytes += pkts_burst[i]->pkt_len;
		}
		lcore_stats[portid].recv_pkts += nb_rx;

		uint64_t end_cycles = rte_get_tsc_cycles();
		total_busy_cycles += (end_cycles - start_cycles);
		total_idle_cycles += (start_cycles - last_end_cycles);
		last_end_cycles = end_cycles;

		uint64_t diff_cycles = end_cycles - last_stat_time;
		if (diff_cycles >= stat_interval_cycles)
		{
			total_idle_cycles += diff_cycles;
			double diff_secs = diff_cycles / (double)rte_get_timer_hz();
			double total_cycles = total_busy_cycles + total_idle_cycles;
			double busy_ratio = (total_busy_cycles / total_cycles) * 100.0;
			double idle_ratio = (total_idle_cycles / total_cycles) * 100.0;
			
            RTE_LOG(INFO, USER1, "[CPU %d] %d RX %.2f Mpps, %.2f Gbps, TX %.2f Mpps, "
				"new: %" PRIu64 ", hit: %" PRIu64 ", miss: %" PRIu64 ", Busy: %.2f, Idle: %.2f\n",
				core, time_cnt++,
				TO_THROUGHPUT(lcore_stats[portid].recv_pkts, diff_secs),
				TO_BANDWIDTH(lcore_stats[portid].recv_bytes, diff_secs),
				TO_THROUGHPUT(lcore_stats[portid].send_pkts, diff_secs),
				new_counter, hit_counter, miss_counter,
				busy_ratio,
				idle_ratio);
			last_stat_time = end_cycles;
			lcore_stats[portid].send_pkts = 0;
			lcore_stats[portid].recv_pkts = 0;
			lcore_stats[portid].recv_bytes = 0;

			// Reset cycle counters for the next interval
			hit_counter = 0;
			miss_counter = 0;
			total_busy_cycles = 0;
			total_idle_cycles = 0;
		}
	}

	return;
}

static int launch_one_lcore(void *arg __rte_unused)
{
	mcrouter_main_loop();
	
    return 0;
}


#define BURST_TX_DRAIN_US 10 /* TX drain every ~100us */
int main(int argc, char **argv)
{
	int i, ret;
	uint8_t portid;
	char corebuf[8];

	srand(time(NULL));

    for (i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-n") == 0)
		{
		    app_cores = atoi(argv[i+1]);
		}
		if (strcmp(argv[i], "-c") == 0)
		{
			strcpy(ctrlType, argv[i+1]);
		}
        if (strcmp(argv[i], "-f") == 0)
        {
            strcpy(key_file, argv[i+1]);
        }
        if (strcmp(argv[i], "-b") == 0)
        {
            key_bucket = strtol(argv[i+1], NULL, 0);
        }
    }

	snprintf(corebuf, 8, "0-%d", app_cores);

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

	// nb_ports = rte_eth_dev_count();
	nb_ports = app_cores;
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

    // run init processure
    nic_init(nb_ports);
	create_key_buffer();

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