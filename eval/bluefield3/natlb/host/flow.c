#include "flow.h"

#define RTE_LOGTYPE_NATLB RTE_LOGTYPE_USER1

#define MAX_QUEUE 8
#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

/*
* Configurable number of RX/TX ring descriptors
*/
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct rte_ether_addr l2fwd_ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t l2fwd_enabled_port_mask = 1;

/* list of enabled ports */
static uint32_t l2fwd_dst_ports[RTE_MAX_ETHPORTS];

struct __rte_cache_aligned port_pair_params {
#define NUM_PORTS	2
	uint16_t port[NUM_PORTS];
};

// static struct port_pair_params *port_pair_params;
static struct port_pair_params port_pair_params[1] = {0};
static uint16_t nb_port_pair_params = 1;

static unsigned int l2fwd_rx_queue_per_lcore = 1;

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
/* List of queues to be polled for a given lcore. 8< */
struct __rte_cache_aligned lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
	unsigned rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
};
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];
/* >8 End of list of queues to be polled for a given lcore. */

static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS][MAX_QUEUE];

static struct rte_eth_conf port_conf = {
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
};

struct rte_mempool * l2fwd_pktmbuf_pool = NULL;

/* Per-port statistics struct */
struct __rte_cache_aligned l2fwd_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t tx_bytes;
	uint64_t rx_bytes;
	uint64_t dropped;
};
struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS][MAX_QUEUE];

static volatile bool force_quit;

/* Ports set in promiscuous mode off by default. */
static int promiscuous_on = 1;

#define MAX_GROUP_CHAIN    	4
#define BUCKET_NUM         	32
#define MAX_TIMER_PERIOD 	86400 /* 1 day max */
#define MAX_PATTERN_NUM	   	4
#define MAX_ACTION_NUM	   	3
#define MAX_GROUP_RULES    	65535
#define DEBUG              	0
#define GROUP_NUM	    	256
#define DIP_NUM		    	4096

struct bucket
{
	int index;
	int in_use;
	uint32_t counter[MAX_GROUP_CHAIN];
};

/* A tsc-based timer responsible for triggering statistics printout */
static int rule_num;
static struct bucket buckets[BUCKET_NUM];
static struct rte_flow *rule_table_0[MAX_SW_RULES];
static struct rte_flow *rule_table_1[MAX_SW_RULES];

struct real_server
{
	uint32_t dip;
	uint32_t dport;
	rte_atomic32_t counter;
};

struct stat_load
{
	uint32_t rs_id;
	uint32_t counter;
	rte_spinlock_t lock;
};

struct stat_load server_loads[GROUP_NUM];
struct real_server real_servers[DIP_NUM];

/*
* Check port pair config with enabled port mask,
* and for valid port pair combinations.
*/
static int
check_port_pair_config(void)
{
	uint32_t port_pair_config_mask = 0;
	uint32_t port_pair_mask = 0;
	uint16_t index, i, portid;

	for (index = 0; index < nb_port_pair_params; index++) {
		port_pair_mask = 0;

		for (i = 0; i < NUM_PORTS; i++)  {
			portid = port_pair_params[index].port[i];
			if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
				printf("port %u is not enabled in port mask\n",
					portid);
				return -1;
			}
			if (!rte_eth_dev_is_valid_port(portid)) {
				printf("port %u is not present on the board\n",
					portid);
				return -1;
			}

			port_pair_mask |= 1 << portid;
		}

		if (port_pair_config_mask & port_pair_mask) {
			printf("port %u is used in other port pairs\n", portid);
			return -1;
		}
		port_pair_config_mask |= port_pair_mask;
	}

	l2fwd_enabled_port_mask &= port_pair_config_mask;

	return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	int ret;
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if (force_quit)
				return;
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n",
						portid, rte_strerror(-ret));
				continue;
			}
			/* print link status if flag set */
			if (print_flag == 1) {
				rte_eth_link_to_str(link_status_text,
					sizeof(link_status_text), &link);
				printf("Port %d %s\n", portid,
					link_status_text);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == RTE_ETH_LINK_DOWN) {
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

static struct rte_flow *add_default_next_rule(uint16_t port_id, 
    struct rte_flow_error *error, int cur_group, int next_group)
{
    struct rte_flow_attr attr = {
        .ingress = 1,
        .group = cur_group,
        .priority = 1   /* low priority */
    };
    struct rte_flow_item patterns[MAX_PATTERN_NUM] = {0};
    memset(patterns, 0, sizeof(patterns));
    patterns[0].type = RTE_FLOW_ITEM_TYPE_END;

    struct rte_flow_action_jump jump;
    memset(&jump, 0, sizeof(jump));
    jump.group = next_group;

    struct rte_flow_action actions[MAX_ACTION_NUM] = {0};
    memset(actions, 0, sizeof(actions));
    actions[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
    actions[0].conf = &jump;
    actions[1].type = RTE_FLOW_ACTION_TYPE_END;

    if (rte_flow_validate(port_id, &attr, patterns, actions, error) == 0)
    {
#if DEBUG
        printf("Add default next rule from group %d to group %d\n", cur_group, next_group);
#endif
        return rte_flow_create(port_id, &attr, patterns, actions, error);
    }
    
    return NULL;
}

static struct rte_flow *add_default_drop_rule(uint16_t port_id, 
    struct rte_flow_error *error, int cur_group)
{
    struct rte_flow_attr attr = {
        .ingress = 1,
        .group = cur_group,
        .priority = 1   /*low priority*/
    };
    struct rte_flow_item patterns[MAX_PATTERN_NUM] = {0};
    memset(patterns, 0, sizeof(patterns));
    patterns[0].type = RTE_FLOW_ITEM_TYPE_END;

    struct rte_flow_action actions[MAX_ACTION_NUM] = {0};
    memset(actions, 0, sizeof(actions));
    actions[0].type = RTE_FLOW_ACTION_TYPE_DROP;
    actions[1].type = RTE_FLOW_ACTION_TYPE_END;

    if (rte_flow_validate(port_id, &attr, patterns, actions, error) == 0)
    {
#if DEBUG
        printf("Add default drop rule for group %d\n", cur_group);
#endif
        return rte_flow_create(port_id, &attr, patterns, actions, error);
    }

    return NULL;
}

static struct rte_flow *l2fwd_ipv4_flow_create_group_0(uint16_t port_id, 
    struct rte_flow_error *error, uint32_t dstip)
{
    struct rte_flow_attr attr = {
        .ingress = 1, 
        .group = 0,
        .priority = 0
    };
    struct rte_flow_action actions[MAX_ACTION_NUM] = {0};
	struct rte_flow_item patterns[MAX_PATTERN_NUM] = {0};
    struct rte_flow_action_jump jump;
    struct rte_flow *flow = NULL;
    struct rte_flow_item_ipv4 *ip_spec;
    struct rte_flow_item_ipv4 *ip_mask;

    int bucket_id;
    actions[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
    actions[0].conf = &jump;
    actions[1].type = RTE_FLOW_ACTION_TYPE_END;

    patterns[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    patterns[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    ip_spec = calloc(1, sizeof(struct rte_flow_item_ipv4));
    if (ip_spec == NULL)
        fprintf(stderr, "Failed to allocate memory for ip_spec\n");

    ip_mask = calloc(1, sizeof(struct rte_flow_item_ipv4));
    if (ip_mask == NULL)
        fprintf(stderr, "Failed to allocate memory for ip_mask\n");

    ip_spec->hdr.dst_addr = htonl(dstip);
    ip_mask->hdr.dst_addr = htonl(BUCKET_NUM - 1);
    patterns[1].spec = ip_spec;
    patterns[1].mask = ip_mask;
    bucket_id = dstip & (BUCKET_NUM - 1);
    jump.group = bucket_id * MAX_GROUP_CHAIN + 1;

    patterns[2].type = RTE_FLOW_ITEM_TYPE_END;

    /* Validate the rule and create it. */
    if (rte_flow_validate(port_id, &attr, patterns, actions, error) == 0)
    {
#if DEBUG
        printf("Add rule for bucket %d in group 0 (root)\n", bucket_id);
#endif
        flow = rte_flow_create(port_id, &attr, patterns, actions, error);
    }
    
    return flow;
}

static struct rte_flow *l2fwd_ipv4_flow_create_group_1(uint16_t port_id, 
    struct rte_flow_error *error, struct bucket *buckets, 
    uint32_t srcip, uint32_t dstip, uint16_t srcport, uint16_t dstport)
{
    struct rte_flow_attr attr = {
        .ingress = 1,
        .priority = 0
    };
    struct rte_flow_action actions[MAX_ACTION_NUM] = {0};
    struct rte_flow_item patterns[MAX_PATTERN_NUM] = {0};

    struct rte_flow_item_ipv4 *ip_spec;
    struct rte_flow_item_ipv4 *ip_mask;
    struct rte_flow_item_tcp *tcp_spec;
    struct rte_flow_item_tcp *tcp_mask;

    int bucket_id;
    struct rte_flow_action_count *count = calloc(1, sizeof(struct rte_flow_action_count));
    if (count == NULL)
        fprintf(stderr, "Failed to allocate memory for count\n");
    actions[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
    actions[0].conf = count;
	// actions[0].type = RTE_FLOW_ACTION_TYPE_DROP;
    
    struct rte_flow_action_queue *queue = calloc(1, sizeof(struct rte_flow_action_queue));
    if (queue == NULL)
        fprintf(stderr, "Failed to allocate memory for queue\n");
    queue->index = htonl(dstip) % GROUP_NUM % nb_queue;
    actions[1].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    actions[1].conf = queue;
    actions[2].type = RTE_FLOW_ACTION_TYPE_END;

    patterns[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    patterns[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    ip_spec = calloc(1, sizeof(struct rte_flow_item_ipv4));
    if (ip_spec == NULL)
        fprintf(stderr, "Failed to allocate memory for ip_spec\n");

    ip_mask = calloc(1, sizeof(struct rte_flow_item_ipv4));
    if (ip_mask == NULL)
        fprintf(stderr, "Failed to allocate memory for ip_mask\n");

    ip_spec->hdr.dst_addr = htonl(dstip);
    ip_mask->hdr.dst_addr = 0xffffffff;
    ip_spec->hdr.src_addr = htonl(srcip);
    ip_mask->hdr.src_addr = 0xffffffff;
    ip_spec->hdr.next_proto_id = IPPROTO_TCP;
    ip_mask->hdr.next_proto_id = 0xff;
    
    bucket_id = dstip & (BUCKET_NUM - 1);
    patterns[1].spec = ip_spec;
    patterns[1].mask = ip_mask;

	patterns[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    tcp_spec = calloc(1, sizeof(struct rte_flow_item_tcp));
    if (tcp_spec == NULL)
        fprintf(stderr, "Failed to allocate memory for tcp_spec\n");
    
    tcp_mask = calloc(1, sizeof(struct rte_flow_item_tcp));
    if (tcp_mask == NULL)
        fprintf(stderr, "Failed to allocate memory for tcp_mask\n");
    
    tcp_spec->hdr.src_port = htons(srcport);
    tcp_mask->hdr.src_port = 0xffff;
    tcp_spec->hdr.dst_port = htons(dstport);
    tcp_mask->hdr.dst_port = 0xffff;
    
    patterns[2].spec = tcp_spec;
    patterns[2].mask = tcp_mask;
    
	// patterns[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    // tcp_spec = calloc(1, sizeof(struct rte_flow_item_tcp));
    // if (tcp_spec == NULL)
    //     fprintf(stderr, "Failed to allocate memory for tcp_spec\n");
    
    // tcp_mask = calloc(1, sizeof(struct rte_flow_item_tcp));
    // if (tcp_mask == NULL)
    //     fprintf(stderr, "Failed to allocate memory for tcp_mask\n");
    
    // tcp_spec->hdr.src_port = htons(srcport);
    // tcp_mask->hdr.src_port = 0xffff;
    // tcp_spec->hdr.dst_port = htons(dstport);
    // tcp_mask->hdr.dst_port = 0xffff;
    // patterns[2].spec = tcp_spec;
    // patterns[2].mask = tcp_mask;

    /* The final level must be always type end. */
    patterns[3].type = RTE_FLOW_ITEM_TYPE_END;

    int table_id = buckets[bucket_id].in_use;
    int cur_group = bucket_id * MAX_GROUP_CHAIN + table_id + 1;
    if (buckets[bucket_id].counter[table_id] == MAX_GROUP_RULES)
    {
        buckets[bucket_id].in_use++;
        table_id = buckets[bucket_id].in_use;
        if (table_id == MAX_GROUP_CHAIN)
        {
            fprintf(stderr, "Bucket %d is full\n", bucket_id);
            exit(-1);
        }
        cur_group++;
    }

    /* Add default rule if the table is empty. */
    if (buckets[bucket_id].counter[table_id] == 0)
    {
        if (table_id == MAX_GROUP_CHAIN - 1)
        {
            if (add_default_drop_rule(port_id, error, cur_group) == NULL)
                fprintf(stderr, "Failed to add default rule for bucket %d table %d\n",
                    bucket_id, cur_group);
        }
        else
        {
            if (add_default_next_rule(port_id, error, cur_group, cur_group+1) == NULL)
                fprintf(stderr, "Failed to add default rule for bucket %d table %d\n",
                    bucket_id, cur_group);
        }
    }

    attr.group = cur_group;

    /* Validate the rule and create it. */
	struct rte_flow *flow = NULL;
    if (rte_flow_validate(port_id, &attr, patterns, actions, error) == 0)
    {
#if DEBUG
        printf("Add rule for bucket %d in group %d, srcip %u dstip %u srcport %u dstport %u\n", 
                bucket_id, cur_group, srcip, dstip, srcport, dstport);
#endif
        flow = rte_flow_create(port_id, &attr, patterns, actions, error);
    }
    
    buckets[bucket_id].counter[table_id]++;
    return flow;
}

static void counter_report(struct bucket *buckets)
{
	for (int i = 0; i < BUCKET_NUM; i++)
	{
		printf("Bucket %d: ", buckets[i].index);
		for (int j = 0; j <= buckets[i].in_use; j++)
		{
			printf("%d ", buckets[i].counter[j]);
		}
		printf("\n");
	}

	return;
}

static void
natlb_init_flow_rule(unsigned port_id)
{
	FILE *fp;
	char *buffer = NULL;
	char *eptr;
	size_t bufsize = 128;
	size_t len = 0;
	ssize_t read;
	char delim[] = "\t";
	struct rte_flow_error error;
	uint32_t tmp[_N_FLD];

	buffer = (char *)malloc(bufsize * sizeof(char));

	fp = fopen(pktfile, "r");
	if (fp == NULL)
	{
		printf("Failed to open file %s\n", pktfile);
		exit(-1);
	}

	for (int i = 0; i < BUCKET_NUM; i++)
	{
		buckets[i].index = i;
		buckets[i].in_use = 0;
		for (int j = 0; j < MAX_GROUP_CHAIN; j++)
		{
			buckets[i].counter[j] = 0;
		}
	}

	while ((read = getline(&buffer, &len, fp)) != -1) 
	{
		char *ptr = strtok(buffer, delim);
		int i = 0;

		while(ptr != NULL)
		{
			ptr = strtok(NULL, delim);
			if (!ptr)
				break;
			tmp[i++] = strtoul(ptr, &eptr, 10);
		}

		if (tmp[PROTO] == 6)
		{
			if (all_flow && (int)tmp[FLOWID] >= all_flow)
				continue;
			if (rule_table_0[tmp[FLOWID]] == NULL)
			{
				rule_table_0[tmp[FLOWID]] = l2fwd_ipv4_flow_create_group_0(
					port_id, &error, tmp[DSTIP]);
				if (!rule_table_0[tmp[FLOWID]]) {
					printf("Failed to create RX steering rule %d (group 0), err: %s\n", 
						rule_num, error.message ? error.message : "(no stated reason)");
					counter_report(buckets);
					exit(-1);
				}

				rule_table_1[tmp[FLOWID]] = l2fwd_ipv4_flow_create_group_1(
					port_id, &error, buckets, 
					tmp[SRCIP], tmp[DSTIP], tmp[SRCPORT], tmp[DSTPORT]);
				if (!rule_table_1[tmp[FLOWID]]) {
					printf("Failed to create RX steering rule %d (group 1), err: %s\n", 
						rule_num, error.message ? error.message : "(no stated reason)");
					counter_report(buckets);
					exit(-1);
				}
				rule_num++;
			}
			// printf("\rrule_num: %d", rule_num);
		}
	}
	printf("\n%d rx steering rules created\n", rule_num);
	
	counter_report(buckets);
	fclose(fp);
	if (buffer)
	{
		free(buffer);
	}

	return;
}

int dpdk_init(void)
{
	struct lcore_queue_conf *qconf;
	int ret;
	uint16_t nb_ports;
	uint16_t nb_ports_available = 0;
	uint16_t portid, last_port;
	unsigned rx_lcore_id;
	unsigned nb_ports_in_mask = 0;
	unsigned int nb_lcores = 0;
	unsigned int nb_mbufs;

    nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	if (port_pair_params != NULL) {
		if (check_port_pair_config() < 0)
			rte_exit(EXIT_FAILURE, "Invalid port pair config\n");
	}

	/* check port mask to possible port mask */
	if (l2fwd_enabled_port_mask & ~((1 << nb_ports) - 1))
		rte_exit(EXIT_FAILURE, "Invalid portmask; possible (0x%x)\n",
			(1 << nb_ports) - 1);

	/* Initialization of the driver. 8< */

	/* reset l2fwd_dst_ports */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
		l2fwd_dst_ports[portid] = 0;
	last_port = 0;

	/* populate destination port details */
	if (port_pair_params != NULL) {
		uint16_t idx, p;

		for (idx = 0; idx < (nb_port_pair_params << 1); idx++) {
			p = idx & 1;
			portid = port_pair_params[idx >> 1].port[p];
			l2fwd_dst_ports[portid] =
				port_pair_params[idx >> 1].port[p ^ 1];
		}
	} else {
		RTE_ETH_FOREACH_DEV(portid) {
			/* skip ports that are not enabled */
			if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
				continue;

			if (nb_ports_in_mask % 2) {
				l2fwd_dst_ports[portid] = last_port;
				l2fwd_dst_ports[last_port] = portid;
			} else {
				last_port = portid;
			}

			nb_ports_in_mask++;
		}
		if (nb_ports_in_mask % 2) {
			printf("Notice: odd number of ports in portmask.\n");
			l2fwd_dst_ports[last_port] = last_port;
		}
	}
	/* >8 End of initialization of the driver. */

	rx_lcore_id = 0;
	qconf = NULL;

	/* Initialize the port/queue configuration of each logical core */
	for (int i = 0; i < nb_queue; i++)
	{
		RTE_ETH_FOREACH_DEV(portid) {
			/* skip ports that are not enabled */
			if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
				continue;
	
			/* get the lcore_id for this port */
			while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
				lcore_queue_conf[rx_lcore_id].n_rx_port ==
				l2fwd_rx_queue_per_lcore) {
				rx_lcore_id++;
				if (rx_lcore_id >= RTE_MAX_LCORE)
					rte_exit(EXIT_FAILURE, "Not enough cores\n");
			}
	
			if (qconf != &lcore_queue_conf[rx_lcore_id]) {
				/* Assigned a new logical core in the loop above. */
				qconf = &lcore_queue_conf[rx_lcore_id];
				nb_lcores++;
			}
	
			qconf->rx_port_list[qconf->n_rx_port] = portid;
			qconf->rx_queue_list[qconf->n_rx_port] = i;
			qconf->n_rx_port++;
			printf("Lcore %u: RX port %u TX port %u Queue %d\n", rx_lcore_id,
				portid, l2fwd_dst_ports[portid], i);
		}
	}

	nb_mbufs = RTE_MAX(nb_ports * (nb_rxd + nb_txd + MAX_PKT_BURST +
		nb_lcores * MEMPOOL_CACHE_SIZE), 8192U);

	/* Create the mbuf pool. 8< */
	l2fwd_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (l2fwd_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
	/* >8 End of create the mbuf pool. */

	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;

		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
			printf("Skipping disabled port %u\n", portid);
			continue;
		}
		nb_ports_available++;

		/* init port */
		printf("Initializing port %u... ", portid);
		fflush(stdout);

		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, strerror(-ret));

		// uint64_t rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP;
		// local_port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
		// local_port_conf.rx_adv_conf.rss_conf.rss_hf = rss_hf & dev_info.flow_type_rss_offloads;

		if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
		/* Configure the number of queues for a port. */
		ret = rte_eth_dev_configure(portid, nb_queue, nb_queue, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
				ret, portid);
		/* >8 End of configuration of the number of queues for a port. */

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
							&nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"Cannot adjust number of descriptors: err=%d, port=%u\n",
				ret, portid);

		ret = rte_eth_macaddr_get(portid,
					&l2fwd_ports_eth_addr[portid]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"Cannot get MAC address: err=%d, port=%u\n",
				ret, portid);

		for (int i = 0; i < nb_queue; i++)
		{
			/* init one RX queue */
			fflush(stdout);
			rxq_conf = dev_info.default_rxconf;
			rxq_conf.offloads = local_port_conf.rxmode.offloads;
			/* RX queue setup. 8< */
			ret = rte_eth_rx_queue_setup(portid, i, nb_rxd,
							rte_eth_dev_socket_id(portid),
							&rxq_conf,
							l2fwd_pktmbuf_pool);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u, queue=%d\n",
					ret, portid, i);
			/* >8 End of RX queue setup. */

			/* Init one TX queue on each port. 8< */
			fflush(stdout);
			txq_conf = dev_info.default_txconf;
			txq_conf.offloads = local_port_conf.txmode.offloads;
			ret = rte_eth_tx_queue_setup(portid, i, nb_txd,
					rte_eth_dev_socket_id(portid),
					&txq_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u, queue=%d\n",
					ret, portid, i);
			/* >8 End of init one TX queue on each port. */

			/* Initialize TX buffers */
			tx_buffer[portid][i] = rte_zmalloc_socket("tx_buffer",
					RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
					rte_eth_dev_socket_id(portid));
			if (tx_buffer[portid][i] == NULL)
				rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u queue %d\n",
						portid, i);

			rte_eth_tx_buffer_init(tx_buffer[portid][i], MAX_PKT_BURST);

			ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid][i],
					rte_eth_tx_buffer_count_callback,
					&port_statistics[portid][i].dropped);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
				"Cannot set error callback for tx buffer on port %u\n",
					portid);
		}

		ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL,
						0);
		if (ret < 0)
			printf("Port %u, Failed to disable Ptype parsing\n",
					portid);
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				ret, portid);

		printf("done: \n");
		if (promiscuous_on) {
			ret = rte_eth_promiscuous_enable(portid);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
					"rte_eth_promiscuous_enable:err=%s, port=%u\n",
					rte_strerror(-ret), portid);
		}

		printf("Port %u, MAC address: " RTE_ETHER_ADDR_PRT_FMT "\n\n",
			portid,
			RTE_ETHER_ADDR_BYTES(&l2fwd_ports_eth_addr[portid]));

		/* initialize port stats */
		memset(&port_statistics, 0, sizeof(port_statistics));
	}

	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE,
			"All available ports are disabled. Please set portmask.\n");
	}

	check_all_ports_link_status(l2fwd_enabled_port_mask);

	/* Initialize flow rules for port 0 */
	natlb_init_flow_rule(0);

    return 0;
}


int natlb_main_loop(__rte_unused void *dummy)
{
    unsigned portid = 0, queid = 0;
    struct rte_ether_hdr *eth;
    struct rte_ipv4_hdr *ipv4;
    // struct rte_tcp_hdr *tcp;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    uint32_t core, nb_rx, i, time_cnt = 0;
    struct lcore_queue_conf *qconf;
	int send;

    uint64_t counter = 0;
	struct rte_ether_addr dst_mac = {{0x02, 0x82, 0x4d, 0x74, 0x1c, 0xd0}};
    
    core = rte_lcore_id();
	qconf = &lcore_queue_conf[core];
	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, NATLB, "lcore %u has nothing to do\n", core);
		return 0;
	}
	RTE_LOG(INFO, NATLB, "entering main loop on lcore %u\n", core);
	for (i = 0; i < qconf->n_rx_port; i++) {

		portid = qconf->rx_port_list[i];
        queid = qconf->rx_queue_list[i];
		RTE_LOG(INFO, NATLB, " -- lcoreid=%u portid=%u queid=%u\n", core,
			portid, queid);

	}

    uint64_t total_busy_cycles = 0;
    uint64_t total_idle_cycles = 0;
    uint64_t last_stat_time = rte_get_tsc_cycles();
    uint64_t stat_interval_cycles = rte_get_timer_hz(); // 1 second
    uint64_t last_end_cycles = last_stat_time;

    while (!force_quit)
    {
		uint64_t start_cycles = rte_get_tsc_cycles();
        nb_rx = rte_eth_rx_burst(portid, queid, pkts_burst, MAX_PKT_BURST);

        for (i = 0; i < nb_rx; i++)
        {
            // per-packet processing
            rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[i], void *));
            uint8_t *ptr = (uint8_t *)pkts_burst[i]->buf_addr + pkts_burst[i]->data_off;
            eth = (struct rte_ether_hdr *)ptr;
            rte_memcpy(eth->dst_addr.addr_bytes, &dst_mac, RTE_ETHER_ADDR_LEN);
            ptr += sizeof(struct rte_ether_hdr);
            ipv4 = (struct rte_ipv4_hdr *)ptr;

            if (ipv4->next_proto_id == 0x06)
            { 
                // ptr += sizeof(struct rte_ipv4_hdr);
                // tcp = (struct rte_tcp_hdr *)ptr;
				// uint32_t flowid = *(uint32_t *)&tcp[1];
				uint32_t rs_id = ntohl(ipv4->dst_addr) % DIP_NUM;
				uint32_t group_id = ntohl(ipv4->dst_addr) % GROUP_NUM;

				/* existing record */
				uint32_t count = rte_atomic32_add_return(&real_servers[rs_id].counter, 1);
				rte_spinlock_lock(&server_loads[group_id].lock);
				if (count < server_loads[group_id].counter)
				{
					server_loads[group_id].counter = count;
					server_loads[group_id].rs_id = rs_id;
				}
				else if (rs_id == server_loads[group_id].rs_id)
				{
					server_loads[group_id].counter = count;
				}
				rte_spinlock_unlock(&server_loads[group_id].lock);
            }
			// rte_pktmbuf_free(pkts_burst[i]);
			send = rte_eth_tx_buffer(portid, queid, tx_buffer[portid][queid], pkts_burst[i]);
            if (send)
            {
                port_statistics[portid][queid].tx += send;
            }
			port_statistics[portid][queid].tx_bytes += pkts_burst[i]->pkt_len;
			port_statistics[portid][queid].rx_bytes += pkts_burst[i]->pkt_len;
        }
        port_statistics[portid][queid].rx += nb_rx;

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

            RTE_LOG(INFO, USER1, "[CPU %d] %d RX %.2f Mpps, %.2f Gbps, TX %.2f Mpps, %.2f Gbps, "
                "NAT table: %" PRIu64 ", Busy: %.2f, Idle: %.2f\n",
                core, time_cnt++,
                TO_THROUGHPUT(port_statistics[portid][queid].rx, diff_secs),
                TO_BANDWIDTH(port_statistics[portid][queid].rx_bytes, diff_secs),
                TO_THROUGHPUT(port_statistics[portid][queid].tx, diff_secs),
                TO_BANDWIDTH(port_statistics[portid][queid].tx_bytes, diff_secs),
                counter,
                busy_ratio,
                idle_ratio);
            last_stat_time = end_cycles;
            port_statistics[portid][queid].tx = 0;
            port_statistics[portid][queid].rx = 0;
            port_statistics[portid][queid].tx_bytes = 0;
            port_statistics[portid][queid].rx_bytes = 0;

            // Reset cycle counters for the next interval
            total_busy_cycles = 0;
            total_idle_cycles = 0;
        }

    }

#if DEBUG
	if (core == 0)
	{
		const void *next_key = NULL;
		void *next_data = NULL;
		uint32_t iter = 0;

		printf("Iterating NAT table:\n");
		while (rte_hash_iterate(NAT_table, &next_key, &next_data, &iter) >= 0) {
			struct ip5tuple *flow_key = (struct ip5tuple *)next_key;
			struct real_server *flow_data = (struct real_server *)next_data;

			printf("Flow %u: SRCIP=%u, DSTIP=%u, SRCPORT=%u, DSTPORT=%u, PROTO=%u -> DIP=%u, CNT=%d, RS=%p\n",
					iter,    
					flow_key->srcip, flow_key->dstip, flow_key->srcport,
				  	flow_key->dstport, flow_key->proto, flow_data->dip, rte_atomic32_read(&flow_data->counter), flow_data);
		}
	}
#endif

    return 0;
}