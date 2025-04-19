/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES.
 * Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/* Source file for host part of packet processing sample.
 * Contain functions for parsing input parameters, allocating and freeing resources,
 * initialization of a process and a event handler, and running event handler.
 */

/* Used for geteuid function. */
#include <unistd.h>
#include <signal.h>

/* Used for host (x86/DPU) memory allocations. */
#include <malloc.h>

/* Used for IBV device operations. */
#include <infiniband/verbs.h>
#include <infiniband/mlx5_api.h>
#include <infiniband/mlx5dv.h>
#include <arpa/inet.h>
#include <numaif.h>
#include <sys/shm.h>

/* Flex IO SDK host side version API header. */
#include <libflexio/flexio_ver.h>

/* Flex IO SDK host side API header. */
#include <libflexio/flexio.h>

/* Flow steering utilities helper header. */
#include "flow_steering_utils.h"

/* Common header for communication between host and DPA. */
#include "../flexio_packet_processor_com.h"

#include "flow.h"

/* Flex IO packet processor application struct.
 * Created by DPACC during compilation. The DEV_APP_NAME
 * is a macro transferred from Meson through gcc, with the
 * same name as the created application.
 */
extern struct flexio_app *DEV_APP_NAME;
/* Flex IO packet processor device (DPA) side function stub. */
extern flexio_func_t flexio_pp_dev;
extern flexio_func_t itable_counter_get;

static int thread_num = 1;
static int base_num = 0;
static int port = 0;
static char app_name[MAX_FNAME];
static char key_file[MAX_FNAME];
static char key_trace[MAX_FNAME];
static struct flexio_process *app_fp;
int nb_queue = 1;
int cpu_hash_group = 0;
static uint8_t *select_group;
uint32_t key_bucket = 0x200000;
struct index_bucket *host_itable = NULL;
static int cpu_bypass = 10000;

/* Application context struct holding necessary host side variables */
struct app_context {
	/* Flex IO process is used to load a program to the DPA. */
	struct flexio_process *flexio_process;
	/* Flex IO window is used to access external memory from the DPA */
	struct flexio_window *flexio_window;
	/* Flex IO message stream is used to get messages from the DPA. */
	struct flexio_msg_stream *stream;
	/* Flex IO event handler is used to execute code over the DPA. */
	struct flexio_event_handler *pp_eh[MAX_THREADS];
	/* Flex IO SQ's CQ. */
	struct flexio_cq *flexio_sq_cq_ptr[MAX_THREADS];
	/* Flex IO SQ. */
	struct flexio_sq *flexio_sq_ptr[MAX_THREADS];
	/* Flex IO RQ's CQ. */
	struct flexio_cq *flexio_rq_cq_ptr[MAX_THREADS];
	/* Flex IO RQ. */
	struct flexio_rq *flexio_rq_ptr[MAX_THREADS];
	/* DPA user access register (DPA UAR) for all application's queues.
	 * Will be set to the Flex IO process UAR.
	 */
	struct flexio_uar *process_uar;
	/* Memory key (MKey) for SQ data. */
	struct flexio_mkey *sqd_mkey[MAX_THREADS];
	/* MKey for RQ data. */
	struct flexio_mkey *rqd_mkey[MAX_THREADS];

	/* Protection domain (PD) for all application's queues.
	 * Will be set to the Flex IO process PD.
	 */
	struct ibv_pd *process_pd;
	/* IBV context opened for the device name provided by the user. */
	struct ibv_context *ibv_ctx;

	/* RX flow matcher. */
	struct flow_matcher *rx_matcher;
	/* RX flow rule for matching incoming RX packets to the Flex IO RQ. */
	struct flow_rule *rx_rule_root[MAX_RULE];
	struct flow_rule *rx_rule_vport[MAX_THREADS];
	/* TX flow matcher. */
	struct flow_matcher *tx_matcher;
	/* TX flow rule for forwarding outgoing TX packets to the SWS rule table. */
	struct flow_rule *tx_rule_table[MAX_THREADS];
	/* TX flow rule for forwarding outgoing TX packets to the vport (wire). */
	struct flow_rule *tx_rule_vport[MAX_THREADS];

	/* Transfer structs with information to pass to DPA side.
	 * The structs are defined by a common header which both sides may use.
	 */
	/* SQ's CQ transfer information. */
	struct app_transfer_cq sq_cq_transf[MAX_THREADS];
	/* SQ transfer information. */
	struct app_transfer_wq sq_transf[MAX_THREADS];
	/* RQ's CQ transfer information. */
	struct app_transfer_cq rq_cq_transf[MAX_THREADS];
	/* RQ transfer information. */
	struct app_transfer_wq rq_transf[MAX_THREADS];

	/* DPA heap memory address of application information struct.
	 * Invoked event handler will get this as argument and parse it to the application
	 * information struct.
	 */
	flexio_uintptr_t app_data_daddr[MAX_THREADS];

	/* Index table. */
	void *host_itable;
	uint32_t host_itable_mkey;
	flexio_uintptr_t dpa_itable;
	flexio_uintptr_t index_remap_table;
};

/* Open ibv device
 * Returns 0 on success and -1 if the destroy was failed.
 * app_ctx - app_ctx - pointer to app_context structure.
 * device - device name to open.
 */
static int app_open_ibv_ctx(struct app_context *app_ctx, char *device)
{
	/* Queried IBV device list. */
	struct ibv_device **dev_list;
	/* Fucntion return value. */
	int ret = 0;
	/* IBV device iterator. */
	int dev_i;

	/* Query IBV devices list. */
	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		printf("Failed to get IB devices list\n");
		return -1;
	}

	/* Loop over found IBV devices. */
	for (dev_i = 0; dev_list[dev_i]; dev_i++) {
		/* Look for a device with the user provided name. */
		if (!strcmp(ibv_get_device_name(dev_list[dev_i]), device))
			break;
	}

	/* Check a device was found. */
	if (!dev_list[dev_i]) {
		printf("No IBV device found for device name '%s'\n", device);
		ret = -1;
		goto cleanup;
	}

	/* Open IBV device context for the requested device. */
	app_ctx->ibv_ctx = ibv_open_device(dev_list[dev_i]);
	if (!app_ctx->ibv_ctx) {
		printf("Couldn't open an IBV context for device '%s'\n", device);
		ret = -1;
	}

cleanup:
	/* Free queried IBV devices list. */
	ibv_free_device_list(dev_list);

	return ret;
}

/* Convert logarithm to value */
#define L2V(l) (1UL << (l))
/* Number of entries in each RQ/SQ/CQ is 2^LOG_Q_DEPTH. */
#define LOG_Q_DEPTH 7
#define Q_DEPTH L2V(LOG_Q_DEPTH)
/* SQ/RQ data entry byte size is 512B (enough for packet data in this case). */
#define LOG_Q_DATA_ENTRY_BSIZE 11
/* SQ/RQ data entry byte size log to value. */
#define Q_DATA_ENTRY_BSIZE L2V(LOG_Q_DATA_ENTRY_BSIZE)
/* SQ/RQ DATA byte size is queue depth times entry byte size. */
#define Q_DATA_BSIZE Q_DEPTH *Q_DATA_ENTRY_BSIZE

static int create_steering_matcher(struct app_context *app_ctx, int nic_mode)
{
	/* Create RX flow matcher. */
	// app_ctx->rx_matcher = create_matcher_rx_mcrouter(app_ctx->ibv_ctx);
	app_ctx->rx_matcher = create_matcher_rx_mcrouter_simple(app_ctx->ibv_ctx);
	if (!app_ctx->rx_matcher) {
		printf("Failed to create RX matcher\n");
		return -1;
	}

	if (!nic_mode)
	{
		/* Add a rule to steer outgoing traffic to the vport for it to exit from
		 * the DPU to the wire.
		 */
		/* Create TX flow matcher. */
		app_ctx->tx_matcher = create_matcher_tx(app_ctx->ibv_ctx);
		if (!app_ctx->tx_matcher) {
			printf("Failed to create TX matcher\n");
			return -1;
		}
	}

	return 0;
}

/* Source MAC address to match for incoming packets. */
#define MAGIC	0x02824d741c00
#define SMAC_1 	0x02824d741cd0
#define SMAC_2 	0x026aa27afbee
#define SIP	 	0xc0a80001
/* Creates steering rules for application.
 * Returns 0 on success and -1 if the allocation was failed.
 * app_ctx - pointer to app_context structure.
 * nic_mode - if set to 1, the sample runs on ConnectX part.
 */
static int create_steering_rules_rx(struct app_context *app_ctx)
{
/*
	if (create_rule_rx_mcrouter_root(app_ctx->rx_matcher) == NULL)
	{
		printf("Failed to create RX steering root rule\n");
		return -1;
	}
*/
	int i;
	int dpuCnt = 0, cpuCnt = 0;
	for (i = 0; i < MAX_RULE; i++)
	{
		if (select_group[i] == 0)
		{
			int tid = i % thread_num;
			// app_ctx->rx_rule_root[i] = create_rule_rx_mcrouter_sws(app_ctx->rx_matcher, 
			app_ctx->rx_rule_root[i] = create_rule_rx_mcrouter_simple(app_ctx->rx_matcher, 
				flexio_rq_get_tir(app_ctx->flexio_rq_ptr[tid]), htons(i));
			if (!app_ctx->rx_rule_root[i]) {
				printf("Failed to create RX steering sws rule\n");
				return -1;
			}
			dpuCnt++;
		}
		else
			cpuCnt++;
	}
	printf("Create RX steering rules: dpuCnt=%d, cpuCnt=%d\n", dpuCnt, cpuCnt);

	return 0;
}

static int create_steering_rules_tx(struct app_context *app_ctx, int nic_mode)
{
	/* If the sample runs on NIC, the outgoing rule is already configured.
	 * If the sample runs on DPU, the outgoing rule is configured as a DROP rule,
	 * so the sample needs to reconfigure the outgoing rule.
	 */
	if (!nic_mode) {
		uint64_t smac = port == 0 ? SMAC_1 : SMAC_2;
		/* Create a TX flow rule to forward outgoing packets to SW steering table. */
		app_ctx->tx_rule_table[port] = create_rule_tx_fwd_to_sws_table(app_ctx->tx_matcher, smac);
		if (!app_ctx->tx_rule_table[port]) {
			printf("Failed to create TX table steering rule\n");
			return -1;
		}

		/* Create a TX flow rule to forward outgoing packets to vport (wire). */
		app_ctx->tx_rule_vport[port] = create_rule_tx_fwd_to_vport(app_ctx->tx_matcher, smac);
		if (!app_ctx->tx_rule_vport[port]) {
			printf("Failed to create TX vport steering rule\n");
			return -1;
		}
	}

	return 0;
}

/* CQE size is 64B */
#define CQE_BSIZE 64
#define CQ_BSIZE (Q_DEPTH * CQE_BSIZE)
/* Allocate and initialize DPA heap memory for CQ.
 * Returns 0 on success and -1 if the allocation fails.
 * process - pointer to the previously allocated process information.
 * cq_transf - structure with allocated DPA buffers for CQ.
 */
static int cq_mem_alloc(struct flexio_process *process, struct app_transfer_cq *cq_transf)
{
	/* Pointer to the CQ ring source memory on the host (to copy). */
	struct mlx5_cqe64 *cq_ring_src;
	/* Temp pointer to an iterator for CQE initialization. */
	struct mlx5_cqe64 *cqe;

	/* DBR source memory on the host (to copy). */
	__be32 dbr[2] = { 0, 0 };
	/* Function return value. */
	int ret = 0;
	/* Iterator for CQE initialization. */
	uint32_t i;

	/* Allocate and initialize CQ DBR memory on the DPA heap memory. */
	if (flexio_copy_from_host(process, dbr, sizeof(dbr), &cq_transf->cq_dbr_daddr)) {
		printf("Failed to allocate CQ DBR memory on DPA heap.\n");
		return -1;
	}

	/* Allocate memory for the CQ ring on the host. */
	cq_ring_src = calloc(Q_DEPTH, CQE_BSIZE);
	if (!cq_ring_src) {
		printf("Failed to allocate memory for cq_ring_src.\n");
		return -1;
	}

	/* Init CQEs and set ownership bit. */
	for (i = 0, cqe = cq_ring_src; i < Q_DEPTH; i++)
		mlx5dv_set_cqe_owner(cqe++, 1);

	/* Allocate and copy the initialized CQ ring from host to DPA heap memory. */
	if (flexio_copy_from_host(process, cq_ring_src, CQ_BSIZE, &cq_transf->cq_ring_daddr)) {
		printf("Failed to allocate CQ ring memory on DPA heap.\n");
		ret = -1;
	}

	/* Free CQ ring source memory from host once copied to DPA. */
	free(cq_ring_src);

	return ret;
}

#define IPC_CREAT		01000		/* Create key if key does not exist. */
#define IPC_EXCL		02000		/* Fail if key exists.  */
#define IPC_NOWAIT		04000		/* Return error on wait.  */
#define IPC_RMID		0			/* Remove identifier.  */
#define SHM_HUGETLB		04000		/* segment is mapped via hugetlb */
static void *get_huge_mem(uint32_t numa_node, size_t size)
{
	size = (size + (2 * 1024 * 1024 - 1)) & ~(2 * 1024 * 1024 - 1);
	int shm_key, shm_id;

	srand(time(NULL));

	while (1) {
		shm_key = rand();
		shm_key = abs(shm_key);

		shm_id = shmget(shm_key, size, IPC_CREAT | IPC_EXCL | 0666 | SHM_HUGETLB);

		if (shm_id == -1) {
		switch (errno) {
			case EEXIST:
			printf("shm_key already exists. Try again.\n");
			continue;

			case EACCES:
			printf("Invalid access, maybe code is not illegal\n");
			exit(-1);

			case EINVAL:
			printf("Invalid argument, maybe code is not illegal\n");
			exit(-1);

			case ENOMEM:
			printf("No enough memory could be allocated, please insure you have enough 2M hugepage on this NUMA\n");
			exit(-1);

			default:
			printf("Unexpected error\n");
			exit(-1);
		}
		} else {
			break;
		}
	}

	void *shm_buf = shmat(shm_id, NULL, 0);
	if (shm_buf == (void *)-1) {
		printf("HugeAlloc: shmat() failed. Key = %d\n", shm_key);
		exit(-1);
	}
	shmctl(shm_id, IPC_RMID, NULL);

	unsigned long nodemask = (1ul << (unsigned long)numa_node);

	long ret = mbind(shm_buf, size, MPOL_BIND, &nodemask, 32, 0);

	if (ret) {
		printf("mbind error %ld\n", ret);
		exit(-1);
	}

	return shm_buf;
}

/* SQ WQE byte size is 64B. */
#define LOG_SQ_WQE_BSIZE 6
/* SQ WQE byte size log to value. */
#define SQ_WQE_BSIZE L2V(LOG_SQ_WQE_BSIZE)
/* SQ ring byte size is queue depth times WQE byte size. */
#define SQ_RING_BSIZE (Q_DEPTH * SQ_WQE_BSIZE)
/* Allocate DPA heap memory for SQ.
 * Returns 0 on success and -1 if the allocation fails.
 * process - pointer to the previously allocated process info.
 * sq_transf - structure with allocated DPA buffers for SQ.
 */
static int sq_mem_alloc(struct app_context *app_ctx, struct app_transfer_wq *sq_transf)
{
	/* Allocate host memory for SQ data. */
	void *tmp_ptr = NULL;
	tmp_ptr = get_huge_mem(0, (Q_DATA_BSIZE + 63) & (~63));
	memset(tmp_ptr, 0, Q_DATA_BSIZE);
	struct ibv_mr *mr = ibv_reg_mr(app_ctx->process_pd, tmp_ptr, Q_DATA_BSIZE, 
		IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_ATOMIC);
	sq_transf->wqd_daddr = (flexio_uintptr_t)tmp_ptr;
	sq_transf->wqd_mkey_id = mr->lkey;

	/* Allocate DPA heap memory for SQ ring. */
	flexio_buf_dev_alloc(app_ctx->flexio_process, SQ_RING_BSIZE, &sq_transf->wq_ring_daddr);
	if (!sq_transf->wq_ring_daddr)
		return -1;
	
	return 0;
}

/* Create an SQ over the DPA for sending packets from DPA to wire.
 * A CQ is also created for the SQ.
 * Returns 0 on success and -1 if the allocation fails.
 * app_ctx - app_ctx - pointer to app_context structure.
 */
static int create_app_sq(struct app_context *app_ctx, unsigned int tid)
{
	/* Pointer to the application Flex IO process (ease of use). */
	struct flexio_process *app_fp = app_ctx->flexio_process;
	/* Attributes for the SQ's CQ. */
	struct flexio_cq_attr sqcq_attr = {0};
	/* Attributes for the SQ. */
	struct flexio_wq_attr sq_attr = {0};

	/* UAR ID for CQ/SQ from Flex IO process UAR. */
	uint32_t uar_id = flexio_uar_get_id(app_ctx->process_uar);
	/* SQ's CQ number. */
	uint32_t cq_num;

	/* Allocate CQ memory (ring and DBR) on DPA heap memory. */
	if (cq_mem_alloc(app_fp, &app_ctx->sq_cq_transf[tid])) {
		printf("Failed to alloc memory for SQ's CQ.\n");
		return -1;
	}

	/* Set CQ depth (log) attribute. */
	sqcq_attr.log_cq_depth = LOG_Q_DEPTH;
	/* Set CQ element type attribute to 'non DPA CQ'.
	 * This means this CQ will not be attached to an event handler.
	 */
	sqcq_attr.element_type = FLEXIO_CQ_ELEMENT_TYPE_NON_DPA_CQ;

	/* Set CQ UAR ID attribute to the Flex IO process UAR ID.
	 * This will allow updating/arming the CQ from the DPA side.
	 */
	sqcq_attr.uar_id = uar_id;
	/* Set CQ DBR memory. DBR memory is on the DPA side in order to allow direct access from
	 * DPA.
	 */
	sqcq_attr.cq_dbr_daddr = app_ctx->sq_cq_transf[tid].cq_dbr_daddr;
	/* Set CQ ring memory. Ring memory is on the DPA side in order to allow reading CQEs from
	 * DPA during packet forwarding.
	 */
	sqcq_attr.cq_ring_qmem.daddr = app_ctx->sq_cq_transf[tid].cq_ring_daddr;
	/* Create CQ for SQ. */
	if (flexio_cq_create(app_fp, NULL, &sqcq_attr, &app_ctx->flexio_sq_cq_ptr[tid])) {
		printf("Failed to create Flex IO CQ\n");
		return -1;
	}

	/* Fetch SQ's CQ number to communicate to DPA side. */
	cq_num = flexio_cq_get_cq_num(app_ctx->flexio_sq_cq_ptr[tid]);
	/* Set SQ's CQ number in communication struct. */
	app_ctx->sq_cq_transf[tid].cq_num = cq_num;
	/* Set SQ's CQ depth in communication struct. */
	app_ctx->sq_cq_transf[tid].log_cq_depth = LOG_Q_DEPTH;
	/* Allocate SQ memeory (ring and data) on host memory */
	if (sq_mem_alloc(app_ctx, &app_ctx->sq_transf[tid])) {
		printf("Failed to allocate memory for SQ\n");
		return -1;
	}

	/* Set SQ depth (log) attribute. */
	sq_attr.log_wq_depth = LOG_Q_DEPTH;
	/* Set SQ UAR ID attribute to the Flex IO process UAR ID.
	 * This will allow writing doorbells to the SQ from the DPA side.
	 */
	sq_attr.uar_id = uar_id;
	/* Set SQ ring memory. Ring memory is on the DPA side in order to allow writing WQEs from
	 * DPA during packet forwarding.
	 */
	sq_attr.wq_ring_qmem.daddr = app_ctx->sq_transf[tid].wq_ring_daddr;

	/* Set SQ protection domain */
	sq_attr.pd = app_ctx->process_pd;
	sq_attr.sq.allow_multi_pkt_send_wqe = 1;

	/* Create SQ.
	 * Second argument is NULL as SQ is created on the same GVMI as the process.
	 */
	if (flexio_sq_create(app_fp, NULL, cq_num, &sq_attr, &app_ctx->flexio_sq_ptr[tid])) {
		printf("Failed to create Flex IO SQ\n");
		return -1;
	}

	/* Fetch SQ's number to communicate to DPA side. */
	app_ctx->sq_transf[tid].wq_num = flexio_sq_get_wq_num(app_ctx->flexio_sq_ptr[tid]);

	return 0;
}

/* RQ WQE byte size is 64B. */
#define LOG_RQ_WQE_BSIZE 4
/* RQ WQE byte size log to value. */
#define RQ_WQE_BSIZE L2V(LOG_RQ_WQE_BSIZE)
/* RQ ring byte size is queue depth times WQE byte size. */
#define RQ_RING_BSIZE Q_DEPTH *RQ_WQE_BSIZE
/* Allocate DPA heap memory for SQ.
 * Returns 0 on success and -1 if the allocation fails.
 * process - pointer to the previously allocated process info.
 * rq_transf - structure with allocated DPA buffers for RQ.
 */
static int rq_mem_alloc(struct app_context *app_ctx, struct app_transfer_wq *rq_transf)
{
	/* Allocate host memory for RQ data. */
	void *tmp_ptr = NULL;
	tmp_ptr = get_huge_mem(0, (Q_DATA_BSIZE + 63) & (~63));
	memset(tmp_ptr, 0, Q_DATA_BSIZE);
	struct ibv_mr *mr = ibv_reg_mr(app_ctx->process_pd, tmp_ptr, Q_DATA_BSIZE, 
		IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_ATOMIC);
	rq_transf->wqd_daddr = (flexio_uintptr_t)tmp_ptr;
	rq_transf->wqd_mkey_id = mr->lkey;

	/* Allocate DPA heap memory for RQ ring. */
	flexio_buf_dev_alloc(app_ctx->flexio_process, RQ_RING_BSIZE, &rq_transf->wq_ring_daddr);
	if (!rq_transf->wq_ring_daddr)
		return -1;

	/* Allocate and initialize RQ DBR memory on the DPA heap memory. */
	__be32 dbr[2] = { 0, 0 };
	flexio_copy_from_host(app_ctx->flexio_process, dbr, sizeof(dbr), &rq_transf->wq_dbr_daddr);
	if (!rq_transf->wq_dbr_daddr)
		return -1;

	return 0;
}

/* Initialize an RQ ring memory over the DPA heap memory.
 * RQ WQEs need to be initialized (produced) by SW so they are ready for incoming packets.
 * The WQEs are initialized over temporary host memory and then copied to the DPA.
 * Returns 0 on success and -1 if the allocation fails.
 * app_ctx - app_ctx - pointer to app_context structure.
 */
static int init_dpa_rq_ring(struct app_context *app_ctx, unsigned int tid)
{
	/* RQ WQE data iterator. */
	flexio_uintptr_t wqe_data_daddr = app_ctx->rq_transf[tid].wqd_daddr;
	/* RQ ring MKey. */
	uint32_t mkey_id = app_ctx->rq_transf[tid].wqd_mkey_id;
	/* Temporary host memory for RQ ring. */
	struct mlx5_wqe_data_seg *rx_wqes;
	/* RQ WQE iterator. */
	struct mlx5_wqe_data_seg *dseg;
	/* Function return value. */
	int retval = 0;
	/* RQ WQE index iterator. */
	uint32_t i;

	/* Allocate temporary host memory for RQ ring.*/
	rx_wqes = calloc(1, RQ_RING_BSIZE);
	if (!rx_wqes) {
		printf("Failed to allocate memory for rx_wqes\n");
		return -1;
	}

	/* Initialize RQ WQEs'. */
	for (i = 0, dseg = rx_wqes; i < Q_DEPTH; i++, dseg++) {
		/* Set WQE's data segment to point to the relevant RQ data segment. */
		mlx5dv_set_data_seg(dseg, Q_DATA_ENTRY_BSIZE, mkey_id, wqe_data_daddr);
		/* Advance data pointer to next segment. */
		wqe_data_daddr += Q_DATA_ENTRY_BSIZE;
	}

	/* Copy RX WQEs from host to RQ ring DPA heap memory. */
	if (flexio_host2dev_memcpy(app_ctx->flexio_process, rx_wqes, RQ_RING_BSIZE,
				   app_ctx->rq_transf[tid].wq_ring_daddr)) {
		retval = -1;
	}

	/* Free temporary host memory. */
	free(rx_wqes);
	return retval;
}

/* Initialize RQ's DBR.
 * Recieve counter need to be set to number of produces WQEs.
 * Returns 0 on success and -1 if the allocation fails.
 * app_ctx - app_ctx - pointer to app_context structure.
 */
static int init_rq_dbr(struct app_context *app_ctx, unsigned int tid)
{
	/* Temporary host memory for DBR value. */
	__be32 dbr[2];

	/* Set receiver counter to number of WQEs. */
	dbr[0] = htobe32(Q_DEPTH & 0xffff);
	/* Send counter is not used for RQ so it is nullified. */
	dbr[1] = htobe32(0);
	/* Copy DBR value to DPA heap memory.*/
	if (flexio_host2dev_memcpy(app_ctx->flexio_process, dbr, sizeof(dbr),
				   app_ctx->rq_transf[tid].wq_dbr_daddr)) {
		return -1;
	}

	return 0;
}

/* Create an RQ over the DPA for receiving packets on DPA.
 * A CQ is also created for the RQ.
 * Returns 0 on success and -1 if the allocation fails.
 * app_ctx - app_ctx - pointer to app_context structure.
 */
static int create_app_rq(struct app_context *app_ctx, unsigned int tid)
{
	/* Pointer to the application Flex IO process (ease of use). */
	struct flexio_process *app_fp = app_ctx->flexio_process;
	/* Attributes for the RQ's CQ. */
	struct flexio_cq_attr rqcq_attr = {0};
	/* Attributes for the RQ. */
	struct flexio_wq_attr rq_attr = {0};

	/* UAR ID for CQ/SQ from Flex IO process UAR. */
	uint32_t uar_id = flexio_uar_get_id(app_ctx->process_uar);
	/* RQ's CQ number. */
	uint32_t cq_num;

	/* Allocate CQ memory (ring and DBR) on DPA heap memory. */
	if (cq_mem_alloc(app_fp, &app_ctx->rq_cq_transf[tid])) {
		printf("Failed to alloc memory for RQ's CQ.\n");
		return -1;
	}

	/* Set CQ depth (log) attribute. */
	rqcq_attr.log_cq_depth = LOG_Q_DEPTH;
	/* Set CQ element type attribute to 'DPA thread'.
	 * This means that a CQE on this CQ will trigger the connetced DPA thread.
	 * This will be used for running the DPA program for each incoming packet on the RQ.
	 */
	rqcq_attr.element_type = FLEXIO_CQ_ELEMENT_TYPE_DPA_THREAD;
	/* Set CQ thread to the application event handler's thread. */
	rqcq_attr.thread = flexio_event_handler_get_thread(app_ctx->pp_eh[tid]);
	/* Set CQ UAR ID attribute to the Flex IO process UAR ID.
	 * This will allow updating/arming the CQ from the DPA side.
	 */
	rqcq_attr.uar_id = uar_id;
	/* Set CQ DBR memory. DBR memory is on the DPA side in order to allow direct access from
	 * DPA.
	 */
	rqcq_attr.cq_dbr_daddr = app_ctx->rq_cq_transf[tid].cq_dbr_daddr;
	/* Set CQ ring memory. Ring memory is on the DPA side in order to allow reading CQEs from
	 * DPA during packet forwarding.
	 */
	rqcq_attr.cq_ring_qmem.daddr = app_ctx->rq_cq_transf[tid].cq_ring_daddr;
	/* Create CQ for RQ. */
	if (flexio_cq_create(app_fp, NULL, &rqcq_attr, &app_ctx->flexio_rq_cq_ptr[tid])) {
		printf("Failed to create Flex IO CQ\n");
		return -1;
	}

	/* Fetch SQ's CQ number to communicate to DPA side. */
	cq_num = flexio_cq_get_cq_num(app_ctx->flexio_rq_cq_ptr[tid]);
	/* Set RQ's CQ number in communication struct. */
	app_ctx->rq_cq_transf[tid].cq_num = cq_num;
	/* Set RQ's CQ depth in communication struct. */
	app_ctx->rq_cq_transf[tid].log_cq_depth = LOG_Q_DEPTH;	
	/* Allocate RQ memeory (ring and data) on host memory */
	if (rq_mem_alloc(app_ctx, &app_ctx->rq_transf[tid])) {
		printf("Failed to allocate memory for RQ.\n");
		return -1;
	}

	/* Initialize RQ ring. */
	if (init_dpa_rq_ring(app_ctx, tid)) {
		printf("Failed to init RQ ring.\n");
		return -1;
	}

	/* Set RQ depth (log) attribute. */
	rq_attr.log_wq_depth = LOG_Q_DEPTH;
	/* Set RQ protection domain attribute to be the same as the Flex IO process. */
	rq_attr.pd = app_ctx->process_pd;
	/* Set RQ DBR memory type to DPA heap memory. */
	rq_attr.wq_dbr_qmem.memtype = FLEXIO_MEMTYPE_DPA;
	/* Set RQ DBR memory address. */
	rq_attr.wq_dbr_qmem.daddr = app_ctx->rq_transf[tid].wq_dbr_daddr;
	/* Set RQ ring memory address. */
	rq_attr.wq_ring_qmem.daddr = app_ctx->rq_transf[tid].wq_ring_daddr;
	/* Create the Flex IO RQ.
	 * Second argument is NULL as RQ is created on the same GVMI as the process.
	 */
	if (flexio_rq_create(app_fp, NULL, cq_num, &rq_attr, &app_ctx->flexio_rq_ptr[tid])) {
		printf("Failed to create Flex IO RQ.\n");
		return -1;
	}

	/* Fetch RQ's number to communicate to DPA side. */
	app_ctx->rq_transf[tid].wq_num = flexio_rq_get_wq_num(app_ctx->flexio_rq_ptr[tid]);
	if (init_rq_dbr(app_ctx, tid)) {
		printf("Failed to init RQ DBR.\n");
		return -1;
	}

	return 0;
}

/* Creates a Flex IO SDK event handler.
 * The event handler is used for setting a function in the loaded program to run once
 * a proper trigger happens (CQE on the relevant CQ).
 * Returns 0 on success and -1 if the allocation fails.
 * app_ctx - app_ctx - pointer to app_context structure.
 */
static int create_app_event_handler(struct app_context *app_ctx, unsigned int tid)
{
	/* Event handler creation attributes. */
	struct flexio_event_handler_attr eh_attr = {0};

	/* Set function stub to the stub created by DPACC and declared in the host application. */
	eh_attr.host_stub_func = flexio_pp_dev;
	/* Set execution unit affinity to 'none'.
	 * This will cause the event handler thread to trigger on any free execution unit.
	 * This assumes there's at least one available execution unit in the device default
	 * execution unit group.
	 */
	// eh_attr.affinity.type = FLEXIO_AFFINITY_NONE;
	eh_attr.affinity.type = FLEXIO_AFFINITY_STRICT;
	eh_attr.affinity.id = tid + base_num;
	/* Create the Flex IO event handler object. */
	if (flexio_event_handler_create(app_ctx->flexio_process, &eh_attr, &app_ctx->pp_eh[tid])) {
		printf("Failed to create Flex IO event handler\n");
		return -1;
	}

	return 0;
}

/* Copy application information to DPA.
 * DPA side needs queue information in order to process the packets.
 * The DPA heap memory address will be passed as the event handler argument.
 * Returns 0 if success and -1 if the copy failed.
 * app_ctx - app_ctx - pointer to app_context structure.
 */
static int copy_app_data_to_dpa(struct app_context *app_ctx, unsigned int tid, unsigned int port)
{
	/* Size of application information struct. */
	uint64_t struct_bsize = sizeof(struct host2dev_packet_processor_data);
	/* Temporary application information struct to copy. */
	struct host2dev_packet_processor_data *h2d_data;
	/* Function return value. */
	int ret = 0;

	/* Allocate memory for temporary struct to copy. */
	h2d_data = calloc(1, struct_bsize);
	if (!h2d_data) {
		printf("Failed to allocate memory for h2d_data\n");
		return -1;
	}

	/* Set SQ's CQ information. */
	h2d_data->sq_cq_transf = app_ctx->sq_cq_transf[tid];
	/* Set SQ's information. */
	h2d_data->sq_transf = app_ctx->sq_transf[tid];
	/* Set RQ's CQ information. */
	h2d_data->rq_cq_transf = app_ctx->rq_cq_transf[tid];
	/* Set RQ's information. */
	h2d_data->rq_transf = app_ctx->rq_transf[tid];
	/* Set APP data info for first run. */
	h2d_data->not_first_run = 0;
	/* Set Thread ID */
	h2d_data->id = tid;
	/* Set Port */
	h2d_data->port = port;
	/* Set window id */
	h2d_data->window_id = flexio_window_get_id(app_ctx->flexio_window);
	/* Set key index table */
	h2d_data->dpa_itable = app_ctx->dpa_itable;
	h2d_data->index_remap_table = app_ctx->index_remap_table;
	h2d_data->host_itable = app_ctx->host_itable;
	h2d_data->key_bucket = key_bucket;
	h2d_data->host_itable_mkey = app_ctx->host_itable_mkey;

	/* Copy to DPA heap memory.
	 * Allocated DPA heap memory address will be kept in app_data_daddr.
	 */
	if (flexio_copy_from_host(app_ctx->flexio_process, h2d_data, struct_bsize,
				  &app_ctx->app_data_daddr[tid])) {
		printf("Failed to copy application information to DPA.\n");
		ret = -1;
	}

	/* Free temporary host memory. */
	free(h2d_data);
	return ret;
}

/* Clean up previously allocated rules.
 * Returns 0 on success and -1 if the destroy failed.
 * app_ctx - app_ctx - pointer to app_context structure.
 */
static int clean_up_rules(struct app_context *app_ctx)
{
	int err = 0;
	int i;

	for (i = 0; i < thread_num; i++)
	{
		/* Clean up rx rule if created */
		if (app_ctx->rx_rule_root[i] && destroy_rule(app_ctx->rx_rule_root[i])) {
			printf("Failed to destroy rx rule\n");
			err = -1;
		}

		if (app_ctx->rx_rule_vport[i] && destroy_rule(app_ctx->rx_rule_vport[i])) {
			printf("Failed to destroy rx rule vport\n");
			err = -1;
		}

		/* Clean up tx rule for vport if created */
		if (app_ctx->tx_rule_vport[i] && destroy_rule(app_ctx->tx_rule_vport[i])) {
			printf("Failed to destroy tx rule vport\n");
			err = -1;
		}

		/* Clean up tx rule for table if created */
		if (app_ctx->tx_rule_table[i] && destroy_rule(app_ctx->tx_rule_table[i])) {
			printf("Failed to destroy tx rule\n");
			err = -1;
		}
	}

	/* Clean up rx matcher if created */
	if (app_ctx->rx_matcher && destroy_matcher(app_ctx->rx_matcher)) {
		printf("Failed to destroy rx matcher\n");
		err = -1;
	}

	/* Clean up tx matcher if created */
	if (app_ctx->tx_matcher && destroy_matcher(app_ctx->tx_matcher)) {
		printf("Failed to destroy tx matcher\n");
		err = -1;
	}

	return err;
}

/* Clean up previously allocated RQ
 * Returns 0 on success and -1 if the destroy failed.
 * app_ctx - app_ctx - pointer to app_context structure.
 */
static int clean_up_app_rq(struct app_context *app_ctx)
{
	int err = 0;
	int i;

	for (i = 0; i < thread_num; i++)
	{
		/* Clean up rq pointer if created */
		if (app_ctx->flexio_rq_ptr[i] && flexio_rq_destroy(app_ctx->flexio_rq_ptr[i])) {
			printf("Failed to destroy RQ\n");
			err = -1;
		}

		/* Clean up memory key for rqd if created */
		if (app_ctx->rqd_mkey[i] && flexio_device_mkey_destroy(app_ctx->rqd_mkey[i])) {
			printf("Failed to destroy mkey RQD\n");
			err = -1;
		}

		/* Clean up app data daddr if created */
		if (app_ctx->rq_transf[i].wq_dbr_daddr &&
			flexio_buf_dev_free(app_ctx->flexio_process, app_ctx->rq_transf[i].wq_dbr_daddr)) {
			printf("Failed to free rq_transf.wq_dbr_daddr\n");
			err = -1;
		}

		/* Clean up wq_ring_daddr for rq_transf if created */
		if (app_ctx->rq_transf[i].wq_ring_daddr &&
			flexio_buf_dev_free(app_ctx->flexio_process, app_ctx->rq_transf[i].wq_ring_daddr)) {
			printf("Failed to free rq_transf.wq_ring_daddr\n");
			err = -1;
		}

		if (app_ctx->rq_transf[i].wqd_daddr &&
			flexio_buf_dev_free(app_ctx->flexio_process, app_ctx->rq_transf[i].wqd_daddr)) {
			printf("Failed to free rq_transf.wqd_daddr\n");
			err = -1;
		}

		if (app_ctx->flexio_rq_cq_ptr[i] && flexio_cq_destroy(app_ctx->flexio_rq_cq_ptr[i])) {
			printf("Failed to destroy RQ' CQ\n");
			err = -1;
		}

		if (app_ctx->rq_cq_transf[i].cq_ring_daddr &&
			flexio_buf_dev_free(app_ctx->flexio_process, app_ctx->rq_cq_transf[i].cq_ring_daddr)) {
			printf("Failed to free rq_cq_transf.cq_ring_daddr\n");
			err = -1;
		}

		if (app_ctx->rq_cq_transf[i].cq_dbr_daddr &&
			flexio_buf_dev_free(app_ctx->flexio_process, app_ctx->rq_cq_transf[i].cq_dbr_daddr)) {
			printf("Failed to free rq_cq_transf.cq_dbr_daddr\n");
			err = -1;
		}
	}

	return err;
}

/* Clean up previously allocated SQ
 * Returns 0 on success and -1 if the destroy failed.
 * app_ctx - app_ctx - pointer to app_context structure.
 */
static int clean_up_app_sq(struct app_context *app_ctx)
{
	int err = 0;
	int i;

	for (i = 0; i < thread_num; i++)
	{
		if (app_ctx->flexio_sq_ptr[i] && flexio_sq_destroy(app_ctx->flexio_sq_ptr[i])) {
			printf("Failed to destroy SQ\n");
			err = -1;
		}

		if (app_ctx->sqd_mkey[i] && flexio_device_mkey_destroy(app_ctx->sqd_mkey[i])) {
			printf("Failed to destroy mkey SQD\n");
			err = -1;
		}

		if (app_ctx->sq_transf[i].wq_ring_daddr &&
			flexio_buf_dev_free(app_ctx->flexio_process, app_ctx->sq_transf[i].wq_ring_daddr)) {
			printf("Failed to free sq_transf.wq_ring_daddr\n");
			err = -1;
		}

		if (app_ctx->sq_transf[i].wqd_daddr &&
			flexio_buf_dev_free(app_ctx->flexio_process, app_ctx->sq_transf[i].wqd_daddr)) {
			printf("Failed to free sq_transf.wqd_daddr\n");
			err = -1;
		}

		if (app_ctx->flexio_sq_cq_ptr[i] && flexio_cq_destroy(app_ctx->flexio_sq_cq_ptr[i])) {
			printf("Failed to destroy SQ' CQ\n");
			err = -1;
		}

		if (app_ctx->sq_cq_transf[i].cq_ring_daddr &&
			flexio_buf_dev_free(app_ctx->flexio_process, app_ctx->sq_cq_transf[i].cq_ring_daddr)) {
			printf("Failed to free sq_cq_transf.cq_ring_daddr\n");
			err = -1;
		}

		if (app_ctx->sq_cq_transf[i].cq_dbr_daddr &&
			flexio_buf_dev_free(app_ctx->flexio_process, app_ctx->sq_cq_transf[i].cq_dbr_daddr)) {
			printf("Failed to free sq_cq_transf.cq_dbr_daddr\n");
			err = -1;
		}
	}

	return err;
}

static void create_key_buffer(struct app_context *app_ctx)
{
    struct index_bucket *itable = 
		(struct index_bucket *)calloc(DPA_MAX_BUCKET, sizeof(struct index_bucket));
	if (itable == NULL) {
		printf("Failed to allocate data buffer\n");
		exit(-1);
	}

	long int host_itable_size = KEY_MAX_BUCKET * sizeof(struct index_bucket);
	host_itable = get_huge_mem(0, (host_itable_size + 63) & ~63);
	if (host_itable == NULL)
	{
		printf("Failed to allocate memory for host_itable\n");
		exit(-1);
	}
	memset(host_itable, 0, host_itable_size);
	struct ibv_mr *mr = ibv_reg_mr(app_ctx->process_pd, host_itable, host_itable_size, 
		IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_ATOMIC);
	app_ctx->host_itable = host_itable;
	app_ctx->host_itable_mkey = mr->lkey;

	/* No bucket is scheduled to CPU */
	select_group = rte_zmalloc("selectBucket", MAX_RULE * sizeof(uint8_t), 0);

    /* Set the key buffer to the DPA heap memory. */
	FILE *fp = fopen(key_file, "rb");
	if (fp == NULL) {
		printf("Failed to open key file\n");
		exit(-1);
	}
	
	int dpa_set = 0, dpa_loss = 0;
	int host_set = 0, host_loss = 0;
	uint32_t hash_mask = key_bucket - 1;
	size_t batch_size = 1024;
	uint32_t elements[batch_size][5];
	while (1) {
		size_t read_count = fread(elements, sizeof(elements[0]), batch_size, fp);
		if (read_count == 0) {
			break;
		}

		for (size_t j = 0; j < read_count; j++) {
			uint32_t key_index = elements[j][4] & hash_mask;
			if (key_index < DPA_MAX_BUCKET) {
				for (int i = 0; i < ENTRY_NUM; i++) {
					if (itable[key_index].entries[i].keys[0] == 0) {
						memcpy(itable[key_index].entries[i].keys, elements[j], sizeof(elements[j]));
						dpa_set++;
						break;
					} else if (i == ENTRY_NUM - 1) {
						dpa_loss++;
					}
				}
			}
			for (int i = 0; i < ENTRY_NUM; i++) {
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
	printf("DPA set %d keys, lost %d keys, host set %d keys, lost %d keys\n", 
		dpa_set, dpa_loss, host_set, host_loss);
	fclose(fp);

    flexio_uintptr_t data_daddr;
	long int size = DPA_MAX_BUCKET * sizeof(struct index_bucket);
    if (flexio_copy_from_host(app_ctx->flexio_process, (void *)itable, size, &data_daddr)) {
		printf("Failed to copy data to DPA\n");
		exit(-1);
	}
	printf("DPA: Successfully set key buffer\n");
	free(itable);
	
	app_ctx->dpa_itable = data_daddr;
	app_ctx->index_remap_table = (flexio_uintptr_t)NULL;
	
	return;
}

struct group_stat {
	uint64_t count;
	uint16_t group_id;
};

static int compare_group_stats(const void *a, const void *b) {
	struct group_stat *stat_a = (struct group_stat *)a;
	struct group_stat *stat_b = (struct group_stat *)b;
	// Sort descending by count
	if (stat_b->count > stat_a->count) return 1;
	if (stat_b->count < stat_a->count) return -1;
	return 0;
}

static void create_key_buffer_ipipe(struct app_context *app_ctx)
{
	struct index_bucket *itable = 
		(struct index_bucket *)calloc(DPA_MAX_BUCKET, sizeof(struct index_bucket));
	if (itable == NULL) {
		printf("Failed to allocate data buffer\n");
		exit(-1);
	}

	long int host_itable_size = KEY_MAX_BUCKET * sizeof(struct index_bucket);
	host_itable = get_huge_mem(0, (host_itable_size + 63) & ~63);
	if (host_itable == NULL) {
		printf("Failed to allocate memory for host_itable\n");
		exit(-1);
	}
	memset(host_itable, 0, host_itable_size);
	struct ibv_mr *mr = ibv_reg_mr(app_ctx->process_pd, host_itable, host_itable_size, 
		IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_ATOMIC);
	app_ctx->host_itable = host_itable;
	app_ctx->host_itable_mkey = mr->lkey;

	// Load key file into host and DPA memory
	FILE *key_fp = fopen(key_file, "rb");
	if (key_fp == NULL) {
		printf("Failed to open key file\n");
		exit(-1);
	}

	fseek(key_fp, 0, SEEK_END);
	long file_size = ftell(key_fp);
	long int num_keys = file_size / 20;
	printf("Found %ld keys in %s.\n", num_keys, key_file);
	rewind(key_fp);
	int NUM_HASH_GROUPS = MAX_RULE;
	int group_hash_mask = MAX_RULE - 1;
	uint16_t *key_group_map = (uint16_t *)malloc(num_keys * sizeof(uint16_t));
	uint64_t *group_counts = (uint64_t *)calloc(NUM_HASH_GROUPS, sizeof(uint64_t));

	size_t batch_size = 1024;
	int dpa_set = 0, dpa_loss = 0;
	int host_set = 0, host_loss = 0;
	uint32_t elements[batch_size][5];
	uint32_t hash_mask = key_bucket - 1;
	int idx = 0;
	while (1) {
		size_t read_count = fread(elements, sizeof(elements[0]), batch_size, key_fp);
		if (read_count == 0) {
			break;
		}

		for (size_t j = 0; j < read_count; j++) {
			uint32_t key_index = elements[j][4] & hash_mask;
			key_group_map[idx++] = (uint16_t)(elements[j][4] & group_hash_mask);
			if (key_index < DPA_MAX_BUCKET) {
				for (int i = 0; i < ENTRY_NUM; i++) {
					if (itable[key_index].entries[i].keys[0] == 0) {
						memcpy(itable[key_index].entries[i].keys, elements[j], sizeof(elements[j]));
						dpa_set++;
						break;
					} else if (i == ENTRY_NUM - 1) {
						dpa_loss++;
					}
				}
			}
			for (int i = 0; i < ENTRY_NUM; i++) {
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
	printf("DPA set %d keys, lost %d keys, host set %d keys, lost %d keys\n", 
		dpa_set, dpa_loss, host_set, host_loss);
	fclose(key_fp);

	flexio_uintptr_t data_daddr;
	long int size = DPA_MAX_BUCKET * sizeof(struct index_bucket);
	if (flexio_copy_from_host(app_ctx->flexio_process, (void *)itable, size, &data_daddr)) {
		printf("Failed to copy data to DPA\n");
		exit(-1);
	}
	printf("DPA: Successfully set key buffer\n");
	free(itable);
	app_ctx->dpa_itable = data_daddr;
	app_ctx->index_remap_table = (flexio_uintptr_t)NULL;

	select_group = rte_zmalloc("selectGroup", MAX_RULE * sizeof(uint8_t), 0);
	// Read key trace file and count bucket references
	FILE *trace_fp = fopen(key_trace, "rb");
	if (trace_fp == NULL) {
		printf("Failed to open key trace file\n");
		exit(-1);
	}

	uint32_t trace_indices[batch_size];
	while (1) {
		size_t read_count = fread(trace_indices, sizeof(trace_indices[0]), batch_size, trace_fp);
		if (read_count == 0) {
			break;
		}

		for (size_t j = 0; j < read_count; j++) {
			group_counts[key_group_map[trace_indices[j]]]++;
		}
	}
	fclose(trace_fp);
	free(key_group_map);
	
	struct group_stat *group_stats_sorted = (struct group_stat *)malloc(NUM_HASH_GROUPS * sizeof(struct group_stat));
	for (int i = 0; i < NUM_HASH_GROUPS; i++) {
        group_stats_sorted[i].count = group_counts[i];
        group_stats_sorted[i].group_id = (uint16_t)i;
    }
	qsort(group_stats_sorted, NUM_HASH_GROUPS, sizeof(struct group_stat), compare_group_stats);
	free(group_counts);
	printf("Marking top %d hottest groups for CPU processing...\n", cpu_hash_group);
    uint64_t hot_group_access_count = 0;
    for (int i = 0; i < cpu_hash_group && i < NUM_HASH_GROUPS; i++) {
		uint16_t hot_group_id = group_stats_sorted[i].group_id;
		select_group[hot_group_id] = 1; // Mark as hot
		hot_group_access_count += group_stats_sorted[i].count;
    }
    printf("Marked %d groups. Total accesses in marked groups: %lu (%.2f%% of total)\n",
		cpu_hash_group, hot_group_access_count,
		(double)hot_group_access_count * 100.0 / 1000000000);

    // Free the sorting structure
    free(group_stats_sorted);
    group_stats_sorted = NULL;

	return;
}

struct bucket_stat {
	uint64_t count;
	uint32_t bucket_id;
};

static int compare_bucket_stats(const void *a, const void *b) {
	struct bucket_stat *stat_a = (struct bucket_stat *)a;
	struct bucket_stat *stat_b = (struct bucket_stat *)b;
	// Sort descending by count
	if (stat_b->count > stat_a->count) return 1;
	if (stat_b->count < stat_a->count) return -1;
	return 0;
}

static void create_key_buffer_vela(struct app_context *app_ctx)
{
	int NUM_HASH_GROUPS = MAX_RULE;
	int group_hash_mask = MAX_RULE - 1;

	/* Allocate key index table */
	struct index_bucket *itable = 
		(struct index_bucket *)calloc(DPA_MAX_BUCKET, sizeof(struct index_bucket));
	if (itable == NULL) {
		printf("Failed to allocate data buffer\n");
		exit(-1);
	}

	long int host_itable_size = KEY_MAX_BUCKET * sizeof(struct index_bucket);
	host_itable = get_huge_mem(0, (host_itable_size + 63) & ~63);
	if (host_itable == NULL) {
		printf("Failed to allocate memory for host_itable\n");
		exit(-1);
	}
	memset(host_itable, 0, host_itable_size);
	struct ibv_mr *mr = ibv_reg_mr(app_ctx->process_pd, host_itable, host_itable_size, 
		IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_ATOMIC);
	app_ctx->host_itable = host_itable;
	app_ctx->host_itable_mkey = mr->lkey;

	/* Allocate tracking arrays */
	select_group = rte_zmalloc("selectGroup", MAX_RULE * sizeof(uint8_t), 0);	
	uint64_t *group_counts = (uint64_t *)calloc(NUM_HASH_GROUPS, sizeof(uint64_t));
	uint64_t *bucket_counts = (uint64_t *)calloc(key_bucket, sizeof(uint64_t));
	
	// Read key file to build key_group_map
	FILE *key_fp = fopen(key_file, "rb");
	if (key_fp == NULL) {
		printf("Failed to open key file\n");
		exit(-1);
	}

	fseek(key_fp, 0, SEEK_END);
	long file_size = ftell(key_fp);
	long int num_keys = file_size / 20;
	printf("Found %ld keys in %s.\n", num_keys, key_file);
	rewind(key_fp);
	uint16_t *key_group_map = (uint16_t *)malloc(num_keys * sizeof(uint16_t));
	uint32_t *key_bucket_map = (uint32_t *)malloc(num_keys * sizeof(uint32_t));
	size_t batch_size = 1024;
	uint32_t elements[batch_size][5];
	uint32_t hash_mask = key_bucket - 1;

	int idx = 0;
	while (1) {
		size_t read_count = fread(elements, sizeof(elements[0]), batch_size, key_fp);
		if (read_count == 0) {
			break;
		}

		for (size_t j = 0; j < read_count; j++) {
			key_group_map[idx] = (uint16_t)(elements[j][4] & group_hash_mask);
			key_bucket_map[idx] = (uint32_t)(elements[j][4] & hash_mask);
			idx++;
		}
	}
	fclose(key_fp);
	key_fp = NULL;

	// Read key trace file and count bucket references
	FILE *trace_fp = fopen(key_trace, "rb");
	if (trace_fp == NULL) {
		printf("Failed to open key trace file\n");
		exit(-1);
	}

	uint32_t trace_indices[batch_size];
	while (1) {
		size_t read_count = fread(trace_indices, sizeof(trace_indices[0]), batch_size, trace_fp);
		if (read_count == 0) {
			break;
		}

		for (size_t j = 0; j < read_count; j++) {
			group_counts[key_group_map[trace_indices[j]]]++;
			bucket_counts[key_bucket_map[trace_indices[j]]]++;
		}
	}
	fclose(trace_fp);
	free(key_group_map);
	free(key_bucket_map);
	trace_fp = NULL;
	key_group_map = NULL;
	key_bucket_map = NULL;

	struct group_stat *group_stats_sorted = (struct group_stat *)malloc(NUM_HASH_GROUPS * sizeof(struct group_stat));
	for (int i = 0; i < NUM_HASH_GROUPS; i++) {
        group_stats_sorted[i].count = group_counts[i];
        group_stats_sorted[i].group_id = (uint16_t)i;
    }
	qsort(group_stats_sorted, NUM_HASH_GROUPS, sizeof(struct group_stat), compare_group_stats);
	free(group_counts);
	group_counts = NULL;

	// // Mark Coldest Groups in select_group
	// int num_to_mark = (cpu_hash_group < MAX_RULE) ? cpu_hash_group : MAX_RULE;
	// printf("Marking %d coldest groups for CPU processing...\n", num_to_mark);
	// uint64_t cold_group_access_count = 0;
	// // Coldest groups are at the *end* of the sorted list
	// for (int i = 0; i < num_to_mark; i++) {
	// 	uint32_t cold_rank_index = MAX_RULE - 1 - i; // Index from the end
	// 	uint32_t original_cold_group_id = group_stats_sorted[cold_rank_index].group_id;
	// 	select_group[original_cold_group_id] = 1; // Mark original ID as cold
	// 	cold_group_access_count += group_stats_sorted[cold_rank_index].count;
	// }
	// printf("Marked %d groups. Total accesses in marked cold groups: %lu (%.2f%% of total)\n",
	// 	num_to_mark, cold_group_access_count,
	// 	(double)cold_group_access_count * 100.0 / 1000000000);

	// Mark Hottest Groups in select_group
	printf("Marking top %d hottest groups for CPU processing...\n", cpu_hash_group);
    uint64_t hot_group_access_count = 0;
    for (int i = cpu_bypass; i < cpu_hash_group + cpu_bypass && i < NUM_HASH_GROUPS; i++) {
		uint16_t hot_group_id = group_stats_sorted[i].group_id;
		select_group[hot_group_id] = 1; // Mark as hot
		hot_group_access_count += group_stats_sorted[i].count;
    }
    printf("Marked %d groups. Total accesses in marked groups: %lu (%.2f%% of total)\n",
		cpu_hash_group, hot_group_access_count,
		(double)hot_group_access_count * 100.0 / 1000000000);

	// Free sorting structure, no longer needed
	free(group_stats_sorted);
	group_stats_sorted = NULL;

	// Build index remapping table
	uint32_t *index_remap_table = (uint32_t *)calloc(key_bucket, sizeof(uint32_t));
	printf("Building index remapping table...\n");
	// Sort buckets count, if the bucket does not allocate to CPU, assign to host range
	struct bucket_stat *bucket_stats_sorted = (struct bucket_stat *)malloc(key_bucket * sizeof(struct bucket_stat));
	for (uint32_t i = 0; i < key_bucket; i++) {
		bucket_stats_sorted[i].count = bucket_counts[i];
		bucket_stats_sorted[i].bucket_id = i;
	}
	qsort(bucket_stats_sorted, key_bucket, sizeof(struct bucket_stat), compare_bucket_stats);
	free(bucket_counts);
	bucket_counts = NULL;
	
	uint32_t current_physical_idx = 0;
	uint64_t local_mem_access_count = 0;
	for (uint32_t i = 0; i < key_bucket; i++) {
		uint32_t orignal_bucket_id = bucket_stats_sorted[i].bucket_id;
		uint32_t original_group_id = orignal_bucket_id & group_hash_mask;
		if (select_group[original_group_id] == 0 && current_physical_idx < DPA_MAX_BUCKET) {
			index_remap_table[orignal_bucket_id] = current_physical_idx++;
			local_mem_access_count += bucket_stats_sorted[i].count;
		}
		else {
			index_remap_table[orignal_bucket_id] = DPA_MAX_BUCKET;
		}
	}
	printf("Total buckets: %d, buckets allocated to DPA: %d, total access: %.2f%% of total\n",
		key_bucket, current_physical_idx, local_mem_access_count * 100.0 / 1000000000);

	// Read key file to populate key buffer using remapping
	int dpa_set = 0, dpa_loss = 0;
	int host_set = 0, host_loss = 0;
	key_fp = fopen(key_file, "rb");
	if (key_fp == NULL) {
		printf("Failed to open key file\n");
		exit(-1);
	}
    printf("Populating unified buffer using remapped indices...\n");

	idx = 0;
	while (1) {
		size_t read_count = fread(elements, sizeof(elements[0]), batch_size, key_fp);
		if (read_count == 0) {
			break;
		}

		for (size_t j = 0; j < read_count; j++) {
			uint32_t key_index = elements[j][4] & hash_mask;
			uint32_t remap_index = index_remap_table[key_index];
			if (remap_index < DPA_MAX_BUCKET) {
				for (int i = 0; i < ENTRY_NUM; i++) {
					if (itable[remap_index].entries[i].keys[0] == 0) {
						memcpy(itable[remap_index].entries[i].keys, elements[j], sizeof(elements[j]));
						dpa_set++;
						break;
					} else if (i == ENTRY_NUM - 1) {
						dpa_loss++;
					}
				}
			}
			for (int i = 0; i < ENTRY_NUM; i++) {
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
	printf("DPA set %d keys, lost %d keys, host set %d keys, lost %d keys\n", 
		dpa_set, dpa_loss, host_set, host_loss);
	fclose(key_fp);

	flexio_uintptr_t data_daddr;
	long int size = DPA_MAX_BUCKET * sizeof(struct index_bucket);
	if (flexio_copy_from_host(app_ctx->flexio_process, (void *)itable, size, &data_daddr)) {
		printf("Failed to copy data to DPA\n");
		exit(-1);
	}
	printf("DPA: Successfully set key buffer\n");
	free(itable);
	app_ctx->dpa_itable = data_daddr;

	size = key_bucket * sizeof(uint32_t);
	if (flexio_copy_from_host(app_ctx->flexio_process, (void *)index_remap_table, size, &data_daddr)) {
		printf("Failed to copy index remap table to DPA\n");
		exit(-1);
	}
	printf("DPA: Successfully set index remap table\n");
	free(index_remap_table);
	app_ctx->index_remap_table = data_daddr;

	return;
}

static bool force_quit = false;
static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		force_quit = true;
	}
}

/* dev msg stream buffer built from chunks of 2^FLEXIO_MSG_DEV_LOG_DATA_CHUNK_BSIZE each */
#define MSG_HOST_BUFF_BSIZE (512 * L2V(FLEXIO_MSG_DEV_LOG_DATA_CHUNK_BSIZE))
/* Main host side function.
 * Responsible for allocating resources and making preparations for DPA side envocatin.
 */
int main(int argc, char **argv)
{
	/* Message stream attributes. */
	flexio_msg_stream_attr_t stream_fattr = {0};
	/* Application context. */
	// struct app_context app_ctx = {0};
	struct app_context *app_ctx;
	app_ctx = calloc(1, sizeof(struct app_context));
	if (!app_ctx) {
		printf("Failed to allocate app context\n");
		return -1;
	}
	/* Pointer to the application Flex IO process (ease of use). */
	// struct flexio_process *app_fp;
	/* Debug token */
	uint64_t udbg_token;
	/* Mode of working - for nic (host) or for dpu (default) */
	int nic_mode = 0;
	/* Buffer for fread */
	char buf[2];
	/* Execution status value. */
	int err;
	int i;

	/* DPDK initialization */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		printf("Failed to initialize DPDK\n");
		return -1;
	}
	argc -= ret;
	argv += ret;

	/* Flex IO initialization */
	printf("Welcome to 'Flex IO SDK packet processing' sample app.\n");

	/* Check input includes a device name. */
	if (argc < 7) {
		printf("Usage: %s <mlx5 device> <thread_num> <app> <queue> <key_file> <key_bucket> <key_trace> <cpu_bucket>\n", argv[0]);
		return -1;
	}

	thread_num = atoi(argv[2]);
	printf("Launch %d DPA threads.\n", thread_num);

	strncpy(app_name, argv[3], MAX_FNAME-1);
	printf("App name is %s.\n", app_name);

	nb_queue = atoi(argv[4]);
	printf("Queue number is %d.\n", nb_queue);

	strncpy(key_file, argv[5], MAX_FNAME-1);
	printf("Key file is %s.\n", key_file);

	key_bucket = strtol(argv[6], NULL, 0);
	printf("Bucket number is %d.\n", key_bucket);

	if (argc >= 9) {
		strncpy(key_trace, argv[7], MAX_FNAME-1);
		printf("Key trace file is %s.\n", key_trace);
		cpu_hash_group = strtol(argv[8], NULL, 0);
		printf("CPU hash group number is %d.\n", cpu_hash_group);
	}

	if (argc == 10) {
		cpu_bypass = atoi(argv[9]);
		printf("CPU bypass group is %d.\n", cpu_bypass);
	}

	/* Check if the application run with root privileges */
	if (geteuid()) {
		printf("Failed - the application must run with root privileges\n");
		return -1;
	}

	/* Create an IBV device context by opening the provided IBV device. */
	err = app_open_ibv_ctx(app_ctx, argv[1]);
	if (err)
		return -1;
	if (strcmp(argv[1], "mlx5_0") == 0)
		port = 0;
	else
		port = 1;

	/* Create a Flex IO process.
	 * The flexio_app struct (created by DPACC) is passed to load the program.
	 * No process creation attributes are needed for this application (default outbox).
	 * Created SW struct will be returned through the given pointer.
	 */
	if (flexio_process_create(app_ctx->ibv_ctx, DEV_APP_NAME, NULL, &app_fp)) {
		printf("Failed to create Flex IO process.\n");
		err = -1;
		goto cleanup;
	}
	app_ctx->flexio_process = app_fp;

	/* Get the token for user debug access to the Flex IO process. */
	udbg_token = flexio_process_udbg_token_get(app_ctx->flexio_process);

	/* If the token is 0, user debug access for the process is not allowed.
	 * If the token is not 0, the user can attach the FlexIO debugger to the process,
	 * set breakpoints, and debug the device application.
	 */
	if (udbg_token)
		printf("Use the token >>> %#lx <<< for debugging\n", udbg_token);

	/* Create a Flex IO message stream for process.
	 * Size of single message stream is MSG_HOST_BUFF_BSIZE.
	 * Working mode is synchronous.
	 * Level of debug in INFO.
	 * Output is stdout.
	 */
	stream_fattr.data_bsize = MSG_HOST_BUFF_BSIZE;
	stream_fattr.sync_mode = FLEXIO_LOG_DEV_SYNC_MODE_SYNC;
	stream_fattr.level = FLEXIO_MSG_DEV_INFO;
	if (flexio_msg_stream_create(app_fp, &stream_fattr, stdout, NULL,
				     &app_ctx->stream)) {
		printf("Failed to init device messaging environment, exiting App\n");
		err = -1;
		goto cleanup;
	}

	app_ctx->process_pd = flexio_process_get_pd(app_fp);
	app_ctx->process_uar = flexio_process_get_uar(app_fp);

	if (flexio_window_create(app_ctx->flexio_process, app_ctx->process_pd, &app_ctx->flexio_window)) {
		printf("Failed to create Flex IO window\n");
		err = -1;
		goto cleanup;
	}

	create_steering_matcher(app_ctx, nic_mode);

	for (i = 0; i < thread_num; i++)
	{
		/* Create an event handler. */
		if (create_app_event_handler(app_ctx, i)) {
			printf("Failed to create Flex IO event handler.\n");
			err = -1;
			goto cleanup;
		}

		/* Create a Flex IO SQ to send packets from the DPA. */
		if (create_app_sq(app_ctx, i)) {
			printf("Failed to create Flex SQ.\n");
			err = -1;
			goto cleanup;
		}

		/* Create a Flex IO RQ to receive packets on the DPA.
		* CQEs for received packets will trigger the packet processing event handler.
		*/
		if (create_app_rq(app_ctx, i)) {
			printf("Failed to create Flex EQ.\n");
			err = -1;
			goto cleanup;
		}
	}

	/* Create steering rules. */
	if (strncmp(app_name, "dpdk", strlen("dpdk")) == 0)
	{
		create_key_buffer(app_ctx);
	}
	else if (strncmp(app_name, "gallium", strlen("gallium")) == 0)
	{
		create_key_buffer(app_ctx);
		if (create_steering_rules_rx(app_ctx)) {
			printf("Failed to create Flex IO steering rules.\n");
			err = -1;
			goto cleanup;
		}
	}
	else if (strncmp(app_name, "ipipe", strlen("ipipe")) == 0)
	{
		create_key_buffer_ipipe(app_ctx);
		if (create_steering_rules_rx(app_ctx)) {
			printf("Failed to create Flex IO steering rules.\n");
			err = -1;
			goto cleanup;
		}
	}
	else if (strncmp(app_name, "vela", strlen("vela")) == 0)
	{
		create_key_buffer_vela(app_ctx);
		if (create_steering_rules_rx(app_ctx)) {
			printf("Failed to create Flex IO steering rules.\n");
			err = -1;
			goto cleanup;
		}
	}

	if (create_steering_rules_tx(app_ctx, nic_mode)) {
		printf("Failed to create Flex IO steering rules.\n");
		err = -1;
		goto cleanup;
	}

	for (i = 0; i < thread_num; i++)
	{
		/* Copy the relevant information to DPA. */
		if (copy_app_data_to_dpa(app_ctx, i, port)) {
			printf("Failed to copy application data to DPA.\n");
			err = -1;
			goto cleanup;
		}
	
		// printf("[%d] Ready to receive messages\n", i);

		/* Start event handler - move from the init state to the running state.
		* Event handlers in the running state may be invoked by an incoming CQE.
		* On other states, the invocation is blocked and lost.
		* Pass the address of common information as a user argument to be used on the DPA side.
		*/
		if (flexio_event_handler_run(app_ctx->pp_eh[i], app_ctx->app_data_daddr[i])) {
			printf("Failed to run event handler.\n");
			err = -1;
			goto cleanup;
		}
	}

	signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

	dpdk_init(app_name);
	rte_eal_mp_remote_launch(mcrouter_main_loop, NULL, SKIP_MAIN);
	
	uint64_t rpc_ret;
	while (!force_quit)
	{
		sleep(1);
		flexio_process_call(app_ctx->flexio_process, &itable_counter_get, &rpc_ret, thread_num);
	}
	exit(0);
	
	/* Wait for Enter - the DPA sample is running in the meanwhile */
	if (!fread(buf, 1, 1, stdin)) {
		printf("Failed in fread\n");
	}

cleanup:
	/* Clean up flow is done in reverse order of creation as there's a refernce system
	 * that won't allow destroying resources that has references to existing resources.
	 */

	for (i = 0; i < thread_num; i++)
	{
		/* Clean up app data daddr if created */
		if (app_ctx->app_data_daddr[i] &&
			flexio_buf_dev_free(app_ctx->flexio_process, app_ctx->app_data_daddr[i])) {
			printf("Failed to dealloc application data memory on Flex IO heap\n");
			err = -1;
		}
	}

	/* Clean up previously created rules */
	if (clean_up_rules(app_ctx)) {
		err = -1;
	}

	/* Clean up previously allocated SQ */
	if (clean_up_app_sq(app_ctx)) {
		err = -1;
	}

	/* Clean up previously allocated RQ */
	if (clean_up_app_rq(app_ctx)) {
		err = -1;
	}

	for (i = 0; i < thread_num; i++)
	{
		/* Destroy event handler if created */
		if (app_ctx->pp_eh[i] &&
			flexio_event_handler_destroy(app_ctx->pp_eh[i])) {
			printf("Failed to destroy event handler\n");
			err = -1;
		}
	}

	/* Destroy message stream if created */
	if (app_fp && flexio_msg_stream_destroy(app_ctx->stream)) {
		printf("Failed to destroy device messaging environment\n");
		err = -1;
	}

	/* Destroy the Flex IO process */
	if (flexio_process_destroy(app_fp)) {
		printf("Failed to destroy process.\n");
		err = -1;
	}

	/* Close the IBV device */
	if (ibv_close_device(app_ctx->ibv_ctx)) {
		printf("Failed to close ibv context.\n");
		err = -1;
	}

	return err;
}
