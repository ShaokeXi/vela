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

/* Used for host (x86/DPU) memory allocations. */
#include <malloc.h>

/* Used for IBV device operations. */
#include <infiniband/verbs.h>
#include <infiniband/mlx5_api.h>
#include <infiniband/mlx5dv.h>

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

/* Flex IO packet processor application struct.
 * Created by DPACC during compilation. The DEV_APP_NAME
 * is a macro transferred from Meson through gcc, with the
 * same name as the created application.
 */
extern struct flexio_app *DEV_APP_NAME;
/* Flex IO packet processor device (DPA) side function stub. */
extern flexio_func_t benchmark_function;
extern flexio_func_t benchmark_get_results;
extern flexio_func_t flexio_pp_dev;

static int thread_num = 1;
static int base_num = 0;
static int port = 0;
static int rpc_test = 0;
static int op_count = 0;
static struct memory_op ops[MAX_OPS];

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
	struct flow_rule *rx_rule[MAX_THREADS];
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

	/* Per thread data buffer */
	flexio_uintptr_t dpa_buf[MAX_THREADS];
	void *host_buf[MAX_THREADS];
	uint32_t host_mkey[MAX_THREADS];
	uint32_t data_size;
	uint32_t per_thread_data_size;
	
	/* Global data buffer */
	flexio_uintptr_t dpa_buf_global;
	void *host_buf_global;
	uint32_t host_mkey_global;
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
	app_ctx->rx_matcher = create_matcher_rx_ip(app_ctx->ibv_ctx);
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
#define SMAC_1 	0x02824d741cd0
#define SMAC_2 	0x026aa27afbee
#define SIP	 	0xc0a80001
/* Creates steering rules for application.
 * Returns 0 on success and -1 if the allocation was failed.
 * app_ctx - pointer to app_context structure.
 * nic_mode - if set to 1, the sample runs on ConnectX part.
 */
static int create_steering_rules(struct app_context *app_ctx, int nic_mode, unsigned int tid)
{
	/* Create RX flow rule for the specific source MAC of incoming packets. */
	app_ctx->rx_rule[tid] =
		create_rule_rx_ip_match(app_ctx->rx_matcher,
					flexio_rq_get_tir(app_ctx->flexio_rq_ptr[tid]), SIP+tid);
	if (!app_ctx->rx_rule[tid]) {
		printf("Failed to create RX steering rule\n");
		return -1;
	}

	/* If the sample runs on NIC, the outgoing rule is already configured.
	 * If the sample runs on DPU, the outgoing rule is configured as a DROP rule,
	 * so the sample needs to reconfigure the outgoing rule.
	 */
	if (!nic_mode) {

		/* Create a TX flow rule to forward outgoing packets to SW steering table. */
		if (port == 0)
			app_ctx->tx_rule_table[tid] = create_rule_tx_fwd_to_sws_table(app_ctx->tx_matcher, SMAC_1);
		else
			app_ctx->tx_rule_table[tid] = create_rule_tx_fwd_to_sws_table(app_ctx->tx_matcher, SMAC_2);
		if (!app_ctx->tx_rule_table[tid]) {
			printf("Failed to create TX table steering rule\n");
			return -1;
		}

		/* Create a TX flow rule to forward outgoing packets to vport (wire). */
		if (port == 0)
			app_ctx->tx_rule_vport[tid] = create_rule_tx_fwd_to_vport(app_ctx->tx_matcher, SMAC_1);
		else
			app_ctx->tx_rule_vport[tid] = create_rule_tx_fwd_to_vport(app_ctx->tx_matcher, SMAC_2);
		if (!app_ctx->tx_rule_vport[tid]) {
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

	/* Set data buf */
	h2d_data->dpa_buf = app_ctx->dpa_buf[tid];
	h2d_data->host_buf = app_ctx->host_buf[tid];
	h2d_data->host_mkey = app_ctx->host_mkey[tid];
	h2d_data->dpa_buf_global = app_ctx->dpa_buf_global;
	h2d_data->host_buf_global = app_ctx->host_buf_global;
	h2d_data->host_mkey_global = app_ctx->host_mkey_global;

	h2d_data->data_size = app_ctx->data_size;
	h2d_data->per_thread_data_size = app_ctx->per_thread_data_size;
	h2d_data->op_count = op_count;
	for (int i = 0; i < op_count; i++)
	{
		h2d_data->ops[i] = ops[i];
	}

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
		if (app_ctx->rx_rule[i] && destroy_rule(app_ctx->rx_rule[i])) {
			printf("Failed to destroy rx rule\n");
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

static flexio_uintptr_t get_data_buffer(struct app_context *app_ctx, size_t size)
{
    void *data = malloc(size);
	if (data == NULL) {
		printf("Failed to allocate data buffer\n");
		exit(-1);
	}

    for (size_t i = 0; i < size / (sizeof(size_t)); i++) {
        ((uint64_t *)data)[i] = i + 10;
    }

    flexio_uintptr_t data_daddr;
    if (flexio_copy_from_host(app_ctx->flexio_process, data, size, &data_daddr)) {
		printf("Failed to copy data to DPA\n");
		exit(-1);
	}
    return data_daddr;
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
	struct app_context app_ctx = {0};
	/* Pointer to the application Flex IO process (ease of use). */
	struct flexio_process *app_fp;
	/* Debug token */
	uint64_t udbg_token;
	/* Mode of working - for nic (host) or for dpu (default) */
	int nic_mode = 0;
	/* Buffer for fread */
	char buf[2];
	/* Execution status value. */
	int err;
	int i;

	printf("Welcome to 'Flex IO SDK packet processing' sample app.\n");

	/* Check input includes a device name. */
	if (argc < 5) {
		printf("Usage: %s <mlx5 device> <thread_num> <base_num> --op <opt_type,data_size,opt_num,opt_size> [--op <opt_type,data_size,opt_num,opt_size> ...] [--nic-mode]\n", argv[0]);
		return -1;
	}

	int arg_index = 4;
	uint32_t data_size = 0;
	while (arg_index < argc) {
		if (strcmp(argv[arg_index], "--op") == 0) {
			if (arg_index + 1 >= argc) {
				printf("Missing parameters for --op\n");
				return -1;
			}
			char *op_params = argv[arg_index + 1];
			char *token = strtok(op_params, ",");
			if (token == NULL) {
				printf("Invalid parameters for --op\n");
				return -1;
			}
			ops[op_count].opt_type = atoi(token);

			token = strtok(NULL, ",");
			if (token == NULL) {
				printf("Invalid parameters for --op\n");
				return -1;
			}
			ops[op_count].data_size = atoi(token);
			if (ops[op_count].data_size > data_size)
			{
				/* Allocate the maximum buffer required for any of the operations */
				data_size = ops[op_count].data_size;
			}

			token = strtok(NULL, ",");
			if (token == NULL) {
				printf("Invalid parameters for --op\n");
				return -1;
			}
			ops[op_count].opt_num = atoi(token);

			token = strtok(NULL, ",");
			if (token == NULL) {
				printf("Invalid parameters for --op\n");
				return -1;
			}
			ops[op_count].opt_size = atoi(token);

			op_count++;
			arg_index += 2;
		} else if (strcmp(argv[arg_index], "--nic-mode") == 0) {
			nic_mode = 1;
			arg_index++;
		} else {
			printf("Unknown argument: %s\n", argv[arg_index]);
			return -1;
		}
	}

	thread_num = atoi(argv[2]);
	printf("Launch %d DPA threads.\n", thread_num);

	base_num = atoi(argv[3]);
	printf("Base number is %d.\n", base_num);

	/* Check if the application run with root privileges */
	if (geteuid()) {
		printf("Failed - the application must run with root privileges\n");
		return -1;
	}

	/* Create an IBV device context by opening the provided IBV device. */
	err = app_open_ibv_ctx(&app_ctx, argv[1]);
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
	if (flexio_process_create(app_ctx.ibv_ctx, DEV_APP_NAME, NULL, &app_fp)) {
		printf("Failed to create Flex IO process.\n");
		err = -1;
		goto cleanup;
	}
	app_ctx.flexio_process = app_fp;

	/* Get the token for user debug access to the Flex IO process. */
	udbg_token = flexio_process_udbg_token_get(app_ctx.flexio_process);

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
				     &app_ctx.stream)) {
		printf("Failed to init device messaging environment, exiting App\n");
		err = -1;
		goto cleanup;
	}

	app_ctx.process_pd = flexio_process_get_pd(app_fp);
	app_ctx.process_uar = flexio_process_get_uar(app_fp);

	if (flexio_window_create(app_ctx.flexio_process, app_ctx.process_pd, &app_ctx.flexio_window)) {
		printf("Failed to create Flex IO window\n");
		err = -1;
		goto cleanup;
	}

	create_steering_matcher(&app_ctx, nic_mode);

	/* Create flexio cmdq */
	struct flexio_cmdq_attr cmdq_fattr;
	cmdq_fattr.workers = thread_num;
	cmdq_fattr.batch_size = 1; /* one rpc per thread */
	cmdq_fattr.state = FLEXIO_CMDQ_STATE_PENDING;
	struct flexio_cmdq *cmd_q;
	if (flexio_cmdq_create(app_ctx.flexio_process, &cmdq_fattr, &cmd_q))
	{
		printf("Failed to create Flex IO cmdq\n");
		err = -1;
		goto cleanup;
	}

	int new_thread_num = 1;
	while (new_thread_num < thread_num) {
		new_thread_num <<= 1;
	}
	int mem_size = new_thread_num * data_size;
	app_ctx.dpa_buf_global = get_data_buffer(&app_ctx, mem_size);
	app_ctx.host_buf_global = get_huge_mem(0, (mem_size + 63) & (~63));
	memset(app_ctx.host_buf_global, 0, mem_size);
	struct ibv_mr *mr = ibv_reg_mr(app_ctx.process_pd, app_ctx.host_buf_global, mem_size, 
		IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_ATOMIC);
	app_ctx.host_mkey_global = mr->lkey;
	for (i = 0; i < thread_num; i++)
	{
		app_ctx.dpa_buf[i] = app_ctx.dpa_buf_global + i * data_size;
		app_ctx.host_buf[i] = (void*)((char*)app_ctx.host_buf_global + i * data_size);
		app_ctx.host_mkey[i] = app_ctx.host_mkey_global;
	}
	for (i = 0; i < op_count; i++)
	{
		/* Allow random access to global data by each thread */
		ops[i].data_size = data_size * new_thread_num;
	}
	app_ctx.per_thread_data_size = data_size;
	app_ctx.data_size = data_size * new_thread_num;

	for (i = 0; i < thread_num; i++)
	{
		/* Create an event handler. */
		if (create_app_event_handler(&app_ctx, i)) {
			printf("Failed to create Flex IO event handler.\n");
			err = -1;
			goto cleanup;
		}

		/* Create a Flex IO SQ to send packets from the DPA. */
		if (create_app_sq(&app_ctx, i)) {
			printf("Failed to create Flex SQ.\n");
			err = -1;
			goto cleanup;
		}

		/* Create a Flex IO RQ to receive packets on the DPA.
		* CQEs for received packets will trigger the packet processing event handler.
		*/
		if (create_app_rq(&app_ctx, i)) {
			printf("Failed to create Flex EQ.\n");
			err = -1;
			goto cleanup;
		}

		/* Create steering rules. */
		if (create_steering_rules(&app_ctx, nic_mode, i)) {
			printf("Failed to create Flex IO steering rules.\n");
			err = -1;
			goto cleanup;
		}

		/* Copy the relevant information to DPA. */
		if (copy_app_data_to_dpa(&app_ctx, i, port)) {
			printf("Failed to copy application data to DPA.\n");
			err = -1;
			goto cleanup;
		}
	
		if (rpc_test) {
			flexio_cmdq_task_add(cmd_q, benchmark_function, app_ctx.app_data_daddr[i]);
		}
		
		/* Start event handler - move from the init state to the running state.
		* Event handlers in the running state may be invoked by an incoming CQE.
		* On other states, the invocation is blocked and lost.
		* Pass the address of common information as a user argument to be used on the DPA side.
		*/
		if (flexio_event_handler_run(app_ctx.pp_eh[i], app_ctx.app_data_daddr[i])) {
			printf("Failed to run event handler.\n");
			err = -1;
			goto cleanup;
		}
	}

	if (rpc_test)
	{
		int useconds = 0;
		int step_us = 1000;
		int time_out_seconds = 300;
		flexio_cmdq_state_running(cmd_q);
		while (!flexio_cmdq_is_empty(cmd_q)) {
			usleep(step_us);
			useconds += step_us;
			if (useconds > time_out_seconds * 1e6)
			{
				printf("Flexio Cmdq Timeout\n");
				exit(-1);
			}
		}

		uint64_t rpc_ret;
		if (flexio_process_call(app_ctx.flexio_process, &benchmark_get_results, &rpc_ret, thread_num)) {
			printf("Failed to call Flex IO process\n");
			err = -1;
			goto cleanup;
		}
		
		switch (ops[0].opt_type)
		{
			case CYCLE:
				printf("__dpa_thread_cycles: %lu/s\n", rpc_ret);
				exit(0);
			case READ_DPA:
				printf("dpa read: %.3f GB/s\n", rpc_ret/1000000000.0);
				exit(0);
			case READ_DPA_RANDOM:
				printf("dpa random read: %.3f GB/s\n", rpc_ret/1000000000.0);
				exit(0);
			case WRITE_DPA:
				printf("dpa write: %.3f GB/s\n", rpc_ret/1000000000.0);
				exit(0);
			case WRITE_DPA_RANDOM:
				printf("dpa random write: %.3f GB/s\n", rpc_ret/1000000000.0);
				exit(0);
			case READ_ARM:
				printf("arm read: %.3f GB/s\n", rpc_ret/1000000000.0);
				exit(0);
			case READ_ARM_RANDOM:
				printf("arm random read: %.3f GB/s\n", rpc_ret/1000000000.0);
				exit(0);
			case WRITE_ARM:
				printf("arm write: %.3f GB/s\n", rpc_ret/1000000000.0);
				exit(0);
			case WRITE_ARM_RANDOM:
				printf("arm random write: %.3f GB/s\n", rpc_ret/1000000000.0);
				exit(0);
			case ATOMIC_READ_DPA:
				printf("dpa atomic read: %.3f GB/s\n", rpc_ret/1000000000.0);
				exit(0);
			case ATOMIC_READ_DPA_RANDOM:
				printf("dpa atomic random read: %.3f GB/s\n", rpc_ret/1000000000.0);
				exit(0);
			case ATOMIC_WRITE_DPA:
				printf("dpa atomic write: %.3f GB/s\n", rpc_ret/1000000000.0);
				exit(0);
			case ATOMIC_WRITE_DPA_RANDOM:
				printf("dpa atomic random write: %.3f GB/s\n", rpc_ret/1000000000.0);
				exit(0);
			case ATOMIC_READ_ARM:
				printf("arm atomic read: %.3f GB/s\n", rpc_ret/1000000000.0);
				exit(0);
			case ATOMIC_READ_ARM_RANDOM:
				printf("arm atomic random read: %.3f GB/s\n", rpc_ret/1000000000.0);
				exit(0);
			case ATOMIC_WRITE_ARM:
				printf("arm atomic write: %.3f GB/s\n", rpc_ret/1000000000.0);
				exit(0);
			case ATOMIC_WRITE_ARM_RANDOM:
				printf("arm atomic random write: %.3f GB/s\n", rpc_ret/1000000000.0);
				exit(0);
		}
	}

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
		if (app_ctx.app_data_daddr[i] &&
			flexio_buf_dev_free(app_ctx.flexio_process, app_ctx.app_data_daddr[i])) {
			printf("Failed to dealloc application data memory on Flex IO heap\n");
			err = -1;
		}
	}

	/* Clean up previously created rules */
	if (clean_up_rules(&app_ctx)) {
		err = -1;
	}

	/* Clean up previously allocated SQ */
	if (clean_up_app_sq(&app_ctx)) {
		err = -1;
	}

	/* Clean up previously allocated RQ */
	if (clean_up_app_rq(&app_ctx)) {
		err = -1;
	}

	for (i = 0; i < thread_num; i++)
	{
		/* Destroy event handler if created */
		if (app_ctx.pp_eh[i] &&
			flexio_event_handler_destroy(app_ctx.pp_eh[i])) {
			printf("Failed to destroy event handler\n");
			err = -1;
		}
	}

	/* Destroy message stream if created */
	if (app_fp && flexio_msg_stream_destroy(app_ctx.stream)) {
		printf("Failed to destroy device messaging environment\n");
		err = -1;
	}

	/* Destroy the Flex IO process */
	if (flexio_process_destroy(app_fp)) {
		printf("Failed to destroy process.\n");
		err = -1;
	}

	/* Close the IBV device */
	if (ibv_close_device(app_ctx.ibv_ctx)) {
		printf("Failed to close ibv context.\n");
		err = -1;
	}

	return err;
}
