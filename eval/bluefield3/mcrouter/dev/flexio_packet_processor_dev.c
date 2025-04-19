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
/* Source file for device part of packet processing sample.
 * Contain functions for initialize contexts of internal queues,
 * read, check, change and resend the packet and wait for another.
 */

/* Shared header file with utilities for samples.
 * The file also have includes to flexio_dev_ver.h and flexio_dev.h
 * The include must be placed first to correctly handle the version.
 */
#include "com_dev.h"
#include <libflexio-dev/flexio_dev_err.h>
#include <libflexio-dev/flexio_dev_queue_access.h>
#include <libflexio-dev/flexio_dev.h>
#include <libflexio-libc/string.h>
#include <stddef.h>
#include <dpaintrin.h>

/* Shared header file for packet processor sample */
#include "../flexio_packet_processor_com.h"

/* Mask for CQ index */
#define CQ_IDX_MASK ((1 << LOG_CQ_DEPTH) - 1)
/* Mask for RQ index */
#define RQ_IDX_MASK ((1 << LOG_RQ_DEPTH) - 1)
/* Mask for SQ index */
#define SQ_IDX_MASK ((1 << (LOG_SQ_DEPTH + LOG_SQE_NUM_SEGS)) - 1)
/* Mask for data index */
#define DATA_IDX_MASK ((1 << (LOG_SQ_DEPTH)) - 1)

typedef struct host_rq_ctx_t {
    uint32_t rkey;            /* receive memory key, used for receive queue */
    uint32_t rq_window_id;

    void *host_rx_buff;
    flexio_uintptr_t dpa_rx_buff;
} host_rq_ctx_t;

typedef struct host_sq_ctx_t {
    uint32_t rkey;
    uint32_t sq_window_id;

    void *host_tx_buff;
    flexio_uintptr_t dpa_tx_buff;
} host_sq_ctx_t;


/* The structure of the sample DPA application contains global data that the application uses */
static struct {
	/* Packet count - used for debug message */
	uint64_t packets_count;
	uint64_t bytes_count;
	/* lkey - local memory key */
	uint32_t lkey;

	cq_ctx_t rq_cq_ctx;     /* RQ CQ */
	rq_ctx_t rq_ctx;        /* RQ */
	sq_ctx_t sq_ctx;        /* SQ */
	cq_ctx_t sq_cq_ctx;     /* SQ CQ */
	dt_ctx_t dt_ctx;        /* SQ Data ring */

	host_rq_ctx_t host_rq_ctx;
	host_sq_ctx_t host_sq_ctx;

	struct index_bucket *dpa_itable;
	uint32_t *index_remap_table;
	struct index_bucket *host_itable;
	uint32_t host_itable_mkey;
	uint32_t dpa_new;
	uint32_t dpa_hit;
	uint32_t dpa_miss;
	uint32_t host_new;
	uint32_t host_hit;
	uint32_t host_miss;
} app_ctx[MAX_THREADS];

struct ether_addr {
    uint8_t addr_bytes[6];
};

struct ether_hdr {
    struct ether_addr dst_addr;
    struct ether_addr src_addr;
    uint16_t ether_type;
} __attribute__((__packed__));

struct ipv4_hdr {
    uint8_t version_ihl;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t packet_id;
    uint16_t fragment_offset;
    uint8_t time_to_live;
    uint8_t next_proto_id;
    uint16_t hdr_checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
} __attribute__((__packed__));

struct tcp_hdr {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_no;
	uint32_t ack_no;
	uint8_t reserved:4;
	uint8_t data_off:4;
	uint8_t tcp_flags;
	uint16_t rx_win;
	uint16_t tcp_cksum;
	uint16_t urgent_ptr;
} __attribute__((__packed__));

struct udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t dgram_len;
    uint16_t dgram_cksum;
} __attribute__((__packed__));

struct ip_pkt {
    struct ether_hdr eth_hdr;
    struct ipv4_hdr ip_hdr;
} __attribute__((__packed__));

__attribute__((unused)) static struct ether_addr SRC_ADDR[2] = { {0x02, 0x86, 0x10, 0x97, 0xdb, 0x13}, {0x02, 0xbe, 0xf0, 0x98, 0x2f, 0x45} };
__attribute__((unused)) static struct ether_addr DST_ADDR[2] = { {0x02, 0x82, 0x4d, 0x74, 0x1c, 0xd0}, {0x02, 0x6a, 0xa2, 0x7a, 0xfb, 0xee} };

/* Initialize the app_ctx structure from the host data.
 *  data_from_host - pointer host2dev_packet_processor_data from host.
 */
static void app_ctx_init(struct host2dev_packet_processor_data *data_from_host, unsigned int tid)
{
	app_ctx[tid].packets_count = 0;
	app_ctx[tid].lkey = data_from_host->sq_transf.wqd_mkey_id;

	app_ctx[tid].host_rq_ctx.rkey = data_from_host->rq_transf.wqd_mkey_id;
	app_ctx[tid].host_rq_ctx.rq_window_id = data_from_host->window_id;
	app_ctx[tid].host_rq_ctx.host_rx_buff = (void *)data_from_host->rq_transf.wqd_daddr;

	app_ctx[tid].host_sq_ctx.rkey = data_from_host->sq_transf.wqd_mkey_id;
	app_ctx[tid].host_sq_ctx.sq_window_id = data_from_host->window_id;
	app_ctx[tid].host_sq_ctx.host_tx_buff = (void *)data_from_host->sq_transf.wqd_daddr;

	app_ctx[tid].dpa_itable = (struct index_bucket *)data_from_host->dpa_itable;
	app_ctx[tid].index_remap_table = (uint32_t *)data_from_host->index_remap_table;
	app_ctx[tid].host_itable_mkey = data_from_host->host_itable_mkey;

	/* Set context for RQ's CQ */
	com_cq_ctx_init(&app_ctx[tid].rq_cq_ctx,
			data_from_host->rq_cq_transf.cq_num,
			data_from_host->rq_cq_transf.log_cq_depth,
			data_from_host->rq_cq_transf.cq_ring_daddr,
			data_from_host->rq_cq_transf.cq_dbr_daddr);

	/* Set context for RQ */
	com_rq_ctx_init(&app_ctx[tid].rq_ctx,
			data_from_host->rq_transf.wq_num,
			data_from_host->rq_transf.wq_ring_daddr,
			data_from_host->rq_transf.wq_dbr_daddr);

	/* Set context for SQ */
	com_sq_ctx_init(&app_ctx[tid].sq_ctx,
			data_from_host->sq_transf.wq_num,
			data_from_host->sq_transf.wq_ring_daddr);

	/* Set context for SQ's CQ */
	com_cq_ctx_init(&app_ctx[tid].sq_cq_ctx,
			data_from_host->sq_cq_transf.cq_num,
			data_from_host->sq_cq_transf.log_cq_depth,
			data_from_host->sq_cq_transf.cq_ring_daddr,
			data_from_host->sq_cq_transf.cq_dbr_daddr);

	/* Set context for data */
	com_dt_ctx_init(&app_ctx[tid].dt_ctx, data_from_host->sq_transf.wqd_daddr);

	for (size_t entry = 0; entry < L2V(LOG_SQ_DEPTH); entry++) {

		union flexio_dev_sqe_seg *swqe;
        swqe = get_next_sqe(&app_ctx[tid].sq_ctx, SQ_IDX_MASK);
        flexio_dev_swqe_seg_ctrl_set(swqe, entry, app_ctx[tid].sq_ctx.sq_number,
            MLX5_CTRL_SEG_CE_CQE_ON_CQE_ERROR, FLEXIO_CTRL_SEG_SEND_EN);

        swqe = get_next_sqe(&app_ctx[tid].sq_ctx, SQ_IDX_MASK);
        flexio_dev_swqe_seg_eth_set(swqe, 0, 0, 0, NULL);

        swqe = get_next_sqe(&app_ctx[tid].sq_ctx, SQ_IDX_MASK);
        flexio_dev_swqe_seg_mem_ptr_data_set(swqe, 0, app_ctx[tid].lkey, 0);

        swqe = get_next_sqe(&app_ctx[tid].sq_ctx, SQ_IDX_MASK);
	}
}

// get a dpa address from a received packet on Arm/Host
__attribute__((unused)) inline static void *host_rq_addr_to_dpa_addr(void *host_addr, struct host_rq_ctx_t *host_rq_ctx) {
    return (void *)((flexio_uintptr_t)host_addr - (flexio_uintptr_t)host_rq_ctx->host_rx_buff + host_rq_ctx->dpa_rx_buff);
}

__attribute__((unused)) inline static void *host_sq_addr_to_dpa_addr(void *host_addr, struct host_sq_ctx_t *host_sq_ctx) {
    return (void *)((flexio_uintptr_t)host_addr - (flexio_uintptr_t)host_sq_ctx->host_tx_buff + host_sq_ctx->dpa_tx_buff);
}

__attribute__((unused)) inline static union flexio_dev_sqe_seg *get_next_data_sqe(sq_ctx_t *sq_ctx) {
    union flexio_dev_sqe_seg *res = &sq_ctx->sq_ring[(sq_ctx->sq_wqe_seg_idx + 2) & SQ_IDX_MASK];
    sq_ctx->sq_wqe_seg_idx += 4;
    return res;
}

/* process packet - read it, swap MAC addresses, modify it, create a send WQE and send it back. */
static void process_packet_host(unsigned int tid, unsigned int pid, uint32_t key_bucket)
{
	/* RX packet handling variables */
	struct flexio_dev_wqe_rcv_data_seg *rwqe;
	/* RQ WQE index */
	uint32_t rq_wqe_idx;
	/* Pointer to RQ data */
	char *rq_data;
	char *rq_data_dpa;

	/* TX packet handling variables */
	union flexio_dev_sqe_seg *swqe;
	/* Pointer to SQ data */
	char *sq_data;
	char *sq_data_dpa;

	/* Size of the data */
	uint32_t data_sz;

	/* Extract relevant data from the CQE */
	rq_wqe_idx = flexio_dev_cqe_get_wqe_counter(app_ctx[tid].rq_cq_ctx.cqe);
	data_sz = flexio_dev_cqe_get_byte_cnt(app_ctx[tid].rq_cq_ctx.cqe);

	/* Get the RQ WQE pointed to by the CQE */
	rwqe = &app_ctx[tid].rq_ctx.rq_ring[rq_wqe_idx & RQ_IDX_MASK];

	/* Extract data (whole packet) pointed to by the RQ WQE */
	rq_data = flexio_dev_rwqe_get_addr(rwqe);
	flexio_dev_window_mkey_config(FLEXIO_DEV_WINDOW_ENTITY_0, app_ctx[tid].host_rq_ctx.rkey);
	rq_data_dpa = host_rq_addr_to_dpa_addr(rq_data, &app_ctx[tid].host_rq_ctx);

	struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *)(rq_data_dpa + sizeof(struct ether_hdr));
	uint32_t hash_mask = key_bucket - 1;
	uint32_t key = ip_hdr->src_addr;
	uint32_t key_index = ip_hdr->dst_addr & hash_mask;
	struct key_element km;
	if (key_index < DPA_MAX_BUCKET)
	{
		for (int k = 0; k < LOOP; k++)
		{
			for (int i = 0; i < ENTRY_NUM; i++)
			{
				if (app_ctx[tid].dpa_itable[key_index].entries[i].keys[0] == 0)
				{
					app_ctx[tid].dpa_itable[key_index].entries[i].keys[0] = key;
					app_ctx[tid].dpa_new++;
					break;
				}
				else if (app_ctx[tid].dpa_itable[key_index].entries[i].keys[0] == key) {
					if (app_ctx[tid].dpa_hit & 1)
					{
						// Update
						for (int j = 0; j < KEY_LEN; j++)
							app_ctx[tid].dpa_itable[key_index].entries[i].keys[j] = key;
					}
					else
					{
						// Get
						for (int j = 0; j < KEY_LEN; j++)
							km.key[j] = app_ctx[tid].dpa_itable[key_index].entries[i].keys[j];
					}
					app_ctx[tid].dpa_hit++;
					break;
				}
				else if (i == ENTRY_NUM - 1)
				{
					app_ctx[tid].dpa_miss++;
				}
			}
		}
	}
	else
	{
		flexio_dev_window_mkey_config(FLEXIO_DEV_WINDOW_ENTITY_0, app_ctx[tid].host_itable_mkey);
		for (int k = 0; k < LOOP; k++)
		{
			for (int i = 0; i < ENTRY_NUM; i++)
			{
				if (app_ctx[tid].host_itable[key_index].entries[i].keys[0] == 0)
				{
					app_ctx[tid].host_itable[key_index].entries[i].keys[0] = key;
					app_ctx[tid].host_new++;
					break;
				}
				else if (app_ctx[tid].host_itable[key_index].entries[i].keys[0] == key) {
					if (app_ctx[tid].host_hit & 1)
					{
						// Update
						for (int j = 0; j < KEY_LEN; j++)
							app_ctx[tid].host_itable[key_index].entries[i].keys[j] = key;
					}
					else
					{
						// Get
						for (int j = 0; j < KEY_LEN; j++)
							km.key[j] = app_ctx[tid].host_itable[key_index].entries[i].keys[j];
					}
					app_ctx[tid].host_hit++;
					break;
				}
				else if (i == ENTRY_NUM - 1)
				{
					app_ctx[tid].host_miss++;
				}
			}
		}
	}
	
	/* Take the next entry from the data ring */
	sq_data = get_next_dte(&app_ctx[tid].dt_ctx, DATA_IDX_MASK, LOG_WQD_CHUNK_BSIZE);
	sq_data_dpa = host_sq_addr_to_dpa_addr(sq_data, &app_ctx[tid].host_sq_ctx);
	struct ether_hdr *eth_hdr = (struct ether_hdr *)(sq_data_dpa);
	flexio_dev_window_mkey_config(FLEXIO_DEV_WINDOW_ENTITY_0, app_ctx[tid].host_sq_ctx.rkey);
	eth_hdr->dst_addr = DST_ADDR[pid];

	swqe = get_next_data_sqe(&app_ctx[tid].sq_ctx);
	flexio_dev_swqe_seg_mem_ptr_data_set(swqe, data_sz, app_ctx[tid].lkey, (uint64_t)sq_data);

	/* Ring DB */
	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
	flexio_dev_qp_sq_ring_db(++app_ctx[tid].sq_ctx.sq_pi, app_ctx[tid].sq_ctx.sq_number);
	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
	flexio_dev_dbr_rq_inc_pi(app_ctx[tid].rq_ctx.rq_dbr);
}

static void process_packet_host_opt(unsigned int tid, unsigned int pid, uint32_t key_bucket)
{
	/* RX packet handling variables */
	struct flexio_dev_wqe_rcv_data_seg *rwqe;
	/* RQ WQE index */
	uint32_t rq_wqe_idx;
	/* Pointer to RQ data */
	char *rq_data;
	char *rq_data_dpa;

	/* TX packet handling variables */
	union flexio_dev_sqe_seg *swqe;
	/* Pointer to SQ data */
	char *sq_data;
	char *sq_data_dpa;

	/* Size of the data */
	uint32_t data_sz;

	/* Extract relevant data from the CQE */
	rq_wqe_idx = flexio_dev_cqe_get_wqe_counter(app_ctx[tid].rq_cq_ctx.cqe);
	data_sz = flexio_dev_cqe_get_byte_cnt(app_ctx[tid].rq_cq_ctx.cqe);

	/* Get the RQ WQE pointed to by the CQE */
	rwqe = &app_ctx[tid].rq_ctx.rq_ring[rq_wqe_idx & RQ_IDX_MASK];

	/* Extract data (whole packet) pointed to by the RQ WQE */
	rq_data = flexio_dev_rwqe_get_addr(rwqe);
	flexio_dev_window_mkey_config(FLEXIO_DEV_WINDOW_ENTITY_0, app_ctx[tid].host_rq_ctx.rkey);
	rq_data_dpa = host_rq_addr_to_dpa_addr(rq_data, &app_ctx[tid].host_rq_ctx);

	struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *)(rq_data_dpa + sizeof(struct ether_hdr));
	uint32_t hash_mask = key_bucket - 1;
	uint32_t key = ip_hdr->src_addr;
	uint32_t key_index = ip_hdr->dst_addr & hash_mask;
	uint32_t remap_index = app_ctx[tid].index_remap_table[key_index];
	struct key_element km;
	if (remap_index < DPA_MAX_BUCKET)
	{
		for (int k = 0; k < LOOP; k++)
		{
			for (int i = 0; i < ENTRY_NUM; i++)
			{
				if (app_ctx[tid].dpa_itable[remap_index].entries[i].keys[0] == 0)
				{
					app_ctx[tid].dpa_itable[remap_index].entries[i].keys[0] = key;
					app_ctx[tid].dpa_new++;
					break;
				}
				else if (app_ctx[tid].dpa_itable[remap_index].entries[i].keys[0] == key) {
					if (app_ctx[tid].dpa_hit & 1)
					{
						// Update
						for (int j = 0; j < KEY_LEN; j++)
							app_ctx[tid].dpa_itable[remap_index].entries[i].keys[j] = key;
					}
					else
					{
						// Get
						for (int j = 0; j < KEY_LEN; j++)
							km.key[j] = app_ctx[tid].dpa_itable[remap_index].entries[i].keys[j];
					}
					app_ctx[tid].dpa_hit++;
					break;
				}
				else if (i == ENTRY_NUM - 1)
				{
					app_ctx[tid].dpa_miss++;
				}
			}
		}
	}
	else
	{
		flexio_dev_window_mkey_config(FLEXIO_DEV_WINDOW_ENTITY_0, app_ctx[tid].host_itable_mkey);
		for (int k = 0; k < LOOP; k++)
		{
			for (int i = 0; i < ENTRY_NUM; i++)
			{
				if (app_ctx[tid].host_itable[key_index].entries[i].keys[0] == 0)
				{
					app_ctx[tid].host_itable[key_index].entries[i].keys[0] = key;
					app_ctx[tid].host_new++;
					break;
				}
				else if (app_ctx[tid].host_itable[key_index].entries[i].keys[0] == key) {
					if (app_ctx[tid].host_hit & 1)
					{
						// Update
						for (int j = 0; j < KEY_LEN; j++)
							app_ctx[tid].host_itable[key_index].entries[i].keys[j] = key;
					}
					else
					{
						// Get
						for (int j = 0; j < KEY_LEN; j++)
							km.key[j] = app_ctx[tid].host_itable[key_index].entries[i].keys[j];
					}
					app_ctx[tid].host_hit++;
					break;
				}
				else if (i == ENTRY_NUM - 1)
				{
					app_ctx[tid].host_miss++;
				}
			}
		}
	}
	
	/* Take the next entry from the data ring */
	sq_data = get_next_dte(&app_ctx[tid].dt_ctx, DATA_IDX_MASK, LOG_WQD_CHUNK_BSIZE);
	sq_data_dpa = host_sq_addr_to_dpa_addr(sq_data, &app_ctx[tid].host_sq_ctx);
	struct ether_hdr *eth_hdr = (struct ether_hdr *)(sq_data_dpa);
	flexio_dev_window_mkey_config(FLEXIO_DEV_WINDOW_ENTITY_0, app_ctx[tid].host_sq_ctx.rkey);
	eth_hdr->dst_addr = DST_ADDR[pid];

	swqe = get_next_data_sqe(&app_ctx[tid].sq_ctx);
	flexio_dev_swqe_seg_mem_ptr_data_set(swqe, data_sz, app_ctx[tid].lkey, (uint64_t)sq_data);

	/* Ring DB */
	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
	flexio_dev_qp_sq_ring_db(++app_ctx[tid].sq_ctx.sq_pi, app_ctx[tid].sq_ctx.sq_number);
	__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
	flexio_dev_dbr_rq_inc_pi(app_ctx[tid].rq_ctx.rq_dbr);
}

uint64_t itable_counter_get(int thread_num);
__dpa_rpc__ uint64_t itable_counter_get(int thread_num)
{
	uint32_t dpa_new = 0, dpa_hit = 0, dpa_miss = 0;
	uint32_t host_new = 0, host_hit = 0, host_miss = 0;

	for(int i = 0; i < thread_num; i++)
	{
		dpa_new += app_ctx[i].dpa_new;
		dpa_hit += app_ctx[i].dpa_hit;
		dpa_miss += app_ctx[i].dpa_miss;
		host_new += app_ctx[i].host_new;
		host_hit += app_ctx[i].host_hit;
		host_miss += app_ctx[i].host_miss;
		app_ctx[i].dpa_new = 0;
		app_ctx[i].dpa_hit = 0;
		app_ctx[i].dpa_miss = 0;
		app_ctx[i].host_new = 0;
		app_ctx[i].host_hit = 0;
		app_ctx[i].host_miss = 0;
	}
	
	flexio_dev_print("DPA new %u, hit %u, miss %u, Host new %u, hit %u, miss %u\n", 
		dpa_new, dpa_hit, dpa_miss, host_new, host_hit, host_miss);
	
	return 0;
}

static flexio_uintptr_t get_host_buffer(uint32_t window_id, uint32_t mkey, void *haddr)
{
	flexio_uintptr_t host_buffer;
	flexio_dev_window_config(FLEXIO_DEV_WINDOW_ENTITY_0, window_id, mkey);
	flexio_dev_window_ptr_acquire(FLEXIO_DEV_WINDOW_ENTITY_0, (uint64_t)haddr, &host_buffer);

	return host_buffer;
}

/* Entry point function that host side call for the execute.
 *  thread_arg - pointer to the host2dev_packet_processor_data structure
 *     to transfer data from the host side.
 */
flexio_dev_event_handler_t flexio_pp_dev;
__dpa_global__ void flexio_pp_dev(uint64_t thread_arg)
{
	struct host2dev_packet_processor_data *data_from_host = (void *)thread_arg;
	uint8_t tid = data_from_host->id;
	uint8_t pid = data_from_host->port;
	void (*process_pkt_func)(unsigned int, unsigned int, uint32_t);

	/* If the thread is executed for first time, then initialize the context
	 */
	if (!data_from_host->not_first_run) {
		app_ctx_init(data_from_host, tid);
		data_from_host->not_first_run = 1;

		app_ctx[tid].host_rq_ctx.dpa_rx_buff = get_host_buffer(app_ctx[tid].host_rq_ctx.rq_window_id, app_ctx[tid].host_rq_ctx.rkey, app_ctx[tid].host_rq_ctx.host_rx_buff);
		app_ctx[tid].host_sq_ctx.dpa_tx_buff = get_host_buffer(app_ctx[tid].host_sq_ctx.sq_window_id, app_ctx[tid].host_sq_ctx.rkey, app_ctx[tid].host_sq_ctx.host_tx_buff);
		app_ctx[tid].host_itable = (struct index_bucket *)get_host_buffer(data_from_host->window_id, app_ctx[tid].host_itable_mkey, data_from_host->host_itable);

		if (app_ctx[tid].index_remap_table)
			process_pkt_func = process_packet_host_opt;
		else
			process_pkt_func = process_packet_host;
	}

	/* Poll CQ until the package is received.
	 */
	while (1)
	{
		while (flexio_dev_cqe_get_owner(app_ctx[tid].rq_cq_ctx.cqe) !=
			app_ctx[tid].rq_cq_ctx.cq_hw_owner_bit) {
			/* Print the message */
			/* Update memory to DPA */
			__dpa_thread_fence(__DPA_MEMORY, __DPA_R, __DPA_R);
			/* Process the packet */
			// flexio_dev_print("[%d] Process host packet: %ld\n", tid, app_ctx[tid].packets_count++);
			process_pkt_func(tid, pid, data_from_host->key_bucket);
			/* Update RQ CQ */
			com_step_cq(&app_ctx[tid].rq_cq_ctx);
		}

		/* Update the memory to the chip */
		__dpa_thread_fence(__DPA_MEMORY, __DPA_W, __DPA_W);
		/* Arming cq for next packet */
		flexio_dev_cq_arm(app_ctx[tid].rq_cq_ctx.cq_idx, app_ctx[tid].rq_cq_ctx.cq_number);
	}
	
	/* Reschedule the thread */
	flexio_dev_thread_reschedule();
}
