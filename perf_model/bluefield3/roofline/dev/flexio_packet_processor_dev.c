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

	void *host_buf_global;
	uint32_t host_buf_mkey;
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

struct io_opt {
	size_t *data;		/* Pointer to the data */
	uint32_t num;		/* Number of R/W operations */
	uint32_t mask;		/* Mask for the data index */
	uint32_t size;		/* Size of the sequential data accessed by each operation */
	uint64_t (*io_func)(struct io_opt *, int);
} __attribute__((__packed__));

__attribute__((unused)) static struct ether_addr SRC_ADDR[2] = { {0x02, 0x86, 0x10, 0x97, 0xdb, 0x13}, {0x02, 0xbe, 0xf0, 0x98, 0x2f, 0x45} };
__attribute__((unused)) static struct ether_addr DST_ADDR[2] = { {0x02, 0x82, 0x4d, 0x74, 0x1c, 0xd0}, {0x02, 0x6a, 0xa2, 0x7a, 0xfb, 0xee} };

static uint64_t benchmark_results[MAX_THREADS];

static void prepare_packet_host(void *sq_data, size_t thread_index)
{
    struct ip_pkt pkt;
	pkt.ip_hdr.version_ihl = 0x45;
    pkt.ip_hdr.type_of_service = 0;
    pkt.ip_hdr.total_length = cpu_to_be16(1024);
    pkt.ip_hdr.packet_id = cpu_to_be16(thread_index);
    pkt.ip_hdr.fragment_offset = cpu_to_be16(0);
    pkt.ip_hdr.time_to_live = 64;
    pkt.ip_hdr.next_proto_id = 17;
    pkt.ip_hdr.src_addr = cpu_to_be16(0x0a000001 + thread_index);
    pkt.ip_hdr.dst_addr = cpu_to_be16(0x0a000002 + thread_index);

    flexio_dev_window_copy_to_host(FLEXIO_DEV_WINDOW_ENTITY_0, (uint64_t)sq_data, &pkt, sizeof(pkt));
}

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

	app_ctx[tid].host_buf_global = (void *)data_from_host->host_buf_global;
	app_ctx[tid].host_buf_mkey = data_from_host->host_mkey_global;

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

	char *sq_data;
	for (size_t entry = 0; entry < L2V(LOG_SQ_DEPTH); entry++) {
		sq_data = get_next_dte(&app_ctx[tid].dt_ctx, DATA_IDX_MASK, LOG_WQD_CHUNK_BSIZE);
		prepare_packet_host(sq_data, tid);
	}
}

// get a dpa address from a received packet on Arm/Host
__attribute__((unused)) inline static void *host_rq_addr_to_dpa_addr(void *host_addr, struct host_rq_ctx_t *host_rq_ctx) {
    return (void *)((flexio_uintptr_t)host_addr - (flexio_uintptr_t)host_rq_ctx->host_rx_buff + host_rq_ctx->dpa_rx_buff);
}

// get a dpa address for a packet to be sent on Arm/Host
__attribute__((unused)) inline static void *host_sq_addr_to_dpa_addr(void *host_addr, struct host_sq_ctx_t *host_sq_ctx) {
    return (void *)((flexio_uintptr_t)host_addr - (flexio_uintptr_t)host_sq_ctx->host_tx_buff + host_sq_ctx->dpa_tx_buff);
}

inline static union flexio_dev_sqe_seg *get_next_data_sqe(sq_ctx_t *sq_ctx) {
    union flexio_dev_sqe_seg *res = &sq_ctx->sq_ring[(sq_ctx->sq_wqe_seg_idx + 2) & SQ_IDX_MASK];
    sq_ctx->sq_wqe_seg_idx += 4;
    return res;
}

static flexio_uintptr_t get_host_buffer(uint32_t window_id, uint32_t mkey, void *haddr)
{
	flexio_uintptr_t host_buffer;
	flexio_dev_multi_window_config(FLEXIO_DEV_WINDOW_ENTITY_0, window_id, mkey);
	flexio_dev_multi_window_ptr_acquire(FLEXIO_DEV_WINDOW_ENTITY_0, (uint64_t)haddr, &host_buffer);

	return host_buffer;
}

static uint64_t benchmark_cycles(uint32_t loop)
{
	uint32_t loop_num = 0;
	uint32_t start = __dpa_thread_cycles();
	while (loop_num < loop) {
		__dpa_thread_cycles();
		loop_num++;
	}
	uint32_t end = __dpa_thread_cycles();
	uint32_t total_cycles = (end - start);

	return loop_num * 1800000000UL / total_cycles;
}

/* Read only per-thread memory */
__attribute__((unused)) static uint64_t benchmark_read(size_t *data, long size, int stride, int loop)
{
	int loop_num = 0;
	long sum[8] = {0};
	long num_ele = size / sizeof(size_t);
	size_t start = __dpa_thread_cycles();
	while (loop_num < loop) {
		for (long i = 0; i < num_ele; i += stride * 8) {
			sum[0] += data[i + 0 * stride];
			sum[1] += data[i + 1 * stride];
			sum[2] += data[i + 2 * stride];
			sum[3] += data[i + 3 * stride];
			sum[4] += data[i + 4 * stride];
			sum[5] += data[i + 5 * stride];
			sum[6] += data[i + 6 * stride];
			sum[7] += data[i + 7 * stride];
		}
		loop_num++;
	}
	size_t end = __dpa_thread_cycles();
	size_t total_cycles = (end - start);
	for (int i = 0; i < 8; i++) {
		// flexio_dev_msg(stream_id, FLEXIO_MSG_DEV_NO_PRINT, "%ld\n", sum[i]);
		data[i] = sum[i];
	}
	return loop * num_ele * sizeof(size_t) * 1800000000UL / stride / total_cycles;
}

/* Each loop reads some thread's memory, trying to add some contention */
__attribute__((unused)) static uint64_t benchmark_atomic_read(size_t *data, long size, long per_thread_size, int stride, int loop)
{
	int loop_num = 0;
	long sum[8] = {0};
	int thread_num = size / per_thread_size;
	long num_ele = per_thread_size / sizeof(size_t);
	size_t start = __dpa_thread_cycles();
	while (loop_num < loop) {
		int idx = __dpa_thread_cycles() % thread_num;
		size_t *tmp_data = &data[idx * num_ele];
		for (long i = 0; i < num_ele; i += stride * 8) {
			sum[0] += __atomic_load_n(&tmp_data[i + 0 * stride], __ATOMIC_RELAXED);
			sum[1] += __atomic_load_n(&tmp_data[i + 1 * stride], __ATOMIC_RELAXED);
			sum[2] += __atomic_load_n(&tmp_data[i + 2 * stride], __ATOMIC_RELAXED);
			sum[3] += __atomic_load_n(&tmp_data[i + 3 * stride], __ATOMIC_RELAXED);
			sum[4] += __atomic_load_n(&tmp_data[i + 4 * stride], __ATOMIC_RELAXED);
			sum[5] += __atomic_load_n(&tmp_data[i + 5 * stride], __ATOMIC_RELAXED);
			sum[6] += __atomic_load_n(&tmp_data[i + 6 * stride], __ATOMIC_RELAXED);
			sum[7] += __atomic_load_n(&tmp_data[i + 7 * stride], __ATOMIC_RELAXED);
		}
		loop_num++;
	}
	size_t end = __dpa_thread_cycles();
	size_t total_cycles = (end - start);
	for (int i = 0; i < 8; i++) {
		data[i] = sum[i];
	}
	return loop * num_ele * sizeof(size_t) * 1800000000UL / stride / total_cycles;
}

/* Write only per-thread memory */
__attribute__((unused)) static uint64_t benchmark_write(size_t *data, long size, int stride, int loop)
{
	int loop_num = 0;
	long num_ele = size / sizeof(size_t);
	size_t start = __dpa_thread_cycles();
	while (loop_num < loop) {
		for (long i = 0; i < num_ele; i += stride * 8) {
			data[i + 0 * stride] = i;
			data[i + 1 * stride] = i;
			data[i + 2 * stride] = i;
			data[i + 3 * stride] = i;
			data[i + 4 * stride] = i;
			data[i + 5 * stride] = i;
			data[i + 6 * stride] = i;
			data[i + 7 * stride] = i;
		}
		loop_num++;
	}
	size_t end = __dpa_thread_cycles();
	size_t total_cycles = (end - start);

	return loop * num_ele * sizeof(size_t) * 1800000000UL / stride / total_cycles;
}

/* Each loop writes some thread's memory, trying to add some contention */
__attribute__((unused)) static uint64_t benchmark_atomic_write(size_t *data, long size, long per_thread_size, int stride, int loop)
{
	int loop_num = 0;
	int thread_num = size / per_thread_size;
	long num_ele = per_thread_size / sizeof(size_t);
	size_t start = __dpa_thread_cycles();
	while (loop_num < loop) {
		int idx = __dpa_thread_cycles() % thread_num;
		size_t *tmp_data = &data[idx * num_ele];
		for (long i = 0; i < num_ele; i += stride * 8) {
			__atomic_store_n(&tmp_data[i + 0 * stride], i, __ATOMIC_RELAXED);
			__atomic_store_n(&tmp_data[i + 1 * stride], i, __ATOMIC_RELAXED);
			__atomic_store_n(&tmp_data[i + 2 * stride], i, __ATOMIC_RELAXED);
			__atomic_store_n(&tmp_data[i + 3 * stride], i, __ATOMIC_RELAXED);
			__atomic_store_n(&tmp_data[i + 4 * stride], i, __ATOMIC_RELAXED);
			__atomic_store_n(&tmp_data[i + 5 * stride], i, __ATOMIC_RELAXED);
			__atomic_store_n(&tmp_data[i + 6 * stride], i, __ATOMIC_RELAXED);
			__atomic_store_n(&tmp_data[i + 7 * stride], i, __ATOMIC_RELAXED);
		}
		loop_num++;
	}
	size_t end = __dpa_thread_cycles();
	size_t total_cycles = (end - start);

	return loop * num_ele * sizeof(size_t) * 1800000000UL / stride / total_cycles;
}

/* Randomly read memory in each loop */
__attribute__((unused)) static uint64_t benchmark_read_random(size_t *data, long size, int stride, int loop)
{
	int loop_num = 0;
	size_t sum[8] = {0};
	long elem_num = size / sizeof(size_t);
	uint32_t mask = elem_num - 1;
	size_t start = __dpa_thread_cycles();
	while (loop_num < loop) {
		for (long i = 0; i < elem_num; i += stride * 8) {
			uint32_t idx = __dpa_thread_cycles() & mask;
			sum[0] += data[(idx + 0 * stride) & mask];
			sum[1] += data[(idx + 1 * stride) & mask];
			sum[2] += data[(idx + 2 * stride) & mask];
			sum[3] += data[(idx + 3 * stride) & mask];
			sum[4] += data[(idx + 4 * stride) & mask];
			sum[5] += data[(idx + 5 * stride) & mask];
			sum[6] += data[(idx + 6 * stride) & mask];
			sum[7] += data[(idx + 7 * stride) & mask];
		}
		loop_num++;
	}
	size_t end = __dpa_thread_cycles();
	size_t total_cycles = (end - start);
	for (int i = 0; i < 8; i++) {
		data[i] = sum[i];
	}
	return loop_num * elem_num * sizeof(size_t) * 1800000000UL / stride / total_cycles;
}

__attribute__((unused)) static uint64_t benchmark_atomic_read_random(size_t *data, long size, long per_thread_size, int stride, int loop)
{
	int loop_num = 0;
	size_t sum[8] = {0};
	long num_ele = per_thread_size / sizeof(size_t);
	uint32_t mask = (size / sizeof(size_t)) - 1;
	size_t start = __dpa_thread_cycles();
	while (loop_num < loop) {
		for (long i = 0; i < num_ele; i += stride * 8) {
			uint32_t idx = __dpa_thread_cycles() & mask;
			sum[0] += __atomic_load_n(&data[(idx + 0 * stride) & mask], __ATOMIC_RELAXED);
			sum[1] += __atomic_load_n(&data[(idx + 1 * stride) & mask], __ATOMIC_RELAXED);
			sum[2] += __atomic_load_n(&data[(idx + 2 * stride) & mask], __ATOMIC_RELAXED);
			sum[3] += __atomic_load_n(&data[(idx + 3 * stride) & mask], __ATOMIC_RELAXED);
			sum[4] += __atomic_load_n(&data[(idx + 4 * stride) & mask], __ATOMIC_RELAXED);
			sum[5] += __atomic_load_n(&data[(idx + 5 * stride) & mask], __ATOMIC_RELAXED);
			sum[6] += __atomic_load_n(&data[(idx + 6 * stride) & mask], __ATOMIC_RELAXED);
			sum[7] += __atomic_load_n(&data[(idx + 7 * stride) & mask], __ATOMIC_RELAXED);
		}
		loop_num++;
	}
	size_t end = __dpa_thread_cycles();
	size_t total_cycles = (end - start);
	for (int i = 0; i < 8; i++) {
		data[i] = sum[i];
	}
	return loop_num * num_ele * sizeof(size_t) * 1800000000UL / stride / total_cycles;
}

__attribute__((unused)) static uint64_t benchmark_write_random(size_t *data, long size, int stride, int loop)
{
	int loop_num = 0;
	long elem_num = size / sizeof(size_t);
	uint32_t mask = elem_num - 1;
	size_t start = __dpa_thread_cycles();
	while (loop_num < loop) {
		for (long i = 0; i < elem_num; i += stride * 8) {
			uint32_t idx = __dpa_thread_cycles() & mask;
			data[(idx + 0 * stride) & mask] = i;
			data[(idx + 1 * stride) & mask] = i;
			data[(idx + 2 * stride) & mask] = i;
			data[(idx + 3 * stride) & mask] = i;
			data[(idx + 4 * stride) & mask] = i;
			data[(idx + 5 * stride) & mask] = i;
			data[(idx + 6 * stride) & mask] = i;
			data[(idx + 7 * stride) & mask] = i;
		}
		loop_num++;
	}
	size_t end = __dpa_thread_cycles();
	size_t total_cycles = (end - start);

	return loop_num * elem_num * sizeof(size_t) * 1800000000UL / stride / total_cycles;
}

__attribute__((unused)) static uint64_t benchmark_atomic_write_random(size_t *data, long size, long per_thread_size, int stride, int loop)
{
	int loop_num = 0;
	long num_ele = per_thread_size / sizeof(size_t);
	uint32_t mask = (size / sizeof(size_t)) - 1;
	size_t start = __dpa_thread_cycles();
	while (loop_num < loop) {
		for (long i = 0; i < num_ele; i += stride * 8) {
			uint32_t idx = __dpa_thread_cycles() & mask;
			__atomic_store_n(&data[(idx + 0 * stride) & mask], i, __ATOMIC_RELAXED);
			__atomic_store_n(&data[(idx + 1 * stride) & mask], i, __ATOMIC_RELAXED);
			__atomic_store_n(&data[(idx + 2 * stride) & mask], i, __ATOMIC_RELAXED);
			__atomic_store_n(&data[(idx + 3 * stride) & mask], i, __ATOMIC_RELAXED);
			__atomic_store_n(&data[(idx + 4 * stride) & mask], i, __ATOMIC_RELAXED);
			__atomic_store_n(&data[(idx + 5 * stride) & mask], i, __ATOMIC_RELAXED);
			__atomic_store_n(&data[(idx + 6 * stride) & mask], i, __ATOMIC_RELAXED);
			__atomic_store_n(&data[(idx + 7 * stride) & mask], i, __ATOMIC_RELAXED);
		}
		loop_num++;
	}
	size_t end = __dpa_thread_cycles();
	size_t total_cycles = (end - start);

	return loop_num * num_ele * sizeof(size_t) * 1800000000UL / stride / total_cycles;
}

uint64_t benchmark_function(uint64_t thread_arg);
__dpa_rpc__ uint64_t benchmark_function(uint64_t thread_arg)
{
	struct host2dev_packet_processor_data *data_from_host = (void *)thread_arg;
	unsigned int tid = data_from_host->id;
	int loop = 10000;
	int stride = 1;
	switch (data_from_host->ops[0].opt_type)
	{
	case CYCLE:
		benchmark_results[tid] = benchmark_cycles(loop);
		break;
	case READ_DPA:
		benchmark_results[tid] = benchmark_read((size_t *)data_from_host->dpa_buf, data_from_host->per_thread_data_size, stride, loop);
		break;
	case READ_DPA_RANDOM:
		benchmark_results[tid] = benchmark_read_random((size_t *)data_from_host->dpa_buf, data_from_host->per_thread_data_size, stride, loop);
		break;
	case WRITE_DPA:
		benchmark_results[tid] = benchmark_write((size_t *)data_from_host->dpa_buf, data_from_host->per_thread_data_size, stride, loop);
		break;
	case WRITE_DPA_RANDOM:
		benchmark_results[tid] = benchmark_write_random((size_t *)data_from_host->dpa_buf, data_from_host->per_thread_data_size, stride, loop);
		break;
	case READ_ARM:
		data_from_host->host_buf = (void *)get_host_buffer(data_from_host->window_id, data_from_host->host_mkey, data_from_host->host_buf);
		benchmark_results[tid] = benchmark_read((size_t *)data_from_host->host_buf, data_from_host->per_thread_data_size, stride, loop);
		break;
	case READ_ARM_RANDOM:
		data_from_host->host_buf = (void *)get_host_buffer(data_from_host->window_id, data_from_host->host_mkey, data_from_host->host_buf);
		benchmark_results[tid] = benchmark_read_random((size_t *)data_from_host->host_buf, data_from_host->per_thread_data_size, stride, loop);
		break;
	case WRITE_ARM:
		data_from_host->host_buf = (void *)get_host_buffer(data_from_host->window_id, data_from_host->host_mkey, data_from_host->host_buf);
		// Setting the stride to a value other than one will result in extremely low performance.
		benchmark_results[tid] = benchmark_write((size_t *)data_from_host->host_buf, data_from_host->per_thread_data_size, stride, loop);
		break;
	case WRITE_ARM_RANDOM:
		data_from_host->host_buf = (void *)get_host_buffer(data_from_host->window_id, data_from_host->host_mkey, data_from_host->host_buf);
		benchmark_results[tid] = benchmark_write_random((size_t *)data_from_host->host_buf, data_from_host->per_thread_data_size, stride, loop);
		break;
	case ATOMIC_READ_DPA:
		benchmark_results[tid] = benchmark_atomic_read((size_t *)data_from_host->dpa_buf_global, data_from_host->data_size, data_from_host->per_thread_data_size, stride, loop);
		break;
	case ATOMIC_READ_DPA_RANDOM:
		benchmark_results[tid] = benchmark_atomic_read_random((size_t *)data_from_host->dpa_buf_global, data_from_host->data_size, data_from_host->per_thread_data_size, stride, loop);
		break;
	case ATOMIC_WRITE_DPA:
		benchmark_results[tid] = benchmark_atomic_write((size_t *)data_from_host->dpa_buf_global, data_from_host->data_size, data_from_host->per_thread_data_size, stride, loop);
		break;
	case ATOMIC_WRITE_DPA_RANDOM:
		benchmark_results[tid] = benchmark_atomic_write_random((size_t *)data_from_host->dpa_buf_global, data_from_host->data_size, data_from_host->per_thread_data_size, stride, loop);
		break;
	case ATOMIC_READ_ARM:
		data_from_host->host_buf_global = (void *)get_host_buffer(data_from_host->window_id, data_from_host->host_mkey_global, data_from_host->host_buf_global);
		benchmark_results[tid] = benchmark_atomic_read((size_t *)data_from_host->host_buf_global, data_from_host->data_size, data_from_host->per_thread_data_size, stride, loop);
		break;
	case ATOMIC_READ_ARM_RANDOM:
		data_from_host->host_buf_global = (void *)get_host_buffer(data_from_host->window_id, data_from_host->host_mkey_global, data_from_host->host_buf_global);
		benchmark_results[tid] = benchmark_atomic_read_random((size_t *)data_from_host->host_buf_global, data_from_host->data_size, data_from_host->per_thread_data_size, stride, loop);
		break;
	case ATOMIC_WRITE_ARM:
		data_from_host->host_buf_global = (void *)get_host_buffer(data_from_host->window_id, data_from_host->host_mkey_global, data_from_host->host_buf_global);
		benchmark_results[tid] = benchmark_atomic_write((size_t *)data_from_host->host_buf_global, data_from_host->data_size, data_from_host->per_thread_data_size, stride, loop);
		break;
	case ATOMIC_WRITE_ARM_RANDOM:
		data_from_host->host_buf_global = (void *)get_host_buffer(data_from_host->window_id, data_from_host->host_mkey_global, data_from_host->host_buf_global);
		benchmark_results[tid] = benchmark_atomic_write_random((size_t *)data_from_host->host_buf_global, data_from_host->data_size, data_from_host->per_thread_data_size, stride, loop);
		break;
	default:
		break;
	}
	return 0;
}

uint64_t benchmark_get_results(int thread_num);
__dpa_rpc__ uint64_t benchmark_get_results(int thread_num)
{
	uint64_t res = 0;
	for (int i = 0; i < thread_num; i++) {
		res += benchmark_results[i];
	}
	return res;
}

static uint64_t read(struct io_opt *opt, __attribute__((unused)) int tid)
{
	uint64_t res = 0;
	for (uint32_t i = 0; i < opt->num; i++) {
		int idx = __dpa_thread_cycles() & opt->mask;
		uint32_t s = 0;
		while (s < opt->size) {
			res += opt->data[(idx + s) & opt->mask];
			s++;
		}
	}
	return res;
}

static uint64_t read_host(struct io_opt *opt, int tid)
{
	flexio_dev_window_mkey_config(FLEXIO_DEV_WINDOW_ENTITY_0, app_ctx[tid].host_buf_mkey);
	uint64_t res = 0;
	for (uint32_t i = 0; i < opt->num; i++) {
		int idx = __dpa_thread_cycles() & opt->mask;
		uint32_t s = 0;
		while (s < opt->size) {
			res += opt->data[(idx + s) & opt->mask];
			s++;
		}
	}
	return res;
}

static uint64_t atomic_read(struct io_opt *opt, __attribute__((unused)) int tid)
{
	uint64_t res = 0;
	for (uint32_t i = 0; i < opt->num; i++) {
		int idx = __dpa_thread_cycles() & opt->mask;
		uint32_t s = 0;
		while (s < opt->size) {
			res += __atomic_load_n(&opt->data[(idx + s) & opt->mask], __ATOMIC_RELAXED);
			s++;
		}
	}
	return res;
}

static uint64_t atomic_read_host(struct io_opt *opt, int tid)
{
	flexio_dev_window_mkey_config(FLEXIO_DEV_WINDOW_ENTITY_0, app_ctx[tid].host_buf_mkey);
	uint64_t res = 0;
	for (uint32_t i = 0; i < opt->num; i++) {
		int idx = __dpa_thread_cycles() & opt->mask;
		uint32_t s = 0;
		while (s < opt->size) {
			res += __atomic_load_n(&opt->data[(idx + s) & opt->mask], __ATOMIC_RELAXED);
			s++;
		}
	}
	return res;
}

static uint64_t write(struct io_opt *opt, __attribute__((unused)) int tid)
{
	for (uint32_t i = 0; i < opt->num; i++) {
		int idx = __dpa_thread_cycles() & opt->mask;
		uint32_t s = 0;
		while (s < opt->size) {
			opt->data[(idx + s) & opt->mask] = i;
			s++;
		}
	}
	return 0;
}

static uint64_t write_host(struct io_opt *opt, int tid)
{
	flexio_dev_window_mkey_config(FLEXIO_DEV_WINDOW_ENTITY_0, app_ctx[tid].host_buf_mkey);
	for (uint32_t i = 0; i < opt->num; i++) {
		int idx = __dpa_thread_cycles() & opt->mask;
		uint32_t s = 0;
		while (s < opt->size) {
			opt->data[(idx + s) & opt->mask] = i;
			s++;
		}
	}
	return 0;
}

static uint64_t atomic_write(struct io_opt *opt, __attribute__((unused)) int tid)
{
	for (uint32_t i = 0; i < opt->num; i++) {
		int idx = __dpa_thread_cycles() & opt->mask;
		uint32_t s = 0;
		while (s < opt->size) {
			__atomic_store_n(&opt->data[(idx + s) & opt->mask], i, __ATOMIC_RELAXED);
			s++;
		}
	}
	return 0;
}

static uint64_t atomic_write_host(struct io_opt *opt, int tid)
{
	flexio_dev_window_mkey_config(FLEXIO_DEV_WINDOW_ENTITY_0, app_ctx[tid].host_buf_mkey);
	for (uint32_t i = 0; i < opt->num; i++) {
		int idx = __dpa_thread_cycles() & opt->mask;
		uint32_t s = 0;
		while (s < opt->size) {
			__atomic_store_n(&opt->data[(idx + s) & opt->mask], i, __ATOMIC_RELAXED);
			s++;
		}
	}
	return 0;
}

static void process_packet_host(unsigned int tid, unsigned int pid, struct io_opt *opt, int count)
{
	/* TX packet handling variables */
	union flexio_dev_sqe_seg *swqe;
	/* Pointer to SQ data */
	char *sq_data;
	char *sq_data_dpa;

	/* Size of the data */
	uint32_t data_sz;

	for (int i = 0; i < count; i++)
	{
		opt[i].io_func(&opt[i], tid);
	}

	/* Extract relevant data from the CQE */
	data_sz = flexio_dev_cqe_get_byte_cnt(app_ctx[tid].rq_cq_ctx.cqe);
	
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

flexio_dev_event_handler_t flexio_pp_dev;
__dpa_global__ void flexio_pp_dev(uint64_t thread_arg)
{
	struct host2dev_packet_processor_data *data_from_host = (void *)thread_arg;
	uint8_t tid = data_from_host->id;
	uint8_t pid = data_from_host->port;

	struct io_opt opt[MAX_OPS];
	for (unsigned i = 0; i < data_from_host->op_count; i++)
	{
		opt[i].data = NULL;
		opt[i].num = data_from_host->ops[i].opt_num;
		opt[i].mask = data_from_host->ops[i].data_size / sizeof(size_t) - 1;
		opt[i].size = data_from_host->ops[i].opt_size;
	}

	/* If the thread is executed for first time, then initialize the context
	 */
	if (!data_from_host->not_first_run) {
		app_ctx_init(data_from_host, tid);
		data_from_host->not_first_run = 1;

		app_ctx[tid].host_rq_ctx.dpa_rx_buff = get_host_buffer(app_ctx[tid].host_rq_ctx.rq_window_id, app_ctx[tid].host_rq_ctx.rkey, app_ctx[tid].host_rq_ctx.host_rx_buff);
		app_ctx[tid].host_sq_ctx.dpa_tx_buff = get_host_buffer(app_ctx[tid].host_sq_ctx.sq_window_id, app_ctx[tid].host_sq_ctx.rkey, app_ctx[tid].host_sq_ctx.host_tx_buff);
	}

	for (unsigned i = 0; i < data_from_host->op_count; i++)
	{
		switch (data_from_host->ops[i].opt_type) {
			case READ_DPA:
			case READ_DPA_RANDOM:
				opt[i].data = (size_t *)data_from_host->dpa_buf_global;
				opt[i].io_func = read;
				break;
			case READ_ARM:
			case READ_ARM_RANDOM:
				opt[i].data = (size_t *)get_host_buffer(data_from_host->window_id, data_from_host->host_mkey_global, data_from_host->host_buf_global);
				opt[i].io_func = read_host;
				break;
			case WRITE_DPA:
			case WRITE_DPA_RANDOM:
				opt[i].data = (size_t *)data_from_host->dpa_buf_global;
				opt[i].io_func = write;
				break;
			case WRITE_ARM:
			case WRITE_ARM_RANDOM:
				opt[i].data = (size_t *)get_host_buffer(data_from_host->window_id, data_from_host->host_mkey_global, data_from_host->host_buf_global);
				opt[i].io_func = write_host;
				break;
			case ATOMIC_READ_DPA:
			case ATOMIC_READ_DPA_RANDOM:
				opt[i].data = (size_t *)data_from_host->dpa_buf_global;
				opt[i].io_func = atomic_read;
				break;
			case ATOMIC_READ_ARM:
			case ATOMIC_READ_ARM_RANDOM:
				opt[i].data = (size_t *)get_host_buffer(data_from_host->window_id, data_from_host->host_mkey_global, data_from_host->host_buf_global);
				opt[i].io_func = atomic_read_host;
				break;
			case ATOMIC_WRITE_DPA:
			case ATOMIC_WRITE_DPA_RANDOM:
				opt[i].data = (size_t *)data_from_host->dpa_buf_global;
				opt[i].io_func = atomic_write;
				break;
			case ATOMIC_WRITE_ARM:
			case ATOMIC_WRITE_ARM_RANDOM:
				opt[i].data = (size_t *)get_host_buffer(data_from_host->window_id, data_from_host->host_mkey_global, data_from_host->host_buf_global);
				opt[i].io_func = atomic_write_host;
				break;
			default:
				opt[i].data = (size_t *)data_from_host->dpa_buf_global;
				opt[i].io_func = read; // Default function
				break;
		}
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
			process_packet_host(tid, pid, opt, data_from_host->op_count);
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
