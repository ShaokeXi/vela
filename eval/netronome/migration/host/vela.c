#include "migrate.h"

static float nic_busy_threshold = 5.5;
static float nic_idle_threshold = 5.7;

static void vela_lcore_stats()
{
	unsigned core = rte_lcore_id();
	unsigned port_id = core - 1;
	struct core_stats *cstat = &lcore_stats[core];
	struct rte_jobstats_context *ctx = &cstat->jobs_context;

	/* LCore statistics. */
	uint64_t stats_period, fwd_exec, idle_exec;

	/* Collect context statistics. */
	stats_period = ctx->state_time - ctx->start_time;

	rte_jobstats_context_reset(ctx);
	fwd_exec = cstat->fwd_job.exec_time;
	rte_jobstats_reset(&cstat->fwd_job);

	idle_exec = cstat->idle_job.exec_time;
	rte_jobstats_reset(&cstat->idle_job);

	struct timeval cur_tv;
	gettimeofday(&cur_tv, NULL);
	uint64_t diff_ts = TIMEVAL_TO_MSEC(cur_tv) - TIMEVAL_TO_MSEC(cstat->prev_tv) + 1;
	RTE_LOG(INFO, USER1, "[CPU %d] %d idle %.2f%%, exec %.2f%%, RX %ld pps, %.2f Gbps, to_cpu %d, to_nic %d, send_pkts %d, "
            "hitter_update %d, new state %d, del state %d, evict error %d, delete error %d, drop %d\n", 
            core, cstat->count++, idle_exec*100.0/stats_period, fwd_exec*100.0/stats_period, 
			cstat->recv_pkts*1000/diff_ts, cstat->recv_bytes*8.0/diff_ts/1000000, cstat->to_cpu, cstat->to_nic, cstat->send_pkts, 
            cstat->hitter_update, cstat->new_state, cstat->del_state, cstat->evict_error, cstat->del_error, dropped[port_id]);
	cstat->prev_tv = cur_tv;
	cstat->new_state = cstat->del_state = 0;
	cstat->recv_pkts = cstat->recv_bytes = cstat->to_cpu = cstat->to_nic = cstat->send_pkts = 0;
	cstat->hitter_update = 0;

	int i;
	if (core == 1)
	{
		for (i = 0; i < FLOW_NUM; i++)
		{
			flowStore[i].count = 0;
		}
	}
}

int vela_main_loop(void)
{
	unsigned core = rte_lcore_id();
	struct core_stats *cstat;
	uint8_t stats_read_pending = 0;
	uint8_t need_manage;
	struct rte_timer stats_timer;

	cstat = &lcore_stats[core];

	srand(core);

	rte_timer_reset_sync(&stats_timer, rte_get_timer_hz(), PERIODICAL, 
		core, vela_lcore_stats, NULL);
	rte_jobstats_init(&cstat->idle_job, "idle", 0, 0, 0, 0);

	int port_id = core - 1;
	gettimeofday(&cstat->prev_tv, NULL);
	prtMon[port_id].cpu_last_update = TIMEVAL_TO_MSEC(cstat->prev_tv);
	prtMon[port_id].nic_last_update = TIMEVAL_TO_MSEC(cstat->prev_tv);
	while (!force_quit)
	{
		do {
			rte_jobstats_context_start(&cstat->jobs_context);
			rte_jobstats_start(&cstat->jobs_context, &cstat->idle_job);

			uint64_t repeats = 0;

			do {
				uint64_t now = rte_get_timer_cycles();

				repeats++;
				need_manage = cstat->fwd_timer.expire < now;

			} while (!need_manage);

			if (likely(repeats != 1))
				rte_jobstats_finish(&cstat->idle_job, cstat->idle_job.target);
			else
				rte_jobstats_abort(&cstat->idle_job);

			rte_timer_manage();
			rte_jobstats_context_finish(&cstat->jobs_context);
		} while (likely(stats_read_pending == 0) && likely(!force_quit));

	}
	return 0;
}

int vela_fwd_loop(void)
{
	uint32_t nb_rx, q_id = 0, i;
    uint32_t core = rte_lcore_id();
	uint32_t port_id = core - 1;
	struct rte_mbuf *pkts_burst[BURST_SIZE];
	uint32_t ipOff = sizeof(struct ether_hdr);
	uint32_t tcpOff = ipOff + sizeof(struct ipv4_hdr);
	uint32_t intOff;

	state ev;
	int flow_ret = 0;

	struct core_stats *cstat = &lcore_stats[core];
	rte_jobstats_start(&cstat->jobs_context, &cstat->fwd_job);

	while ((nb_rx = rte_eth_rx_burst(port_id, q_id, pkts_burst, BURST_SIZE)) > 0)
	{
		for (i = 0; i < nb_rx; i++)
		{				
			uint8_t *ptr = (uint8_t *)pkts_burst[i]->buf_addr + pkts_burst[i]->data_off;
			struct ipv4_hdr *ipv4 = (struct ipv4_hdr *)(ptr + ipOff);
			uint32_t *intInfo;
			if (ipv4->next_proto_id == 6)
				intOff = tcpOff + sizeof(struct tcp_hdr);
			else if (ipv4->next_proto_id == 17)
				intOff = tcpOff + sizeof(struct udp_hdr);
			intInfo = (uint32_t *)(ptr + intOff);
			int opt = rte_be_to_cpu_32(intInfo[OPT]);

			switch (opt)
			{
				case PKT_INIT:
					ev.nic.bucket = rte_be_to_cpu_32(intInfo[BUCKET]);
					ev.nic.index = rte_be_to_cpu_32(intInfo[INDEX]);
					ev.addr.srcAddr = rte_be_to_cpu_32(intInfo[IDLE]);
					ev.addr.dstAddr = rte_be_to_cpu_32(intInfo[FLAG]);
					ev.addr.ports = rte_be_to_cpu_32(intInfo[COUNT]);
					ev.opt = opt;
					flow_ret = rte_hash_lookup(flowTbl, (void const *)&ev.addr);
					if (flow_ret == -ENOENT)
					{
						/* New Flow */
						if ((flow_ret = rte_hash_add_key(flowTbl, (void const *)&ev.addr)) >= 0)
						{
							flowStore[flow_ret] = ev;
							float random_value = (float)rand() / RAND_MAX;
							rte_atomic32_inc(&mCtrl.totalFlowCnt);
							if (random_value <= ratio && rte_atomic32_read(&mCtrl.nicFlowAlloc) <= mCtrl.nicTblSize)
							{
								/* Assign state to NIC */
								rte_atomic32_inc(&mCtrl.nicFlowAlloc);
								flowStore[flow_ret].status = INITIAL_INVALID;
							}
							else
							{
								/* Assign state to CPU */
								flowStore[flow_ret].status = INITIAL_VALID;
							}

							int elem_ret;
							/* Initiate the element table which is indexed by the nic entry address */
							if ((elem_ret = rte_hash_add_key(elemTbl, (void const *)&ev.nic)) >= 0)
							{
								elemMap[elem_ret] = flow_ret;
							}
						}
					}
					else if (flow_ret >= 0)
					{
						/* Existing flow, check duplication */
						if (flowStore[flow_ret].nic.bucket == ev.nic.bucket)
						{
							if (flowStore[flow_ret].nic.index > ev.nic.index)
							{
								/* Always hit the first matched entry on the nic side */
								int elem_ret;
								flowStore[flow_ret].nic.index = ev.nic.index;
								if ((elem_ret = rte_hash_add_key(elemTbl, (void const *)&ev.nic)) >= 0)
								{
									elemMap[elem_ret] = flow_ret;
								}
							}
						}
						else
						{
							int elem_ret;
							flowStore[flow_ret].nic = ev.nic;
							if ((elem_ret = rte_hash_add_key(elemTbl, (void const *)&ev.nic)) >= 0)
							{
								elemMap[elem_ret] = flow_ret;
							}
						}

						if (flowStore[flow_ret].status == INITIAL_INVALID)
						{
							if (flowStore[flow_ret].ctrlCnt % CTRL_UPDATE_FREQ == 0)
							{
								uint32_t info[_NLD] = {0};
								info[OPT] = rte_cpu_to_be_32(CTRL_OFFLOAD);
								info[BUCKET] = rte_cpu_to_be_32(flowStore[flow_ret].nic.bucket);
								info[INDEX] = rte_cpu_to_be_32(flowStore[flow_ret].nic.index);
								send_ctrl_pkt(port_id, intOff, info);
								cstat->send_pkts++;
							}
							flowStore[flow_ret].ctrlCnt++;
						}
						else if (flowStore[flow_ret].status == INITIAL_VALID)
						{
							if (flowStore[flow_ret].ctrlCnt % CTRL_UPDATE_FREQ == 0)
							{
								uint32_t info[_NLD] = {0};
								info[OPT] = rte_cpu_to_be_32(CTRL_EVICT);
								info[BUCKET] = rte_cpu_to_be_32(flowStore[flow_ret].nic.bucket);
								info[INDEX] = rte_cpu_to_be_32(flowStore[flow_ret].nic.index);
								send_ctrl_pkt(port_id, intOff, info);
								cstat->send_pkts++;
							}
							flowStore[flow_ret].ctrlCnt++;
						}
					}
					prtMon[port_id].cpu_cur_count++;
					break;
				
				case PKT_TO_CPU:
					prtMon[port_id].cpu_cur_count++;
					cstat->to_cpu++;
					break;
				
				case PKT_TO_NIC:
					prtMon[port_id].cpu_cur_count++;
					cstat->to_nic++;
					break;
									
				case CTRL_PIGGYBACK:
					prtMon[port_id].idle_sample++;
					prtMon[port_id].idle_time += rte_be_to_cpu_32(intInfo[IDLE]);

					/* Compute heavy hitter at CPU side */
					struct ipv4_hdr *ip = (struct ipv4_hdr *)(ptr + ipOff);
					struct tcp_hdr *tcp = (struct tcp_hdr *)(ptr + tcpOff);
					ev.addr.srcAddr = rte_be_to_cpu_32(ip->src_addr);
					ev.addr.dstAddr = rte_be_to_cpu_32(ip->dst_addr);
					ev.addr.ports = ((uint32_t)rte_be_to_cpu_16(tcp->src_port) << 16 | rte_be_to_cpu_16(tcp->dst_port));
					// uint32_t minCount = cms_update(&prtSketch[port_id], &ev.addr);

					flow_ret = rte_hash_lookup(flowTbl, (void const *)&ev.addr);
					if (flow_ret >= 0)
					{
						flowStore[flow_ret].count++;
						if (flowStore[flow_ret].count > LARGE_FLOW_THRESHOLD)
						{
							flowStore[flow_ret].heavy = true;
							cstat->hitter_update++;
						}
					}

					ev.nic.bucket = rte_be_to_cpu_32(intInfo[BUCKET]);
					ev.nic.index = rte_be_to_cpu_32(intInfo[INDEX]);
					int elem_ret = rte_hash_lookup(elemTbl, (void const *)&ev.nic);
					if (elem_ret >= 0)
					{
						flowStore[elemMap[elem_ret]].heavy = true;
					}
					prtMon[port_id].cpu_cur_count++;
					break;
				
				case CTRL_EVICT:
					ev.nic.bucket = rte_be_to_cpu_32(intInfo[BUCKET]);
					ev.nic.index = rte_be_to_cpu_32(intInfo[INDEX]);

					elem_ret = rte_hash_lookup(elemTbl, (void const *)&ev.nic);
					if (elem_ret >= 0)
					{
						if (elem_ret >= FLOW_NUM)
							printf("ERROR: More elem than flow number\n");
						
						if (flowStore[elemMap[elem_ret]].status != VALID)
						{
							cstat->new_state++;
							if (flowStore[elemMap[elem_ret]].status != INITIAL_VALID)
							{
								rte_atomic32_dec(&mCtrl.nicFlowCnt);
							}
							rte_atomic32_inc(&mCtrl.cpuFlowCnt);
							flowStore[elemMap[elem_ret]].status = VALID;
						}
					}
					else
					{
						cstat->evict_error++;
					}
					break;

				case CTRL_OFFLOAD:
					ev.nic.bucket = rte_be_to_cpu_32(intInfo[BUCKET]);
					ev.nic.index = rte_be_to_cpu_32(intInfo[INDEX]);
					
					elem_ret = rte_hash_lookup(elemTbl, (void const *)&ev.nic);
					if (elem_ret >= 0)
					{
						if (elem_ret >= FLOW_NUM)
							printf("ERROR: More elem than flow number\n");
						
						if (flowStore[elemMap[elem_ret]].status != INVALID)
						{
							cstat->del_state++;
							rte_atomic32_inc(&mCtrl.nicFlowCnt);
							if (flowStore[elemMap[elem_ret]].status != INITIAL_INVALID)
							{
								rte_atomic32_dec(&mCtrl.cpuFlowCnt);
							}
							flowStore[elemMap[elem_ret]].status = INVALID;
						}
					}
					else
					{
						cstat->del_error++;
					}
					break;
				
				case CTRL_TO_CPU:
					{
						uint32_t info[_NLD] = {0};
						info[OPT] = rte_cpu_to_be_32(CTRL_EVICT);
						info[BUCKET] = intInfo[BUCKET];
						info[INDEX] = intInfo[INDEX];
						send_ctrl_pkt(port_id, intOff, info);
					}
					break;
				
				case CTRL_TO_NIC:
					{
						uint32_t info[_NLD] = {0};
						info[OPT] = rte_cpu_to_be_32(CTRL_OFFLOAD);
						info[BUCKET] = intInfo[BUCKET];
						info[INDEX] = intInfo[INDEX];
						send_ctrl_pkt(port_id, intOff, info);
					}
					break;
			}

			cstat->recv_bytes += pkts_burst[i]->pkt_len;
			// if (opt == CTRL_PIGGYBACK && i == 0)
			// {
			// 	struct ether_hdr *ether = (struct ether_hdr *)ptr;
			// 	ether->ether_type = rte_cpu_to_be_16(0x0810 | (port_id & 3));
			// 	cstat->send_pkts += rte_eth_tx_buffer(port_id, q_id, tx_buffer[port_id], pkts_burst[i]);
			// }
			// else
			// {
			// 	rte_pktmbuf_free(pkts_burst[i]);
			// }
			rte_pktmbuf_free(pkts_burst[i]);
		}

		cstat->recv_pkts += nb_rx;
	}

	// cstat->send_pkts += rte_eth_tx_buffer_flush(port_id, q_id, tx_buffer[port_id]);
	rte_jobstats_finish(&cstat->fwd_job, cstat->fwd_job.target);
    return 0;
}


int recv_loop_vela(void)
{
	int to_cpu = 0, to_nic = 0;
	uint32_t core, nb_rx, rx_q = 0, i, time_cnt = 0;
	struct rte_mbuf *pkts_burst[BURST_SIZE];
	struct timeval cur_tv, prev_tv;
    uint64_t diff_ts, recv_pkts = 0, recv_bytes = 0;
	uint32_t send_pkts = 0;
    core = rte_lcore_id();
	uint32_t port_id = core - 1;
	uint32_t ipOff = sizeof(struct ether_hdr);
	uint32_t tcpOff = ipOff + sizeof(struct ipv4_hdr);
	uint32_t intOff = tcpOff + sizeof(struct tcp_hdr);

	// timer
	gettimeofday(&cur_tv, NULL);
    prev_tv = cur_tv;
	prtMon[port_id].cpu_last_update = TIMEVAL_TO_MSEC(cur_tv);
	prtMon[port_id].nic_last_update = TIMEVAL_TO_MSEC(cur_tv);

	state ev;
	int flow_ret = 0;
	uint32_t hitter_update = 0;
	uint32_t hit_flowTbl = 0;

	int new_state = 0, del_state = 0, del_error = 0, evict_error = 0;

	srand(core);

	while (!force_quit)
	{
		while ((nb_rx = rte_eth_rx_burst(port_id, rx_q, pkts_burst, BURST_SIZE)) > 0)
		{
			for (i = 0; i < nb_rx; i++)
			{				
				uint8_t *ptr = (uint8_t *)pkts_burst[i]->buf_addr + pkts_burst[i]->data_off;
				uint32_t *intInfo = (uint32_t *)(ptr + intOff);
				int opt = rte_be_to_cpu_32(intInfo[OPT]);

				switch (opt)
				{
					case PKT_INIT:
						ev.nic.bucket = rte_be_to_cpu_32(intInfo[BUCKET]);
						ev.nic.index = rte_be_to_cpu_32(intInfo[INDEX]);
						ev.addr.srcAddr = rte_be_to_cpu_32(intInfo[IDLE]);
						ev.addr.dstAddr = rte_be_to_cpu_32(intInfo[FLAG]);
						ev.addr.ports = rte_be_to_cpu_32(intInfo[COUNT]);
						ev.opt = opt;
						flow_ret = rte_hash_lookup(flowTbl, (void const *)&ev.addr);
						if (flow_ret == -ENOENT)
						{
							/* New Flow */
							if ((flow_ret = rte_hash_add_key(flowTbl, (void const *)&ev.addr)) >= 0)
							{
								flowStore[flow_ret] = ev;
								float random_value = (float)rand() / RAND_MAX;
								rte_atomic32_inc(&mCtrl.totalFlowCnt);
								if (random_value <= ratio && rte_atomic32_read(&mCtrl.nicFlowAlloc) <= mCtrl.nicTblSize)
								{
									/* Assign state to NIC */
									rte_atomic32_inc(&mCtrl.nicFlowAlloc);
									flowStore[flow_ret].status = INITIAL_INVALID;
								}
								else
								{
									/* Assign state to CPU */
									flowStore[flow_ret].status = INITIAL_VALID;
								}

								int elem_ret;
								/* Initiate the element table which is indexed by the nic entry address */
								if ((elem_ret = rte_hash_add_key(elemTbl, (void const *)&ev.nic)) >= 0)
								{
									elemMap[elem_ret] = flow_ret;
								}
							}
						}
						else if (flow_ret >= 0)
						{
							/* Existing flow, check duplication */
							if (flowStore[flow_ret].nic.bucket == ev.nic.bucket)
							{
								if (flowStore[flow_ret].nic.index > ev.nic.index)
								{
									/* Always hit the first matched entry on the nic side */
									int elem_ret;
									flowStore[flow_ret].nic.index = ev.nic.index;
									if ((elem_ret = rte_hash_add_key(elemTbl, (void const *)&ev.nic)) >= 0)
									{
										elemMap[elem_ret] = flow_ret;
									}
								}
							}
							else
							{
								int elem_ret;
								flowStore[flow_ret].nic = ev.nic;
								if ((elem_ret = rte_hash_add_key(elemTbl, (void const *)&ev.nic)) >= 0)
								{
									elemMap[elem_ret] = flow_ret;
								}
							}

							if (flowStore[flow_ret].status == INITIAL_INVALID)
							{
								if (flowStore[flow_ret].ctrlCnt % CTRL_UPDATE_FREQ == 0)
								{
									uint32_t info[_NLD] = {0};
									info[OPT] = rte_cpu_to_be_32(CTRL_OFFLOAD);
									info[BUCKET] = rte_cpu_to_be_32(flowStore[flow_ret].nic.bucket);
									info[INDEX] = rte_cpu_to_be_32(flowStore[flow_ret].nic.index);
									send_ctrl_pkt(port_id, intOff, info);
									send_pkts++;
								}
								flowStore[flow_ret].ctrlCnt++;
							}
							else if (flowStore[flow_ret].status == INITIAL_VALID)
							{
								if (flowStore[flow_ret].ctrlCnt % CTRL_UPDATE_FREQ == 0)
								{
									uint32_t info[_NLD] = {0};
									info[OPT] = rte_cpu_to_be_32(CTRL_EVICT);
									info[BUCKET] = rte_cpu_to_be_32(flowStore[flow_ret].nic.bucket);
									info[INDEX] = rte_cpu_to_be_32(flowStore[flow_ret].nic.index);
									send_ctrl_pkt(port_id, intOff, info);
									send_pkts++;
								}
								flowStore[flow_ret].ctrlCnt++;
							}
						}
						prtMon[port_id].cpu_cur_count++;
						break;
					
					case PKT_TO_CPU:
						prtMon[port_id].cpu_cur_count++;
						to_cpu++;
						break;
					
					case PKT_TO_NIC:
						prtMon[port_id].cpu_cur_count++;
						to_nic++;
						break;
										
					case CTRL_PIGGYBACK:
						prtMon[port_id].idle_sample++;
						prtMon[port_id].idle_time += rte_be_to_cpu_32(intInfo[IDLE]);

                        /* Compute heavy hitter at CPU side */
                        struct ipv4_hdr *ip = (struct ipv4_hdr *)(ptr + ipOff);
                        struct tcp_hdr *tcp = (struct tcp_hdr *)(ptr + tcpOff);
                        ev.addr.srcAddr = rte_be_to_cpu_32(ip->src_addr);
                        ev.addr.dstAddr = rte_be_to_cpu_32(ip->dst_addr);
                        ev.addr.ports = ((uint32_t)rte_be_to_cpu_16(tcp->src_port) << 16 | rte_be_to_cpu_16(tcp->dst_port));
                        // uint32_t minCount = cms_update(&prtSketch[port_id], &ev.addr);

                        flow_ret = rte_hash_lookup(flowTbl, (void const *)&ev.addr);
                        if (flow_ret >= 0)
                        {
                            flowStore[flow_ret].count++;
                            if (flowStore[flow_ret].count > LARGE_FLOW_THRESHOLD)
                            {
                                flowStore[flow_ret].heavy = true;
                                hitter_update++;
                            }
                        }

						/* Heavy hitters piggybacked from the NIC */
						ev.nic.bucket = rte_be_to_cpu_32(intInfo[BUCKET]);
						ev.nic.index = rte_be_to_cpu_32(intInfo[INDEX]);
						int elem_ret = rte_hash_lookup(elemTbl, (void const *)&ev.nic);
						if (elem_ret >= 0)
						{
							flowStore[elemMap[elem_ret]].heavy = true;
						}
                        prtMon[port_id].cpu_cur_count++;
						break;
					
					case CTRL_EVICT:
						ev.nic.bucket = rte_be_to_cpu_32(intInfo[BUCKET]);
						ev.nic.index = rte_be_to_cpu_32(intInfo[INDEX]);

						elem_ret = rte_hash_lookup(elemTbl, (void const *)&ev.nic);
						if (elem_ret >= 0)
						{
							if (elem_ret >= FLOW_NUM)
								printf("ERROR: More elem than flow number\n");
							
							if (flowStore[elemMap[elem_ret]].status != VALID)
							{
								new_state++;
								if (flowStore[elemMap[elem_ret]].status != INITIAL_VALID)
								{
									rte_atomic32_dec(&mCtrl.nicFlowCnt);
								}
								rte_atomic32_inc(&mCtrl.cpuFlowCnt);
								flowStore[elemMap[elem_ret]].status = VALID;
							}
						}
						else
						{
							evict_error++;
						}
						break;

					case CTRL_OFFLOAD:
						ev.nic.bucket = rte_be_to_cpu_32(intInfo[BUCKET]);
						ev.nic.index = rte_be_to_cpu_32(intInfo[INDEX]);
						
						elem_ret = rte_hash_lookup(elemTbl, (void const *)&ev.nic);
						if (elem_ret >= 0)
						{
							if (elem_ret >= FLOW_NUM)
								printf("ERROR: More elem than flow number\n");
							
							if (flowStore[elemMap[elem_ret]].status != INVALID)
							{
								del_state++;
								rte_atomic32_inc(&mCtrl.nicFlowCnt);
								if (flowStore[elemMap[elem_ret]].status != INITIAL_INVALID)
								{
									rte_atomic32_dec(&mCtrl.cpuFlowCnt);
								}
								flowStore[elemMap[elem_ret]].status = INVALID;
							}
						}
						else
						{
							del_error++;
						}
						break;
					
					case CTRL_TO_CPU:
						{
							uint32_t info[_NLD] = {0};
							info[OPT] = rte_cpu_to_be_32(CTRL_EVICT);
							info[BUCKET] = intInfo[BUCKET];
							info[INDEX] = intInfo[INDEX];
							send_ctrl_pkt(port_id, intOff, info);
						}
						break;
					
					case CTRL_TO_NIC:
						{
							uint32_t info[_NLD] = {0};
							info[OPT] = rte_cpu_to_be_32(CTRL_OFFLOAD);
							info[BUCKET] = intInfo[BUCKET];
							info[INDEX] = intInfo[INDEX];
							send_ctrl_pkt(port_id, intOff, info);
						}
						break;
				}

				recv_bytes += pkts_burst[i]->pkt_len;
				rte_pktmbuf_free(pkts_burst[i]);
			}

			recv_pkts += nb_rx;
		}

		/* Receiving status output */
        gettimeofday(&cur_tv, NULL);
        diff_ts = TIMEVAL_TO_MSEC(cur_tv) - TIMEVAL_TO_MSEC(prev_tv);
        if (diff_ts > interval)
		{
            RTE_LOG(INFO, USER1, "[CPU %d] %d RX %ld pps, %.2f Gbps, to_cpu %d, to_nic %d, send_pkts %d, "
                "hitter_update %d, hit_flowTbl %d, new state %d, del state %d, evict error %d, delete error %d\n", 
                core, time_cnt++, recv_pkts*1000/diff_ts, recv_bytes*8.0/diff_ts/1000000, to_cpu, to_nic, send_pkts, 
                hitter_update, hit_flowTbl, new_state, del_state, evict_error, del_error);
			prev_tv = cur_tv;
			new_state = del_state = 0;
            recv_pkts = recv_bytes = to_cpu = to_nic = send_pkts = 0;
			hitter_update = hit_flowTbl = 0;

            if (core == 1)
            {
                for (i = 0; i < FLOW_NUM; i++)
                {
                    flowStore[i].count = 0;
                }
            }
        }

	}
    
    return 0;
}

#define WINDOW_SIZE 3
static double win_average(double *win)
{
	int i;
	double sum = 0;
	for (i = 0; i < WINDOW_SIZE; i++)
	{
		sum += win[i];
	}
	return sum / WINDOW_SIZE;
}


#define _MIGRATE_TEST 1
int ctrl_loop_vela(void)
{
	uint32_t core;
	int port_id;
    core = rte_lcore_id();
	int ctrlPrt = core - 1;
	int flow_ret, elem_ret;
	int new_state = 0;
	int del_state = 0, del_error = 0, del_times = 0;
	int evict_error = 0, evict_times = 0, evict_loop = 0, break_loop = 0;
	int data_error = 0, flow_error = 0;
	int offIdx = 0;
	int evtIdx = 0;
	
	uint32_t rx_q = 0;
	struct rte_mbuf *pkts_burst[BURST_SIZE];

    /* rate control */
	int ctrl_pps = 10;
	struct timeval cur_tv, prev_tv;
    uint64_t hz = rte_get_timer_hz();
	uint64_t cpp = (ctrl_pps > 0) ? (hz / ctrl_pps) : hz;
	uint64_t tx_cycles = cpp, cur_tsc, next_tsc;
    uint64_t diff_ts;
	uint64_t cur_nfd_lost, pre_nfd_lost, cpu_lost;
	uint32_t recv_pkts = 0;

	/* control packet */
	uint32_t ipOff = sizeof(struct ether_hdr);
	uint32_t tcpOff = ipOff + sizeof(struct ipv4_hdr);
	uint32_t intOff = udp ? tcpOff + sizeof(struct udp_hdr) : tcpOff + sizeof(struct tcp_hdr);

    /* timer */
    gettimeofday(&cur_tv, NULL);
    prev_tv = cur_tv;
	next_tsc = rte_get_tsc_cycles() + tx_cycles;
	prtMon[ctrlPrt].cpu_last_update = TIMEVAL_TO_MSEC(cur_tv);

	char *nfd_lost = read_symbol("_pif_counter_DROP_NFD_NO_CREDITS", 0, 8);
	uint32_t value1, value2;
    sscanf(nfd_lost, "0x%*x:  0x%x 0x%x", &value1, &value2);
	pre_nfd_lost = ((uint64_t)value2 << 32) | value1;

	uint32_t update_success = 0;
	uint32_t update_failure = 0;

	state ev;
	double nic_rate = 0;
	double idle_win[WINDOW_SIZE] = {0};
	int idle_cnt = 0;
	int nic_table_size = 700000;

	while (!force_quit)
    {
		int i, nb_rx;
		while ((nb_rx = rte_eth_rx_burst(ctrlPrt, rx_q, pkts_burst, BURST_SIZE)) > 0)
		{
			for (i = 0; i < nb_rx; i++)
			{
				uint8_t *ptr = (uint8_t *)pkts_burst[i]->buf_addr + pkts_burst[i]->data_off;
				struct ipv4_hdr *ipv4 = (struct ipv4_hdr *)(ptr + ipOff);
				uint32_t *intInfo;
				if (ipv4->next_proto_id == 6)
					intOff = tcpOff + sizeof(struct tcp_hdr);
				else if (ipv4->next_proto_id == 17)
					intOff = tcpOff + sizeof(struct udp_hdr);
				intInfo = (uint32_t *)(ptr + intOff);
				int opt = rte_be_to_cpu_32(intInfo[OPT]);

				if (opt != PKT_INIT)
				{
					nic_flag = rte_be_to_cpu_32(intInfo[FLAG]);
					if (nic_flag > 2)
					{
						printf("nic flag error: %d, opt: %d\n", nic_flag, opt);
						nic_flag = OVERLOAD;
					}
				}

				switch(opt)
				{
					case CTRL_MONITOR:
						prtMon[ctrlPrt].nic_cur_count = rte_be_to_cpu_32(intInfo[COUNT]);
						prtMon[ctrlPrt].nic_cur_update = (uint64_t)intInfo[COUNT_TS_1] << 32 | intInfo[COUNT_TS_0];
						if (prtMon[ctrlPrt].nic_last_count == 0)
							prtMon[ctrlPrt].nic_last_count = prtMon[ctrlPrt].nic_cur_count;
						prtMon[ctrlPrt].idle_sample++;
						prtMon[ctrlPrt].idle_time += rte_be_to_cpu_32(intInfo[IDLE]);
						break;
					
					case CTRL_TO_CPU:
						{
							uint32_t info[_NLD] = {0};
							info[OPT] = rte_cpu_to_be_32(CTRL_EVICT);
							info[BUCKET] = intInfo[BUCKET];
							info[INDEX] = intInfo[INDEX];
							send_ctrl_pkt(ctrlPrt, intOff, info);
						}
						break;
					
					case CTRL_EVICT:
                        ev.nic.bucket = rte_be_to_cpu_32(intInfo[BUCKET]);
						ev.nic.index = rte_be_to_cpu_32(intInfo[INDEX]);
                        elem_ret = rte_hash_lookup(elemTbl, (void const *)&ev.nic);
						if (elem_ret >= 0)
						{
							if (elem_ret >= FLOW_NUM)
								printf("ERROR: More elem than flow number\n");
							
							if (flowStore[elemMap[elem_ret]].status != VALID)
							{
								new_state++;
								if (flowStore[elemMap[elem_ret]].status != INITIAL_VALID)
								{
									rte_atomic32_dec(&mCtrl.nicFlowCnt);
								}
								rte_atomic32_inc(&mCtrl.cpuFlowCnt);
								flowStore[elemMap[elem_ret]].status = VALID;
							}
						}
						else
						{
							evict_error++;
						}
                        break;

					case CTRL_OFFLOAD:
						ev.nic.bucket = rte_be_to_cpu_32(intInfo[BUCKET]);
						ev.nic.index = rte_be_to_cpu_32(intInfo[INDEX]);
						elem_ret = rte_hash_lookup(elemTbl, (void const *)&ev.nic);
						if (elem_ret >= 0)
						{
							if (elem_ret >= FLOW_NUM)
								printf("ERROR: More elem than flow number\n");
							
							if (flowStore[elemMap[elem_ret]].status != INVALID)
							{
								del_state++;
								rte_atomic32_inc(&mCtrl.nicFlowCnt);
								if (flowStore[elemMap[elem_ret]].status != INITIAL_INVALID)
								{
									rte_atomic32_dec(&mCtrl.cpuFlowCnt);
								}
								flowStore[elemMap[elem_ret]].status = INVALID;
							}
						}
						else
						{
							del_error++;
						}
						break;

					case CTRL_TO_NIC:
						{
							uint32_t info[_NLD] = {0};
							info[OPT] = rte_cpu_to_be_32(CTRL_OFFLOAD);
							info[BUCKET] = intInfo[BUCKET];
							info[INDEX] = intInfo[INDEX];
							send_ctrl_pkt(ctrlPrt, intOff, info);
						}
						break;
				}

				rte_pktmbuf_free(pkts_burst[i]);
			}

			recv_pkts += nb_rx;
		}

		/* State management */
		if (nic_flag == AVAILABLE)
		{
// #ifdef _MIGRATE_TEST
// 			if (rte_atomic32_read(&mCtrl.nicFlowCnt) < nic_table_size)
// #else
// 			if (rte_atomic32_read(&mCtrl.nicFlowCnt) < mCtrl.nicTblSize)
// #endif
// 			{
//                 int delCnt = 0;
// 				/* Sequentially offload heavy hitters */
// 				for (i = 0; i < FLOW_NUM; i++)
// 				{
//                     // if (flowStore[i].status == VALID && flowStore[i].heavy)
// 					if (flowStore[i].status == VALID)
//                     {
//                         uint32_t info[_NLD] = {0};
//                         info[OPT] = rte_cpu_to_be_32(CTRL_TO_NIC);
//                         info[BUCKET] = rte_cpu_to_be_32(flowStore[i].nic.bucket);
//                         info[INDEX] = rte_cpu_to_be_32(flowStore[i].nic.index);
//                         send_ctrl_pkt(ctrlPrt, intOff, info);
//                         del_times++;
//                         if (++delCnt > BURST_SIZE)
//                             break;
//                     }
// 				}
// 			}
// 			else
// 			{
// 				/* Randomly evict NIC flows to make more space for offloading */
// 				if (flowStore[offIdx].opt && flowStore[offIdx].status != VALID)
// 				{
// 					/* Sanity check */
// 					flow_ret = rte_hash_lookup(flowTbl, &flowStore[offIdx].addr);
// 					if (flow_ret != offIdx)
// 					{
// 						data_error++;
// 						flowStore[offIdx].opt = 0;
// 						flowStore[offIdx].status = INVALID;
// 					}
// 					else
// 					{
// 						elem_ret = rte_hash_lookup(elemTbl, &flowStore[offIdx].nic);
// 						if (elem_ret < 0)
// 						{
// 							if ((elem_ret = rte_hash_add_key(elemTbl, (void const *)&flowStore[offIdx].nic)) >= 0)
// 							{
// 								elemMap[elem_ret] = offIdx;
// 							}
// 						}
// 						else if (elemMap[elem_ret] != offIdx)
// 						{
// 							data_error++;
// 							elemMap[elem_ret] = offIdx;
// 						}
// 					}

// 					uint32_t info[_NLD] = {0};
// 					info[OPT] = rte_cpu_to_be_32(CTRL_TO_CPU);
// 					info[BUCKET] = rte_cpu_to_be_32(flowStore[offIdx].nic.bucket);
// 					info[INDEX] = rte_cpu_to_be_32(flowStore[offIdx].nic.index);
// 					send_ctrl_pkt(ctrlPrt, intOff, info);
// 					evict_times++;
// 				}
// 				else
// 				{
// 					/* Avoid selecting the heavy hitters */
// 					// while (flowStore[offIdx].status == VALID || flowStore[offIdx].opt == 0 || flowStore[offIdx].heavy)
// 					while (flowStore[offIdx].status == VALID || flowStore[offIdx].opt == 0)
// 					{
// 						offIdx++;
// 						if (offIdx == FLOW_NUM)
// 						{
// 							offIdx = 0;
// 							break_loop++;
// 							break;
// 						}
// 					}
// 					evict_loop++;
// 				}
// 			}
			if (rte_atomic32_read(&mCtrl.nicFlowCnt) < nic_table_size)
			{
				if (flowStore[offIdx].opt && flowStore[offIdx].status != INVALID)
				{
					/* Sanity check */
					flow_ret = rte_hash_lookup(flowTbl, &flowStore[offIdx].addr);
					if (flow_ret != offIdx)
					{
						data_error++;
						flowStore[offIdx].opt = 0;
						flowStore[offIdx].status = INVALID;
					}
					else
					{
						elem_ret = rte_hash_lookup(elemTbl, &flowStore[offIdx].nic);
						if (elem_ret < 0)
						{
							if ((elem_ret = rte_hash_add_key(elemTbl, (void const *)&flowStore[offIdx].nic)) >= 0)
							{
								elemMap[elem_ret] = offIdx;
							}
						}
						else if (elemMap[elem_ret] != offIdx)
						{
							data_error++;
							elemMap[elem_ret] = offIdx;
						}
					}

					uint32_t info[_NLD] = {0};
					info[OPT] = rte_cpu_to_be_32(CTRL_TO_NIC);
					info[BUCKET] = rte_cpu_to_be_32(flowStore[offIdx].nic.bucket);
					info[INDEX] = rte_cpu_to_be_32(flowStore[offIdx].nic.index);
					send_ctrl_pkt(ctrlPrt, intOff, info);
					del_times++;
					// fprintf(dbgFile, "evict bucket: 0x%08X, index: 0x%08X\n", flowStore[evtIdx].nic.bucket, flowStore[evtIdx].nic.index);
				}
				else
				{
					/* Selecting the heavy hitters */
					while (flowStore[offIdx].status == INVALID || flowStore[offIdx].opt == 0)
					{
						offIdx++;
						if (offIdx == FLOW_NUM)
						{
							offIdx = 0;
							break;
						}
					}
					evict_loop++;
				}
			}
			else
			{
				/* Randomly evict NIC flows to make more space for offloading */
				if (flowStore[offIdx].opt && flowStore[offIdx].status != VALID)
				{
					/* Sanity check */
					flow_ret = rte_hash_lookup(flowTbl, &flowStore[offIdx].addr);
					if (flow_ret != offIdx)
					{
						data_error++;
						flowStore[offIdx].opt = 0;
						flowStore[offIdx].status = INVALID;
					}
					else
					{
						elem_ret = rte_hash_lookup(elemTbl, &flowStore[offIdx].nic);
						if (elem_ret < 0)
						{
							if ((elem_ret = rte_hash_add_key(elemTbl, (void const *)&flowStore[offIdx].nic)) >= 0)
							{
								elemMap[elem_ret] = offIdx;
							}
						}
						else if (elemMap[elem_ret] != offIdx)
						{
							data_error++;
							elemMap[elem_ret] = offIdx;
						}
					}

					uint32_t info[_NLD] = {0};
					info[OPT] = rte_cpu_to_be_32(CTRL_TO_CPU);
					info[BUCKET] = rte_cpu_to_be_32(flowStore[offIdx].nic.bucket);
					info[INDEX] = rte_cpu_to_be_32(flowStore[offIdx].nic.index);
					send_ctrl_pkt(ctrlPrt, intOff, info);
					evict_times++;
				}
				else
				{
					while (flowStore[offIdx].status == VALID || flowStore[offIdx].opt == 0)
					{
						offIdx++;
						if (offIdx == FLOW_NUM)
						{
							offIdx = 0;
							break_loop++;
							break;
						}
					}
					evict_loop++;
				}
			}
			rte_delay_us_block(20);
		}
		else if (nic_flag == OVERLOAD)
		{
// #ifdef _MIGRATE_TEST
// 			// if (rte_atomic32_read(&mCtrl.cpuFlowCnt) < 330000)
// 			if (rte_atomic32_read(&mCtrl.cpuFlowCnt) < 600000)
// 			{
//                 int evtCnt = 0;
// 				/* Sequentially evict heavy hitters */
// 				for (i = 0; i < FLOW_NUM; i++)
// 				{
//                     // if (flowStore[i].status == INVALID && flowStore[i].heavy)
// 					if (flowStore[i].status == INVALID)
//                     {
//                         uint32_t info[_NLD] = {0};
//                         info[OPT] = rte_cpu_to_be_32(CTRL_TO_CPU);
//                         info[BUCKET] = rte_cpu_to_be_32(flowStore[i].nic.bucket);
//                         info[INDEX] = rte_cpu_to_be_32(flowStore[i].nic.index);
//                         send_ctrl_pkt(ctrlPrt, intOff, info);
//                         evict_times++;
//                         if (++evtCnt > BURST_SIZE)
//                             break;
//                     }
// 				}
// 			}
// #else
			if (rte_atomic32_read(&mCtrl.cpuFlowCnt) < 450000)
			{
				if (flowStore[evtIdx].opt && flowStore[evtIdx].status != VALID)
				{
					/* Sanity check */
					flow_ret = rte_hash_lookup(flowTbl, &flowStore[evtIdx].addr);
					if (flow_ret != evtIdx)
					{
						data_error++;
						flowStore[evtIdx].opt = 0;
						flowStore[evtIdx].status = INVALID;
					}
					else
					{
						elem_ret = rte_hash_lookup(elemTbl, &flowStore[evtIdx].nic);
						if (elem_ret < 0)
						{
							if ((elem_ret = rte_hash_add_key(elemTbl, (void const *)&flowStore[evtIdx].nic)) >= 0)
							{
								elemMap[elem_ret] = evtIdx;
							}
						}
						else if (elemMap[elem_ret] != evtIdx)
						{
							data_error++;
							elemMap[elem_ret] = evtIdx;
						}
					}

					uint32_t info[_NLD] = {0};
					info[OPT] = rte_cpu_to_be_32(CTRL_TO_CPU);
					info[BUCKET] = rte_cpu_to_be_32(flowStore[evtIdx].nic.bucket);
					info[INDEX] = rte_cpu_to_be_32(flowStore[evtIdx].nic.index);
					send_ctrl_pkt(ctrlPrt, intOff, info);
					evict_times++;
					// fprintf(dbgFile, "evict bucket: 0x%08X, index: 0x%08X\n", flowStore[evtIdx].nic.bucket, flowStore[evtIdx].nic.index);
				}
				else
				{
					/* Selecting the heavy hitters */
					// while (flowStore[evtIdx].status == VALID || flowStore[evtIdx].opt == 0 || flowStore[evtIdx].heavy == 0)
					while (flowStore[evtIdx].status == VALID || flowStore[evtIdx].opt == 0)
					{
						evtIdx++;
						if (evtIdx == FLOW_NUM)
						{
							evtIdx = 0;
							break;
						}
					}
					evict_loop++;
				}
			}
// #endif
		}

		/* Regular heartbeat packets */
		cur_tsc = rte_get_tsc_cycles();
		if (cur_tsc > next_tsc)
		{
			next_tsc = cur_tsc + tx_cycles;

			uint32_t info[_NLD] = {0};
			info[OPT] = rte_cpu_to_be_32(CTRL_MONITOR);
			gettimeofday(&cur_tv, NULL);
			info[COUNT_TS_0] = TIMEVAL_TO_MSEC(cur_tv) & 0xffffffff;
			info[COUNT_TS_1] = (TIMEVAL_TO_MSEC(cur_tv) >> 32) & 0xffffffff;
			send_ctrl_pkt(ctrlPrt, intOff, info);
		}

		/* Monitor NIC idle time */
		gettimeofday(&cur_tv, NULL);
        diff_ts = TIMEVAL_TO_MSEC(cur_tv) - TIMEVAL_TO_MSEC(prev_tv);
        if (diff_ts > interval)
		{
			double idle_time = 0, idle_sample = 0, nic_idle;
			double cpu_rate = 0, cpu_pkts, cpu_interval;
			for(port_id = 0; port_id < app_cores; port_id++)
			{
				idle_time += prtMon[port_id].idle_time;
				idle_sample += prtMon[port_id].idle_sample;
				cpu_pkts = prtMon[port_id].cpu_cur_count - prtMon[port_id].cpu_last_count;
				cpu_interval = TIMEVAL_TO_MSEC(cur_tv) - prtMon[port_id].cpu_last_update;
				prtMon[port_id].cpu_last_count = prtMon[port_id].cpu_cur_count;
				prtMon[port_id].cpu_last_update = TIMEVAL_TO_MSEC(cur_tv);
				cpu_rate += cpu_pkts / cpu_interval / 1000.0;
				// RTE_LOG(INFO, USER1, "port %d pkts %.2f interval %.2f rate %.2f\n", 
					// port_id, cpu_pkts, cpu_interval, cpu_rate);
				prtMon[port_id].idle_time = 0;
				prtMon[port_id].idle_sample = 0;
			}
			
			/* calculate CPU rate */
			nfd_lost = read_symbol("_pif_counter_DROP_NFD_NO_CREDITS", 0, 8);
			sscanf(nfd_lost, "0x%*x:  0x%x 0x%x", &value1, &value2);
			cur_nfd_lost = ((uint64_t)value2 << 32) | value1;
			cpu_lost = cur_nfd_lost - pre_nfd_lost;
			gettimeofday(&cur_tv, NULL);
			cpu_rate += cpu_lost / (TIMEVAL_TO_MSEC(cur_tv) - prtMon[ctrlPrt].cpu_last_update) / 1000.0;
			prtMon[ctrlPrt].cpu_last_update = TIMEVAL_TO_MSEC(cur_tv);

			/* calculate NIC rate */
			double nic_pkts = 0, nic_interval = 0;
			if (idle_sample == 0)
				idle_sample = 1;
			nic_idle = ((idle_time + prtMon[ctrlPrt].idle_time) / (idle_sample + prtMon[ctrlPrt].idle_sample)) * 16.0 / 1200;
			idle_win[idle_cnt++] = nic_idle;
			if (idle_cnt == WINDOW_SIZE)
				idle_cnt = 0;
			double idle_avg = win_average(idle_win);
			nic_pkts = prtMon[ctrlPrt].nic_cur_count - prtMon[ctrlPrt].nic_last_count;
			nic_interval = prtMon[ctrlPrt].nic_cur_update - prtMon[ctrlPrt].nic_last_update;
			nic_rate = nic_pkts / nic_interval / 1000.0;
			prtMon[ctrlPrt].nic_last_count = prtMon[ctrlPrt].nic_cur_count;
			prtMon[ctrlPrt].nic_last_update = prtMon[ctrlPrt].nic_cur_update;
			prtMon[ctrlPrt].idle_sample = prtMon[ctrlPrt].idle_time = 0;
			
			uint32_t info[_NLD] = {0};
			info[OPT] = rte_cpu_to_be_32(CTRL_FLAG);

			// FILE *file = fopen("nic_idle.txt", "r");
			// if (file != NULL)
			// {
			// 	fscanf(file, "%f %f", &nic_busy_threshold, &nic_idle_threshold);
			// 	fclose(file);
			// 	printf("nic busy threshold: %f, nic idle threshold: %f\n", nic_busy_threshold, nic_idle_threshold);
			// }
#ifdef _MIGRATE_TEST
			FILE *file = fopen("nic_table.txt", "r");
			if (file != NULL)
			{
				fscanf(file, "%d", &nic_table_size);
				fclose(file);
				printf("nic table size: %d\n", nic_table_size);
			}
#endif
            /* Idle Time Based Detection */
			int k, new_flag;
            float nic_busy_threshold = 5.6, nic_idle_threshold = 5.7;
            // if (nic_rate < 10)
            // {
            //     nic_busy_threshold = 5.4;
            //     nic_idle_threshold = 5.7;
            // }
            // else
            // {
            //     nic_busy_threshold = 75 * 1.0 / nic_rate;
            //     nic_idle_threshold = 80 * 1.0 / nic_rate;
            // }

			if (idle_avg < nic_busy_threshold)
			{
				new_flag = OVERLOAD;
				if (nic_flag != OVERLOAD)
				{
					info[FLAG] = rte_cpu_to_be_32(OVERLOAD);
					for (k = 0; k < CTRL_UPDATE_FREQ; k++)
					{
						send_ctrl_pkt(ctrlPrt, intOff, info);
					}
					// write_symbol("_flag", 0, 4, OVERLOAD);
				}
			}
			else if (idle_avg > nic_idle_threshold)
			{
				new_flag = AVAILABLE;
				if (nic_flag != AVAILABLE)
				{
					info[FLAG] = rte_cpu_to_be_32(AVAILABLE);
					for (k = 0; k < CTRL_UPDATE_FREQ; k++)
					{
						send_ctrl_pkt(ctrlPrt, intOff, info);
					}
					// write_symbol("_flag", 0, 4, AVAILABLE);
				}
			}
			else
			{
				new_flag = STABLE;
				if (nic_flag != STABLE)
				{
					info[FLAG] = rte_cpu_to_be_32(STABLE);
					for (k = 0; k < CTRL_UPDATE_FREQ; k++)
					{
						send_ctrl_pkt(ctrlPrt, intOff, info);
					}
					// write_symbol("_flag", 0, 4, STABLE);
				}
			}

			int i, cpu_state = 0, cpu_heavy = 0, cpu_light = 0, nic_heavy = 0, nic_light = 0;
			for (i = 0; i < FLOW_NUM; i++)
			{
				if (flowStore[i].status == VALID)
				{
					cpu_state++;
					if (flowStore[i].heavy == true)
						cpu_heavy++;
					else
						cpu_light++;
				}
				else if (flowStore[i].addr.srcAddr != 0)
				{
					if (flowStore[i].heavy == true)
						nic_heavy++;
					else
						nic_light++;
				}
			}

			RTE_LOG(INFO, USER1, "[CPU %d] new %d states, del %d states, cpu %d states, nic %d states, total %d states, "
					"recv %d pps, evict %d pps, del %d pps, del error %d, data_error %d, flow_error %d, evict_loop %d, break_loop %d\n", 
					core, new_state, del_state, cpu_state, rte_atomic32_read(&mCtrl.nicFlowCnt), rte_atomic32_read(&mCtrl.totalFlowCnt), 
					recv_pkts, evict_times, del_times, del_error, data_error, flow_error, evict_loop, break_loop);
			RTE_LOG(INFO, USER1, "[CPU %d] CPU %.2f Mpps, NIC %.2f Mpps, ME idle time %.2f us, NIC status %s, update success %d, failure %d, "
					"cpu heavy %d, cpu light %d, nic heavy %d, nic light %d\n", 
					core, cpu_rate, nic_rate, idle_avg, nic_status_map[new_flag], update_success, update_failure,
					cpu_heavy, cpu_light, nic_heavy, nic_light);
			prev_tv = cur_tv;
			pre_nfd_lost = cur_nfd_lost;
			new_state = evict_times = del_state = del_times = 0;
			evict_loop = break_loop = 0;
			update_success = update_failure = 0;
			recv_pkts = 0;
        }
	}

	return 0;
}

int ctrl_loop_latency_test(void)
{
	uint32_t core;
	int port_id;
    core = rte_lcore_id();
	int ctrlPrt = core - 1;
	int flow_ret, elem_ret;
	int new_state = 0;
	int del_state = 0, del_error = 0, del_times = 0;
	int evict_error = 0, evict_times = 0, evict_loop = 0, break_loop = 0;
	int data_error = 0, flow_error = 0;
	int offIdx = 0;
	int evtIdx = 0;
	
	uint32_t rx_q = 0;
	struct rte_mbuf *pkts_burst[BURST_SIZE];

    /* rate control */
	int ctrl_pps = 10;
	struct timeval cur_tv, prev_tv;
    uint64_t hz = rte_get_timer_hz();
	uint64_t cpp = (ctrl_pps > 0) ? (hz / ctrl_pps) : hz;
	uint64_t tx_cycles = cpp, cur_tsc, next_tsc;
    uint64_t diff_ts;
	uint64_t cur_nfd_lost, pre_nfd_lost, cpu_lost;
	uint32_t recv_pkts = 0;

	/* control packet */
	uint32_t ipOff = sizeof(struct ether_hdr);
	uint32_t tcpOff = ipOff + sizeof(struct ipv4_hdr);
	uint32_t intOff = udp ? tcpOff + sizeof(struct udp_hdr) : tcpOff + sizeof(struct tcp_hdr);

    /* timer */
    gettimeofday(&cur_tv, NULL);
    prev_tv = cur_tv;
	next_tsc = rte_get_tsc_cycles() + tx_cycles;
	prtMon[ctrlPrt].cpu_last_update = TIMEVAL_TO_MSEC(cur_tv);

	char *nfd_lost = read_symbol("_pif_counter_DROP_NFD_NO_CREDITS", 0, 8);
	uint32_t value1, value2;
    sscanf(nfd_lost, "0x%*x:  0x%x 0x%x", &value1, &value2);
	pre_nfd_lost = ((uint64_t)value2 << 32) | value1;

	uint32_t update_success = 0;
	uint32_t update_failure = 0;

	state ev;
	double nic_rate = 0;
	double idle_win[WINDOW_SIZE] = {0};
	int idle_cnt = 0;

	FILE *file = fopen("migrate_latency.txt", "w");
	if (file == NULL)
	{
		printf("File open failed.\n");
	}

	while (!force_quit)
    {
		int i, nb_rx;
		while ((nb_rx = rte_eth_rx_burst(ctrlPrt, rx_q, pkts_burst, BURST_SIZE)) > 0)
		{
			for (i = 0; i < nb_rx; i++)
			{
				uint8_t *ptr = (uint8_t *)pkts_burst[i]->buf_addr + pkts_burst[i]->data_off;
				struct ipv4_hdr *ipv4 = (struct ipv4_hdr *)(ptr + ipOff);
				uint32_t *intInfo;
				if (ipv4->next_proto_id == 6)
					intOff = tcpOff + sizeof(struct tcp_hdr);
				else if (ipv4->next_proto_id == 17)
					intOff = tcpOff + sizeof(struct udp_hdr);
				intInfo = (uint32_t *)(ptr + intOff);
				int opt = rte_be_to_cpu_32(intInfo[OPT]);

				if (opt != PKT_INIT)
				{
					nic_flag = rte_be_to_cpu_32(intInfo[FLAG]);
					if (nic_flag > 2)
					{
						printf("nic flag error: %d, opt: %d\n", nic_flag, opt);
						nic_flag = OVERLOAD;
					}
				}

				switch(opt)
				{
					case CTRL_MONITOR:
						prtMon[ctrlPrt].nic_cur_count = rte_be_to_cpu_32(intInfo[COUNT]);
						prtMon[ctrlPrt].nic_cur_update = (uint64_t)intInfo[COUNT_TS_1] << 32 | intInfo[COUNT_TS_0];
						if (prtMon[ctrlPrt].nic_last_count == 0)
							prtMon[ctrlPrt].nic_last_count = prtMon[ctrlPrt].nic_cur_count;
						prtMon[ctrlPrt].idle_sample++;
						prtMon[ctrlPrt].idle_time += rte_be_to_cpu_32(intInfo[IDLE]);
						break;
					
					case CTRL_TO_CPU:
						{
							uint32_t info[_NLD] = {0};
							info[OPT] = rte_cpu_to_be_32(CTRL_EVICT);
							info[BUCKET] = intInfo[BUCKET];
							info[INDEX] = intInfo[INDEX];
							info[COUNT_TS_0] = intInfo[COUNT_TS_0];
							info[COUNT_TS_1] = intInfo[COUNT_TS_1];
							send_ctrl_pkt(ctrlPrt, intOff, info);
						}
						break;
					
					case CTRL_EVICT:
                        ev.nic.bucket = rte_be_to_cpu_32(intInfo[BUCKET]);
						ev.nic.index = rte_be_to_cpu_32(intInfo[INDEX]);
                        elem_ret = rte_hash_lookup(elemTbl, (void const *)&ev.nic);
						if (elem_ret >= 0)
						{
							if (elem_ret >= FLOW_NUM)
								printf("ERROR: More elem than flow number\n");
							
							if (flowStore[elemMap[elem_ret]].status != VALID)
							{
								new_state++;
								if (flowStore[elemMap[elem_ret]].status != INITIAL_VALID)
								{
									rte_atomic32_dec(&mCtrl.nicFlowCnt);
								}
								rte_atomic32_inc(&mCtrl.cpuFlowCnt);
								flowStore[elemMap[elem_ret]].status = VALID;
							}
						}
						else
						{
							evict_error++;
						}

						struct timeval now;
						gettimeofday(&now, NULL);
						uint64_t prev_ts = (uint64_t)intInfo[COUNT_TS_0] * 1000000 + intInfo[COUNT_TS_1];
						uint64_t cur_ts = (uint64_t)now.tv_sec * 1000000 + now.tv_usec;
						fprintf(file, "%ld\n", cur_ts - prev_ts);
                        break;

					case CTRL_OFFLOAD:

						if (intInfo[BUCKET] == 0)
						{
							uint32_t info[_NLD] = {0};
							info[OPT] = rte_cpu_to_be_32(CTRL_OFFLOAD);
							info[BUCKET] = 1;
							info[INDEX] = intInfo[INDEX];
							info[COUNT_TS_0] = intInfo[COUNT_TS_0];
							info[COUNT_TS_1] = intInfo[COUNT_TS_1];
							send_ctrl_pkt(ctrlPrt, intOff, info);
						}
						else
						{
							ev.nic.bucket = rte_be_to_cpu_32(intInfo[BUCKET]);
							ev.nic.index = rte_be_to_cpu_32(intInfo[INDEX]);
							elem_ret = rte_hash_lookup(elemTbl, (void const *)&ev.nic);
							if (elem_ret >= 0)
							{
								if (elem_ret >= FLOW_NUM)
									printf("ERROR: More elem than flow number\n");

								if (flowStore[elemMap[elem_ret]].status != INVALID)
								{
									del_state++;
									rte_atomic32_inc(&mCtrl.nicFlowCnt);
									if (flowStore[elemMap[elem_ret]].status != INITIAL_INVALID)
									{
										rte_atomic32_dec(&mCtrl.cpuFlowCnt);
									}
									flowStore[elemMap[elem_ret]].status = INVALID;
								}
							}
							else
							{
								del_error++;
							}

							struct timeval now;
							gettimeofday(&now, NULL);
							uint64_t prev_ts = (uint64_t)intInfo[COUNT_TS_0] * 1000000 + intInfo[COUNT_TS_1];
							uint64_t cur_ts = (uint64_t)now.tv_sec * 1000000 + now.tv_usec;
							fprintf(file, "%ld\n", cur_ts - prev_ts);
						}
						break;

					case CTRL_TO_NIC:
						{
							uint32_t info[_NLD] = {0};
							info[OPT] = rte_cpu_to_be_32(CTRL_OFFLOAD);
							info[BUCKET] = intInfo[BUCKET];
							info[INDEX] = intInfo[INDEX];
							info[COUNT_TS_0] = intInfo[COUNT_TS_0];
							info[COUNT_TS_1] = intInfo[COUNT_TS_1];
							send_ctrl_pkt(ctrlPrt, intOff, info);
						}
						break;
				}

				rte_pktmbuf_free(pkts_burst[i]);
			}

			recv_pkts += nb_rx;
		}

		/* Migration latency test */
		cur_tsc = rte_get_tsc_cycles();
		if (cur_tsc > next_tsc)
		{
			next_tsc = cur_tsc + tx_cycles;

			uint32_t info[_NLD] = {0};
			info[OPT] = rte_cpu_to_be_32(CTRL_MONITOR);
			gettimeofday(&cur_tv, NULL);
			info[COUNT_TS_0] = TIMEVAL_TO_MSEC(cur_tv) & 0xffffffff;
			info[COUNT_TS_1] = (TIMEVAL_TO_MSEC(cur_tv) >> 32) & 0xffffffff;
			send_ctrl_pkt(ctrlPrt, intOff, info);

			uint32_t info2[_NLD] = {0};
			// info2[OPT] = rte_cpu_to_be_32(CTRL_TO_CPU);
			info2[OPT] = rte_cpu_to_be_32(CTRL_TO_NIC);
			gettimeofday(&cur_tv, NULL);
			info2[COUNT_TS_0] = cur_tv.tv_sec;
			info2[COUNT_TS_1] = cur_tv.tv_usec;
			send_ctrl_pkt(ctrlPrt, intOff, info2);
		}

		gettimeofday(&cur_tv, NULL);
        diff_ts = TIMEVAL_TO_MSEC(cur_tv) - TIMEVAL_TO_MSEC(prev_tv);
        if (diff_ts > interval)
		{
			double nic_pkts = 0, nic_interval = 0;
			nic_pkts = prtMon[ctrlPrt].nic_cur_count - prtMon[ctrlPrt].nic_last_count;
			nic_interval = prtMon[ctrlPrt].nic_cur_update - prtMon[ctrlPrt].nic_last_update;
			nic_rate = nic_pkts / nic_interval / 1000.0;
			printf("rate %.2f\n", nic_rate);
			fprintf(file, "rate %.2f\n", nic_rate);
			prev_tv = cur_tv;
			prtMon[ctrlPrt].nic_last_count = prtMon[ctrlPrt].nic_cur_count;
			prtMon[ctrlPrt].nic_last_update = prtMon[ctrlPrt].nic_cur_update;
		}

	}

	return 0;
}