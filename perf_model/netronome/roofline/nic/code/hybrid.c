#include <nfp/me.h>
#include <mem_atomic.h>
#include <pif_plugin.h>

#define IMB_NUM 1024*32
#define EMB_NUM 65536*128
#define BULK 8

__export __imem uint32_t p_dbg[32];
__export __imem uint32_t p_imb[IMB_NUM*BULK];
__export __emem uint32_t p_emb[EMB_NUM*BULK];

void pif_plugin_init_master()
{
    return;
}

void pif_plugin_init()
{
    return;
}

/*
- Memory operation descriptor format. 
    1     2     5     20      4
++++++++++++++++++++++++++++++++++
| memt | opt | bnum | idx | onum |
++++++++++++++++++++++++++++++++++
*/
int pif_plugin_mem_simulator(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    __xread uint32_t r_v[32], desc_v[8], desc_n;
    __xwrite uint32_t w_v[32] = {
        1, 2, 3, 4, 5, 6, 7, 8, 
        9, 10, 11, 12, 13, 14, 15, 16, 
        17, 18, 19, 20, 21, 22, 23, 24, 
        25, 26, 27, 28, 29, 30, 31, 32
    };
    __mem __addr40 uint8_t *mptr;
    int i, j, n, memt, opt, bnum, idx, onum;
    mptr = pkt.p_offset + (__mem __addr40 uint8_t *)pkt_ctm_ptr40(__ISLAND, pkt.p_pnum, 0);
    mptr += pif_pkt_info_spec.pkt_pl_off;
    mem_read32(&desc_n, (__mem40 void *)mptr, sizeof(desc_n));
    n = desc_n >> 24;
    n = n > 8 ? 8 : n;
    mptr++;
    mem_read32(&desc_v, (__mem40 void *)mptr, n << 2);
    // for (i = 0; i < n; i++) {
        // w_v[i] = desc_v[i];
    // }
    // mem_write32(&w_v[0], &p_dbg[i+16], n << 2);
    for (i = 0; i < n; i++) {
        memt = desc_v[i] >> 31;
        opt = (desc_v[i] >> 29) & 0x3;
        bnum = (desc_v[i] >> 24) & 0x1f;
        idx = (desc_v[i] >> 4) & 0xfffff;
        onum = desc_v[i] & 0xf;
        switch (memt) {
            case 0: /* internal memory */
                switch (opt) {
                    case 0:
                        for (j = 0; j < onum; j++)
                            mem_read32(&r_v, &p_imb[idx*BULK], bnum << 2);
                        break;
                    case 1:
                        switch (bnum) {
                            case 1:
                                for (j = 0; j < onum; j++)
                                    mem_read_atomic(&r_v, &p_imb[idx*BULK], 1 << 2);
                                break;
                            case 2:
                                for (j = 0; j < onum; j++)
                                    mem_read_atomic(&r_v, &p_imb[idx*BULK], 2 << 2);
                                break;
                            case 3:
                                for (j = 0; j < onum; j++)
                                    mem_read_atomic(&r_v, &p_imb[idx*BULK], 3 << 2);
                                break;
                            case 4:
                                for (j = 0; j < onum; j++)
                                    mem_read_atomic(&r_v, &p_imb[idx*BULK], 4 << 2);
                                break;
                            case 5:
                                for (j = 0; j < onum; j++)
                                    mem_read_atomic(&r_v, &p_imb[idx*BULK], 5 << 2);
                                break;
                            case 6:
                                for (j = 0; j < onum; j++)
                                    mem_read_atomic(&r_v, &p_imb[idx*BULK], 6 << 2);
                                break;
                            case 7:
                                for (j = 0; j < onum; j++)
                                    mem_read_atomic(&r_v, &p_imb[idx*BULK], 7 << 2);
                                break;
                            case 8:
                                for (j = 0; j < onum; j++)
                                    mem_read_atomic(&r_v, &p_imb[idx*BULK], 8 << 2);
                                break;
                            default:
                                mem_incr32(&p_dbg[0]);
                                return PIF_PLUGIN_RETURN_DROP;                                    
                        }
                        break;
                    case 2:
                        for (j = 0; j < onum; j++)
                            mem_write32(&w_v, &p_imb[idx*BULK], bnum << 2);
                        break;
                    case 3:
                        switch (bnum) {
                            case 1:
                                for (j = 0; j < onum; j++)
                                    mem_write_atomic(&w_v, &p_imb[idx*BULK], 1 << 2);
                                break;
                            case 2:
                                for (j = 0; j < onum; j++)
                                    mem_write_atomic(&w_v, &p_imb[idx*BULK], 2 << 2);
                                break;
                            case 3:
                                for (j = 0; j < onum; j++)
                                    mem_write_atomic(&w_v, &p_imb[idx*BULK], 3 << 2);
                                break;
                            case 4:
                                for (j = 0; j < onum; j++)
                                    mem_write_atomic(&w_v, &p_imb[idx*BULK], 4 << 2);
                                break;
                            case 5:
                                for (j = 0; j < onum; j++)
                                    mem_write_atomic(&w_v, &p_imb[idx*BULK], 5 << 2);
                                break;
                            case 6:
                                for (j = 0; j < onum; j++)
                                    mem_write_atomic(&w_v, &p_imb[idx*BULK], 6 << 2);
                                break;
                            case 7:
                                for (j = 0; j < onum; j++)
                                    mem_write_atomic(&w_v, &p_imb[idx*BULK], 7 << 2);
                                break;
                            case 8:
                                for (j = 0; j < onum; j++)
                                    mem_write_atomic(&w_v, &p_imb[idx*BULK], 8 << 2);
                                break;
                            default:
                                mem_incr32(&p_dbg[1]);
                                return PIF_PLUGIN_RETURN_DROP;                                    
                        }
                        break;
                    default:
                        mem_incr32(&p_dbg[2]);
                        return PIF_PLUGIN_RETURN_DROP;
                }
                break;
            case 1: /* external memory */
                switch (opt) {
                    case 0:
                        for (j = 0; j < onum; j++)
                            mem_read32(&r_v, &p_emb[idx*BULK], bnum << 2);
                        break;
                    case 1:
                        switch (bnum) {
                            case 1:
                                for (j = 0; j < onum; j++)
                                    mem_read_atomic(&r_v, &p_emb[idx*BULK], 1 << 2);
                                break;
                            case 2:
                                for (j = 0; j < onum; j++)
                                    mem_read_atomic(&r_v, &p_emb[idx*BULK], 2 << 2);
                                break;
                            case 3:
                                for (j = 0; j < onum; j++)
                                    mem_read_atomic(&r_v, &p_emb[idx*BULK], 3 << 2);
                                break;
                            case 4:
                                for (j = 0; j < onum; j++)
                                    mem_read_atomic(&r_v, &p_emb[idx*BULK], 4 << 2);
                                break;
                            case 5:
                                for (j = 0; j < onum; j++)
                                    mem_read_atomic(&r_v, &p_emb[idx*BULK], 5 << 2);
                                break;
                            case 6:
                                for (j = 0; j < onum; j++)
                                    mem_read_atomic(&r_v, &p_emb[idx*BULK], 6 << 2);
                                break;
                            case 7:
                                for (j = 0; j < onum; j++)
                                    mem_read_atomic(&r_v, &p_emb[idx*BULK], 7 << 2);
                                break;
                            case 8:
                                for (j = 0; j < onum; j++)
                                    mem_read_atomic(&r_v, &p_emb[idx*BULK], 8 << 2);
                                break;
                            default:
                                mem_incr32(&p_dbg[3]);
                                return PIF_PLUGIN_RETURN_DROP;                                    
                        }
                        break;
                    case 2:
                        for (j = 0; j < onum; j++)
                            mem_write32(&w_v, &p_emb[idx*BULK], bnum << 2);
                        break;
                    case 3:
                        switch (bnum) {
                            case 1:
                                for (j = 0; j < onum; j++)
                                    mem_write_atomic(&w_v, &p_emb[idx*BULK], 1 << 2);
                                break;
                            case 2:
                                for (j = 0; j < onum; j++)
                                    mem_write_atomic(&w_v, &p_emb[idx*BULK], 2 << 2);
                                break;
                            case 3:
                                for (j = 0; j < onum; j++)
                                    mem_write_atomic(&w_v, &p_emb[idx*BULK], 3 << 2);
                                break;
                            case 4:
                                for (j = 0; j < onum; j++)
                                    mem_write_atomic(&w_v, &p_emb[idx*BULK], 4 << 2);
                                break;
                            case 5:
                                for (j = 0; j < onum; j++)
                                    mem_write_atomic(&w_v, &p_emb[idx*BULK], 5 << 2);
                                break;
                            case 6:
                                for (j = 0; j < onum; j++)
                                    mem_write_atomic(&w_v, &p_emb[idx*BULK], 6 << 2);
                                break;
                            case 7:
                                for (j = 0; j < onum; j++)
                                    mem_write_atomic(&w_v, &p_emb[idx*BULK], 7 << 2);
                                break;
                            case 8:
                                for (j = 0; j < onum; j++)
                                    mem_write_atomic(&w_v, &p_emb[idx*BULK], 8 << 2);
                                break;
                            default:
                                mem_incr32(&p_dbg[4]);
                                return PIF_PLUGIN_RETURN_DROP;                                    
                        }
                        break;
                    default:
                        mem_incr32(&p_dbg[5]);
                        return PIF_PLUGIN_RETURN_DROP;
                }
                break;
            default:
                mem_incr32(&p_dbg[6]);
                return PIF_PLUGIN_RETURN_DROP;
        }
    }

    return PIF_PLUGIN_RETURN_FORWARD;
}