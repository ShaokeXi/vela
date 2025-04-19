#include <stdint.h>
#include <nfp/me.h>
#include <mem_atomic.h>
#include "pif_plugin.h"

#define IMB_NUM 8192
#define EMB_NUM 65536*128

typedef struct mb_bulk {
    uint32_t m[32];
} mb_bulk;

typedef struct mb_atomic {
    uint32_t m[8];
} mb_atomic;

__export __imem uint32_t rf_dbg[32];
__export __imem mb_bulk rf_imb[IMB_NUM];
__export __emem mb_bulk rf_emb[IMB_NUM];
__export __emem mb_atomic rf_eemb[EMB_NUM];
__shared __lmem uint32_t cnt;


int pif_plugin_single_me(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    uint64_t ctime, ptime, delta;
    PIF_PLUGIN_eth_T *eth = pif_plugin_hdr_get_eth(headers);

    // only one me can forward packets
    if (__ME() == PIF_APP_MASTER_ME) {

        /* __0 being the 32 lsbs and __1 being the 16 msbs */
        ptime = pif_plugin_meta_get__intrinsic_metadata__ingress_global_tstamp__0(headers);
        ptime |= ((uint64_t)pif_plugin_meta_get__intrinsic_metadata__ingress_global_tstamp__1(headers)) << 32;

        ctime = me_tsc_read();

        delta = ctime - ptime;

        PIF_HEADER_SET_eth___tstamp___0(eth, delta & 0xffffffff);
        PIF_HEADER_SET_eth___tstamp___1(eth, (delta >> 32) & 0xffff);
        
        return PIF_PLUGIN_RETURN_FORWARD;
    }
    else {
        return PIF_PLUGIN_RETURN_DROP;
    }
}

int pif_plugin_single_me_mem(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    uint64_t ctime, ptime, delta;
    __xwrite uint32_t w_r[8];
    __xread uint32_t r_r[8];
    PIF_PLUGIN_eth_T *eth = pif_plugin_hdr_get_eth(headers);

    // only one me can forward packets
    if (__ME() == PIF_APP_MASTER_ME) {

        ptime = me_tsc_read();
        mem_read_atomic(&r_r, &rf_dbg[0], sizeof(r_r));
        ctime = me_tsc_read();

        delta = ctime - ptime;

        PIF_HEADER_SET_eth___tstamp___0(eth, delta & 0xffffffff);
        PIF_HEADER_SET_eth___tstamp___1(eth, (delta >> 32) & 0xffff);
        
        return PIF_PLUGIN_RETURN_FORWARD;
    }
    else {
        return PIF_PLUGIN_RETURN_DROP;
    }
}

int pif_plugin_single_thread(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    uint64_t ctime, ptime, delta;
    PIF_PLUGIN_eth_T *eth = pif_plugin_hdr_get_eth(headers);

    // only one me can forward packets
    if (__ME() == PIF_APP_MASTER_ME && __ctx() == 0) {

        /* __0 being the 32 lsbs and __1 being the 16 msbs */
        ptime = pif_plugin_meta_get__intrinsic_metadata__ingress_global_tstamp__0(headers);
        ptime |= ((uint64_t)pif_plugin_meta_get__intrinsic_metadata__ingress_global_tstamp__1(headers)) << 32;

        ctime = me_tsc_read();

        delta = ctime - ptime;

        PIF_HEADER_SET_eth___tstamp___0(eth, delta & 0xffffffff);
        PIF_HEADER_SET_eth___tstamp___1(eth, (delta >> 32) & 0xffff);
        
        return PIF_PLUGIN_RETURN_FORWARD;
    }
    else {
        return PIF_PLUGIN_RETURN_DROP;
    }
}

int pif_plugin_ordinary(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    uint64_t ctime, ptime, delta;
    PIF_PLUGIN_eth_T *eth = pif_plugin_hdr_get_eth(headers);

    /* __0 being the 32 lsbs and __1 being the 16 msbs */
    ptime = pif_plugin_meta_get__intrinsic_metadata__ingress_global_tstamp__0(headers);
    ptime |= ((uint64_t)pif_plugin_meta_get__intrinsic_metadata__ingress_global_tstamp__1(headers)) << 32;

    ctime = me_tsc_read();

    delta = ctime - ptime;

    PIF_HEADER_SET_eth___tstamp___0(eth, delta & 0xffffffff);
    PIF_HEADER_SET_eth___tstamp___1(eth, (delta >> 32) & 0xffff);
    
    return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_ordinary_mem(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    uint64_t ctime, ptime, delta;
    __xread uint32_t r_r[8];
    int i;
    PIF_PLUGIN_eth_T *eth = pif_plugin_hdr_get_eth(headers);

    ptime = me_tsc_read();
    for (i = 0; i < 10; i++) {
        mem_read_atomic(&r_r, &rf_dbg[0], sizeof(r_r));
        // mem_read32(&r_r, &rf_m[0], sizeof(r_r));
        // mem_incr32(&rf_m[0]);
    }
    ctime = me_tsc_read();

    delta = ctime - ptime;

    PIF_HEADER_SET_eth___tstamp___0(eth, delta & 0xffffffff);
    PIF_HEADER_SET_eth___tstamp___1(eth, (delta >> 32) & 0xffff);
    
    return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_mem_cache(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    __xread mb_bulk r_r;
    int i, edst;
    PIF_PLUGIN_eth_T *eth = pif_plugin_hdr_get_eth(headers);
    edst = PIF_HEADER_GET_eth___dstAddr___0(eth);
    i = edst & 0xffff;
    cnt++;
    i = i << 7 | cnt & 0x7f;

    mem_read32(&r_r, &rf_emb[i], sizeof(r_r));

    return PIF_PLUGIN_RETURN_FORWARD;
}

void pif_plugin_init_master()
{
    return;
}

void pif_plugin_init()
{
    return;
}

//     12    12     8     24     8   
// ++++++++++++++++++++++++++++++++++
// | memt | opt | bnum | idx | onum |
// ++++++++++++++++++++++++++++++++++
int pif_plugin_mem_opt_old(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    uint64_t ctime, ptime, delta;
    __xread mb_bulk rb_v;
    __xread mb_atomic ra_v;
    __xwrite mb_bulk wb_v = {
        {
            1111, 2222, 3333, 4444, 5555, 6666, 7777, 8888, 
            9999, 1111, 2222, 3333, 4444, 5555, 6666, 7777,
            8888, 9999, 1111, 2222, 3333, 4444, 5555, 6666,
            7777, 8888, 9999, 1111, 2222, 3333, 4444, 5555
        }
    };
    __xwrite mb_atomic wa_v = {
        {
            1111, 2222, 3333, 4444, 5555, 6666, 7777
        }
    };
    __xwrite uint32_t b;
    uint32_t opt, memt, bnum, onum, mask, idx, i;
    uint64_t code;
    PIF_PLUGIN_eth_T *eth = pif_plugin_hdr_get_eth(headers);
    code = PIF_HEADER_GET_eth___info___1(eth);
    b = code;
    mem_write32(&b, &rf_dbg[8], sizeof(b));
    bnum = code & 0xff;
    opt = (code >> 8) & 0xfff;
    memt = (code >> 20) & 0xfff;
    code = code << 32 | PIF_HEADER_GET_eth___info___0(eth);
    b = code;
    mem_write32(&b, &rf_dbg[9], sizeof(b));
    idx = (code >> 8) & 0xffffff;
    onum = code & 0xff;


    // ptime = pif_plugin_meta_get__intrinsic_metadata__ingress_global_tstamp__0(headers);
    // ptime |= ((uint64_t)pif_plugin_meta_get__intrinsic_metadata__ingress_global_tstamp__1(headers)) << 32;

    // ctime = me_tsc_read();

    // delta = ctime - ptime;

    // PIF_HEADER_SET_eth___tstamp2___0(eth, delta & 0xffffffff);
    // PIF_HEADER_SET_eth___tstamp2___1(eth, (delta >> 32) & 0xffff);

    while (opt & 0x7) {
        switch (memt & 0x7) {
            case 1:
                // switch (opt) {
                    // case 1:
                        // ptime = me_tsc_read();
                        // for (i = 0; i < num; i++)
                            // mem_read32(&r_v, (__addr40 void *)&v1, sizeof(r_v));
                        // ctime = me_tsc_read();
                        // break;
                    // case 3:
                        // ptime = me_tsc_read();
                        // for (i = 0; i < num; i++)
                            // mem_write32(&w_v, (__addr40 void *)&v1, sizeof(w_v));
                        // ctime = me_tsc_read();
                        // break;
                    // default:
                        // return PIF_PLUGIN_RETURN_DROP;
                // }
                break;
            case 2: /* internal memory */
                switch (opt & 0x7) {
                    case 1:
                        ptime = me_tsc_read();
                        for (i = 0; i < onum; i++)
                            mem_read32(&rb_v, &rf_imb[idx], bnum << 2);
                        ctime = me_tsc_read();
                        break;
                    case 2:
                        ptime = me_tsc_read();
                        for (i = 0; i < onum; i++) {
                            switch (bnum) {
                                case 1:
                                    mem_read_atomic(&ra_v, &rf_imb[idx], 1 << 2);
                                    break;
                                case 2:
                                    mem_read_atomic(&ra_v, &rf_imb[idx], 2 << 2);
                                    break;
                                case 4:
                                    mem_read_atomic(&ra_v, &rf_imb[idx], 4 << 2);
                                    break;
                                case 8:
                                    mem_read_atomic(&ra_v, &rf_imb[idx], 8 << 2);
                                    break;
                                default:
                                    mem_incr32(&rf_dbg[0]);
                                    return PIF_PLUGIN_RETURN_DROP;                                    
                            }
                        }
                        ctime = me_tsc_read();
                        break;
                    case 3:
                        ptime = me_tsc_read();
                        for (i = 0; i < onum; i++)
                            mem_write32(&wb_v, &rf_imb[idx], bnum << 2);
                        ctime = me_tsc_read();
                        break;
                    case 4:
                        ptime = me_tsc_read();
                        for (i = 0; i < onum; i++) {
                            switch (bnum) {
                                case 1:
                                    mem_write_atomic(&wa_v, &rf_imb[idx], 1 << 2);
                                    break;
                                case 2:
                                    mem_write_atomic(&wa_v, &rf_imb[idx], 2 << 2);
                                    break;
                                case 4:
                                    mem_write_atomic(&wa_v, &rf_imb[idx], 4 << 2);
                                    break;
                                case 8:
                                    mem_write_atomic(&wa_v, &rf_imb[idx], 8 << 2);
                                    break;
                                default:
                                    mem_incr32(&rf_dbg[1]);
                                    return PIF_PLUGIN_RETURN_DROP;                                    
                            }
                        }
                        ctime = me_tsc_read();
                        break;
                    case 5:
                        ptime = me_tsc_read();
                        for (i = 0; i < onum; i++)
                            mem_incr32(&rf_imb[idx].m[0]);
                        ctime = me_tsc_read();
                        break;
                    default:
                        mem_incr32(&rf_dbg[2]);
                        return PIF_PLUGIN_RETURN_DROP;
                }
                break;
            case 3: /* external cache hit */
                switch (opt & 0x7) {
                    case 1:
                        ptime = me_tsc_read();
                        for (i = 0; i < onum; i++)
                            mem_read32(&rb_v, &rf_emb[idx], bnum << 2);
                        ctime = me_tsc_read();
                        break;
                    case 2:
                        ptime = me_tsc_read();
                        for (i = 0; i < onum; i++) {
                            switch (bnum) {
                                case 1:
                                    mem_read_atomic(&ra_v, &rf_emb[idx], 1 << 2);
                                    break;
                                case 2:
                                    mem_read_atomic(&ra_v, &rf_emb[idx], 2 << 2);
                                    break;
                                case 4:
                                    mem_read_atomic(&ra_v, &rf_emb[idx], 4 << 2);
                                    break;
                                case 8:
                                    mem_read_atomic(&ra_v, &rf_emb[idx], 8 << 2);
                                    break;
                                default:
                                    mem_incr32(&rf_dbg[3]);
                                    return PIF_PLUGIN_RETURN_DROP;                                    
                            }
                        }
                        ctime = me_tsc_read();
                        break;
                    case 3:
                        ptime = me_tsc_read();
                        for (i = 0; i < onum; i++)
                            mem_write32(&wb_v, &rf_emb[idx], bnum << 2);
                        ctime = me_tsc_read();
                        break;
                    case 4:
                        ptime = me_tsc_read();
                        for (i = 0; i < onum; i++) {
                            switch (bnum) {
                                case 1:
                                    mem_write_atomic(&wa_v, &rf_emb[idx], 1 << 2);
                                    break;
                                case 2:
                                    mem_write_atomic(&wa_v, &rf_emb[idx], 2 << 2);
                                    break;
                                case 4:
                                    mem_write_atomic(&wa_v, &rf_emb[idx], 4 << 2);
                                    break;
                                case 8:
                                    mem_write_atomic(&wa_v, &rf_emb[idx], 8 << 2);
                                    break;
                                default:
                                    mem_incr32(&rf_dbg[4]);
                                    return PIF_PLUGIN_RETURN_DROP;                                    
                            }
                        }
                        ctime = me_tsc_read();
                        break;
                    case 5:
                        ptime = me_tsc_read();
                        for (i = 0; i < onum; i++)
                            mem_incr32(&rf_emb[idx].m[0]);
                        ctime = me_tsc_read();
                        break;
                    default:
                        mem_incr32(&rf_dbg[5]);
                        return PIF_PLUGIN_RETURN_DROP;
                }
                break;
            case 4: /* external cache miss */
                switch (opt & 0x7) {
                    case 1:
                        ptime = me_tsc_read();
                        for (i = 0; i < onum; i++)
                            mem_read32(&rb_v, &rf_eemb[idx], bnum << 2);
                        ctime = me_tsc_read();
                        break;
                    case 2:
                        ptime = me_tsc_read();
                        for (i = 0; i < onum; i++)
                            mem_read_atomic(&ra_v, &rf_eemb[idx], sizeof(ra_v));
                        ctime = me_tsc_read();
                        break;
                    case 3:
                        ptime = me_tsc_read();
                        for (i = 0; i < onum; i++)
                            mem_write32(&wb_v, &rf_eemb[idx], bnum << 2);
                        ctime = me_tsc_read();
                        break;
                    case 4:
                        ptime = me_tsc_read();
                        for (i = 0; i < onum; i++)
                            mem_write_atomic(&wa_v, &rf_eemb[idx], sizeof(wa_v));
                        ctime = me_tsc_read();
                        break;
                    case 5:
                        ptime = me_tsc_read();
                        for (i = 0; i < onum; i++)
                            mem_incr32(&rf_eemb[idx].m[0]);
                        ctime = me_tsc_read();
                        break;
                    default:
                        mem_incr32(&rf_dbg[6]);
                        return PIF_PLUGIN_RETURN_DROP;
                }
                break;
            default:
                mem_incr32(&rf_dbg[7]);
                return PIF_PLUGIN_RETURN_DROP;
        }
        opt >>= 3;
        memt >>= 3;
    }

    delta = ctime - ptime;

    PIF_HEADER_SET_eth___tstamp___0(eth, delta & 0xffffffff);
    PIF_HEADER_SET_eth___tstamp___1(eth, (delta >> 32) & 0xffff);
    
    return PIF_PLUGIN_RETURN_FORWARD;
}


int pif_plugin_mem_opt(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    uint64_t ctime, ptime, delta;
    __xread mb_bulk rb_v;
    __xread mb_atomic ra_v;
    __xwrite mb_bulk wb_v = {
        {
            1111, 2222, 3333, 4444, 5555, 6666, 7777, 8888, 
            9999, 1111, 2222, 3333, 4444, 5555, 6666, 7777,
            8888, 9999, 1111, 2222, 3333, 4444, 5555, 6666,
            7777, 8888, 9999, 1111, 2222, 3333, 4444, 5555
        }
    };
    __xwrite mb_atomic wa_v = {
        {
            1111, 2222, 3333, 4444, 5555, 6666, 7777
        }
    };
    __xwrite uint32_t b;
    uint32_t opt, memt, bnum, onum, mask, idx, i, tmp_opt, tmp_memt;
    uint64_t code;
    PIF_PLUGIN_eth_T *eth = pif_plugin_hdr_get_eth(headers);
    code = PIF_HEADER_GET_eth___info___1(eth);
    b = code;
    mem_write32(&b, &rf_dbg[8], sizeof(b));
    bnum = code & 0xff;
    opt = (code >> 8) & 0xfff;
    memt = (code >> 20) & 0xfff;
    code = code << 32 | PIF_HEADER_GET_eth___info___0(eth);
    b = code;
    mem_write32(&b, &rf_dbg[9], sizeof(b));
    idx = (code >> 8) & 0xffffff;
    onum = code & 0xff;
    tmp_opt = opt;
    tmp_memt = memt;

    ptime = me_tsc_read();
    for (i = 0; i < onum; i++) {
        while (tmp_opt & 0x7) {
            switch (tmp_memt & 0x7) {
                case 1:
                    // switch (opt) {
                        // case 1:
                            // ptime = me_tsc_read();
                            // for (i = 0; i < num; i++)
                                // mem_read32(&r_v, (__addr40 void *)&v1, sizeof(r_v));
                            // ctime = me_tsc_read();
                            // break;
                        // case 3:
                            // ptime = me_tsc_read();
                            // for (i = 0; i < num; i++)
                                // mem_write32(&w_v, (__addr40 void *)&v1, sizeof(w_v));
                            // ctime = me_tsc_read();
                            // break;
                        // default:
                            // return PIF_PLUGIN_RETURN_DROP;
                    // }
                    break;
                case 2: /* internal memory */
                    switch (tmp_opt & 0x7) {
                        case 1:
                            mem_read32(&rb_v, &rf_imb[idx], bnum << 2);
                            break;
                        case 2:
                            switch (bnum) {
                                case 1:
                                    mem_read_atomic(&ra_v, &rf_imb[idx], 1 << 2);
                                    break;
                                case 2:
                                    mem_read_atomic(&ra_v, &rf_imb[idx], 2 << 2);
                                    break;
                                case 4:
                                    mem_read_atomic(&ra_v, &rf_imb[idx], 4 << 2);
                                    break;
                                case 8:
                                    mem_read_atomic(&ra_v, &rf_imb[idx], 8 << 2);
                                    break;
                                default:
                                    mem_incr32(&rf_dbg[0]);
                                    return PIF_PLUGIN_RETURN_DROP;                                    
                            }
                            break;
                        case 3:
                            mem_write32(&wb_v, &rf_imb[idx], bnum << 2);
                            break;
                        case 4:
                            switch (bnum) {
                                case 1:
                                    mem_write_atomic(&wa_v, &rf_imb[idx], 1 << 2);
                                    break;
                                case 2:
                                    mem_write_atomic(&wa_v, &rf_imb[idx], 2 << 2);
                                    break;
                                case 4:
                                    mem_write_atomic(&wa_v, &rf_imb[idx], 4 << 2);
                                    break;
                                case 8:
                                    mem_write_atomic(&wa_v, &rf_imb[idx], 8 << 2);
                                    break;
                                default:
                                    mem_incr32(&rf_dbg[1]);
                                    return PIF_PLUGIN_RETURN_DROP;                                    
                            }
                            break;
                        case 5:
                            mem_incr32(&rf_imb[idx].m[0]);
                            break;
                        default:
                            mem_incr32(&rf_dbg[2]);
                            return PIF_PLUGIN_RETURN_DROP;
                    }
                    break;
                case 3: /* external cache hit */
                    switch (tmp_opt & 0x7) {
                        case 1:
                            mem_read32(&rb_v, &rf_emb[idx], bnum << 2);
                            break;
                        case 2:
                            switch (bnum) {
                                case 1:
                                    mem_read_atomic(&ra_v, &rf_emb[idx], 1 << 2);
                                    break;
                                case 2:
                                    mem_read_atomic(&ra_v, &rf_emb[idx], 2 << 2);
                                    break;
                                case 4:
                                    mem_read_atomic(&ra_v, &rf_emb[idx], 4 << 2);
                                    break;
                                case 8:
                                    mem_read_atomic(&ra_v, &rf_emb[idx], 8 << 2);
                                    break;
                                default:
                                    mem_incr32(&rf_dbg[3]);
                                    return PIF_PLUGIN_RETURN_DROP;                                    
                            }
                            break;
                        case 3:
                            mem_write32(&wb_v, &rf_emb[idx], bnum << 2);
                            break;
                        case 4:
                            switch (bnum) {
                                case 1:
                                    mem_write_atomic(&wa_v, &rf_emb[idx], 1 << 2);
                                    break;
                                case 2:
                                    mem_write_atomic(&wa_v, &rf_emb[idx], 2 << 2);
                                    break;
                                case 4:
                                    mem_write_atomic(&wa_v, &rf_emb[idx], 4 << 2);
                                    break;
                                case 8:
                                    mem_write_atomic(&wa_v, &rf_emb[idx], 8 << 2);
                                    break;
                                default:
                                    mem_incr32(&rf_dbg[4]);
                                    return PIF_PLUGIN_RETURN_DROP;                                    
                            }
                            break;
                        case 5:
                            mem_incr32(&rf_emb[idx].m[0]);
                            break;
                        default:
                            mem_incr32(&rf_dbg[5]);
                            return PIF_PLUGIN_RETURN_DROP;
                    }
                    break;
                case 4: /* external cache miss */
                    switch (tmp_opt & 0x7) {
                        case 1:
                            mem_read32(&rb_v, &rf_eemb[idx], bnum << 2);
                            break;
                        case 2:
                            mem_read_atomic(&ra_v, &rf_eemb[idx], sizeof(ra_v));
                            break;
                        case 3:
                            mem_write32(&wb_v, &rf_eemb[idx], bnum << 2);
                            break;
                        case 4:
                            mem_write_atomic(&wa_v, &rf_eemb[idx], sizeof(wa_v));
                            break;
                        case 5:
                            mem_incr32(&rf_eemb[idx].m[0]);
                            break;
                        default:
                            mem_incr32(&rf_dbg[6]);
                            return PIF_PLUGIN_RETURN_DROP;
                    }
                    break;
                default:
                    mem_incr32(&rf_dbg[7]);
                    return PIF_PLUGIN_RETURN_DROP;
            }
            tmp_opt >>= 3;
            tmp_memt >>= 3;
        }
        tmp_opt = opt;
        tmp_memt = memt;
    }
    ctime = me_tsc_read();

    delta = ctime - ptime;

    PIF_HEADER_SET_eth___tstamp___0(eth, delta & 0xffffffff);
    PIF_HEADER_SET_eth___tstamp___1(eth, (delta >> 32) & 0xffff);
    
    return PIF_PLUGIN_RETURN_FORWARD;
}

/*
    32        32       32    
++++++++++++++++++++++++++++++
| tstamp_0 | info_1 | info_0 |
++++++++++++++++++++++++++++++
- tstamp_0 (low 32 bits) - operation times
- info_1 (high 32 bits) - operation number 2
- info_0 (low 32 bits) - operation number 1 and result
*/
int pif_plugin_alu_opt(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data)
{
    uint32_t i, onum, op1, op2;

    PIF_PLUGIN_eth_T *eth = pif_plugin_hdr_get_eth(headers);
    onum = PIF_HEADER_GET_eth___tstamp___0(eth);
    op1 = PIF_HEADER_GET_eth___info___0(eth);
    op2 = PIF_HEADER_GET_eth___info___1(eth);

    for (i = 0; i < onum; i++) {
        op1 += op2;
        op1 ^= op2;
        op1 -= op2;
        op1 &= op2;
        op1 |= op2;
        // op1 *= op2;
    }

    PIF_HEADER_SET_eth___info___0(eth, op1);

    return PIF_PLUGIN_RETURN_FORWARD;
}