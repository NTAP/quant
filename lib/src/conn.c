// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2016-2019, NetApp, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include <inttypes.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>

#ifndef NO_ERR_REASONS
#include <stdarg.h>
#endif

#ifndef PARTICLE
#include <netinet/in.h>
#include <netinet/ip.h>
#endif

// IWYU pragma: no_include <picotls/../picotls.h>

#include <picotls.h> // IWYU pragma: keep
#include <quant/quant.h>
#include <timeout.h>

#include "bitset.h"
#include "conn.h"
#include "diet.h"
#include "frame.h"
#include "loop.h"
#include "marshall.h"
#include "pkt.h"
#include "pn.h"
#include "qlog.h"
#include "quic.h"
#include "recovery.h"
#include "stream.h"
#include "tls.h"


#undef CONN_STATE
#define CONN_STATE(k, v) [v] = #k

const char * const conn_state_str[] = {CONN_STATES};

struct q_conn_sl c_ready = sl_head_initializer(c_ready);

khash_t(conns_by_ipnp) conns_by_ipnp = {0};
khash_t(conns_by_id) conns_by_id = {0};
khash_t(conns_by_srt) conns_by_srt = {0};


static inline __attribute__((const)) bool is_vneg_vers(const uint32_t vers)
{
    return (vers & 0x0f0f0f0f) == 0x0a0a0a0a;
}


static inline __attribute__((const)) bool is_draft_vers(const uint32_t vers)
{
    return (vers & 0xff000000) == 0xff000000;
}


static inline int __attribute__((nonnull))
sockaddr_cmp(const struct sockaddr * const a, const struct sockaddr * const b)
{
    int diff = (a->sa_family > b->sa_family) - (a->sa_family < b->sa_family);
    if (diff)
        return diff;

    switch (a->sa_family) {
    case AF_INET:;
        const struct sockaddr_in * const a4 =
            (const struct sockaddr_in *)(const void *)a;
        const struct sockaddr_in * const b4 =
            (const struct sockaddr_in *)(const void *)b;
        diff = (a4->sin_port > b4->sin_port) - (a4->sin_port < b4->sin_port);
        if (diff)
            return diff;
        return (a4->sin_addr.s_addr > b4->sin_addr.s_addr) -
               (a4->sin_addr.s_addr < b4->sin_addr.s_addr);
    default:
#ifndef FUZZING
        die("unsupported address family");
#ifdef PARTICLE
        return 0; // old gcc doesn't seem to understand "noreturn" attribute
#endif
#else
        return memcmp(a->sa_data, b->sa_data, sizeof(a->sa_data));
#endif
    }
}

#ifndef NO_MIGRATION
SPLAY_GENERATE(cids_by_seq, cid, node_seq, cids_by_seq_cmp)
#endif


static bool __attribute__((const)) vers_supported(const uint32_t v)
{
    if (is_vneg_vers(v))
        return false;

    for (uint8_t i = 0; i < ok_vers_len; i++)
        if (v == ok_vers[i])
            return true;

    // we're out of matching candidates
    warn(INF, "no vers in common");
    return false;
}


static uint32_t __attribute__((nonnull))
clnt_vneg(const uint8_t * const pos, const uint8_t * const end)
{
    for (uint8_t i = 0; i < ok_vers_len; i++) {
        if (is_vneg_vers(ok_vers[i]))
            continue;

        const uint8_t * p = pos;
        while (p + sizeof(ok_vers[0]) <= end) {
            uint32_t vers = 0;
            dec4(&vers, &p, end);
            if (is_vneg_vers(vers))
                continue;
#ifdef DEBUG_EXTRA
            warn(DBG,
                 "serv prio %ld = 0x%0" PRIx32 "; our prio %u = 0x%0" PRIx32,
                 (unsigned long)(p - pos) / sizeof(vers), vers, i, ok_vers[i]);
#endif
            if (ok_vers[i] == vers)
                return vers;
        }
    }

    // we're out of matching candidates
    warn(INF, "no vers in common with serv");
    return 0;
}


#ifndef NO_OOO_0RTT
struct ooo_0rtt_by_cid ooo_0rtt_by_cid = splay_initializer(&ooo_0rtt_by_cid);

SPLAY_GENERATE(ooo_0rtt_by_cid, ooo_0rtt, node, ooo_0rtt_by_cid_cmp)
#endif


static inline epoch_t __attribute__((nonnull))
epoch_in(const struct q_conn * const c)
{
    const size_t epoch = ptls_get_read_epoch(c->tls.t);
    ensure(epoch <= ep_data, "unhandled epoch %lu", (unsigned long)epoch);
    return (epoch_t)epoch;
}


static struct q_conn * __attribute__((nonnull))
get_conn_by_ipnp(const struct sockaddr * const src,
                 const struct sockaddr * const dst)
{
    const khiter_t k = kh_get(conns_by_ipnp, &conns_by_ipnp,
                              (khint64_t)conns_by_ipnp_key(src, dst));
    if (unlikely(k == kh_end(&conns_by_ipnp)))
        return 0;
    return kh_val(&conns_by_ipnp, k);
}


static struct q_conn * __attribute__((nonnull))
get_conn_by_cid(struct cid * const scid)
{
    const khiter_t k = kh_get(conns_by_id, &conns_by_id, scid);
    if (unlikely(k == kh_end(&conns_by_id)))
        return 0;
    return kh_val(&conns_by_id, k);
}


struct q_conn * get_conn_by_srt(uint8_t * const srt)
{
    const khiter_t k = kh_get(conns_by_srt, &conns_by_srt, srt);
    if (unlikely(k == kh_end(&conns_by_srt)))
        return 0;
    return kh_val(&conns_by_srt, k);
}


#ifndef NO_MIGRATION
static inline void __attribute__((nonnull))
cids_by_id_ins(khash_t(cids_by_id) * const cbi, struct cid * const id)
{
    int ret;
    const khiter_t k = kh_put(cids_by_id, cbi, id, &ret);
    ensure(ret >= 1, "inserted returned %d", ret);
    kh_val(cbi, k) = id;
}


static inline void __attribute__((nonnull))
cids_by_id_del(khash_t(cids_by_id) * const cbi, struct cid * const id)
{
    const khiter_t k = kh_get(cids_by_id, cbi, id);
    ensure(k != kh_end(cbi), "found");
    kh_del(cids_by_id, cbi, k);
}


static struct cid * __attribute__((nonnull))
get_cid_by_id(const khash_t(cids_by_id) * const cbi, struct cid * const id)
{
    const khiter_t k = kh_get(cids_by_id, cbi, id);
    if (unlikely(k == kh_end(cbi)))
        return 0;
    return kh_val(cbi, k);
}


void use_next_dcid(struct q_conn * const c)
{
    struct cid * const dcid =
        splay_next(cids_by_seq, &c->dcids_by_seq, c->dcid);
    ensure(dcid, "can't switch from dcid %" PRIu, c->dcid->seq);

    mk_cid_str(NTE, dcid, dcid_str_new);
    mk_cid_str(NTE, c->dcid, dcid_str_prev);
    warn(NTE, "migration to dcid %s for %s conn (was %s)", dcid_str_new,
         conn_type(c), dcid_str_prev);

    if (c->spin_enabled)
        c->spin = 0; // need to reset spin value
    c->tx_retire_cid = c->dcid->retired = true;
    c->dcid = dcid;
}
#endif


#if (!defined(NDEBUG) || defined(NDEBUG_WITH_DLOG))
static void __attribute__((nonnull)) log_sent_pkts(struct q_conn * const c)
{
    for (pn_t t = pn_init; t <= pn_data; t++) {
        struct pn_space * const pn = &c->pns[t];
        if (pn->abandoned)
            continue;

        struct diet unacked = diet_initializer(unacked);
        struct pkt_meta * m;
        kh_foreach_value(&pn->sent_pkts, m,
                         diet_insert(&unacked, m->hdr.nr, 0));

#ifndef PARTICLE
        char buf[512];
#else
        char buf[64];
#endif
        int pos = 0;
        struct ival * i = 0;
        diet_foreach (i, diet, &unacked) {
            if ((size_t)pos >= sizeof(buf)) {
                buf[sizeof(buf) - 2] = buf[sizeof(buf) - 3] =
                    buf[sizeof(buf) - 4] = '.';
                buf[sizeof(buf) - 1] = 0;
                break;
            }

            if (i->lo == i->hi)
                pos += snprintf(&buf[pos], sizeof(buf) - (size_t)pos,
                                FMT_PNR_OUT "%s", i->lo,
                                splay_next(diet, &unacked, i) ? ", " : "");
            else
                pos += snprintf(&buf[pos], sizeof(buf) - (size_t)pos,
                                FMT_PNR_OUT ".." FMT_PNR_OUT "%s", i->lo, i->hi,
                                splay_next(diet, &unacked, i) ? ", " : "");
        }
        diet_free(&unacked);

        if (pos)
            warn(INF, "%s %s unacked: %s", conn_type(c), pn_type_str(t), buf);
    }
}
#else
#define log_sent_pkts(...)
#endif


static void __attribute__((nonnull))
rtx_pkt(struct w_iov * const v, struct pkt_meta * const m)
{
    struct q_conn * const c = m->pn->c;
    c->i.pkts_out_rtx++;

    if (m->lost)
        // we don't need to do the steps below if the pkt is lost already
        return;

    // on RTX, remember orig pkt meta data
    const uint16_t data_start = m->strm_data_pos;
    struct pkt_meta * m_orig;
    struct w_iov * const v_orig = alloc_iov(c->w, 0, data_start, &m_orig);
    pm_cpy(m_orig, m, true);
    memcpy(v_orig->buf - data_start, v->buf - data_start, data_start);
    m_orig->has_rtx = true;
    sl_insert_head(&m->rtx, m_orig, rtx_next);
    sl_insert_head(&m_orig->rtx, m, rtx_next);
    pm_by_nr_del(&m->pn->sent_pkts, m);
    // we reinsert m with its new pkt nr in on_pkt_sent()
    pm_by_nr_ins(&m_orig->pn->sent_pkts, m_orig);
}


static void __attribute__((nonnull)) mk_rand_cid(struct cid * const cid)
{
    cid->len = 8 + (uint8_t)w_rand_uniform32(CID_LEN_MAX - 7);
    rand_bytes(cid->id, sizeof(cid->id) + sizeof(cid->srt));
}


static void __attribute__((nonnull))
tx_vneg_resp(const struct w_sock * const ws,
             const struct w_iov * const v,
             struct pkt_meta * const m)
{
    struct pkt_meta * mx;
    struct w_iov * const xv = alloc_iov(ws->w, 0, 0, &mx);

    struct w_iov_sq q = w_iov_sq_initializer(q);
    sq_insert_head(&q, xv, next);

    warn(INF, "sending vneg serv response");
    mx->hdr.flags = HEAD_FORM | (uint8_t)w_rand_uniform32(UINT8_MAX);

    uint8_t * pos = xv->buf;
    const uint8_t * end = xv->buf + xv->len;
    enc1(&pos, end, mx->hdr.flags);
    enc4(&pos, end, mx->hdr.vers);
    enc_lh_cids(&pos, end, mx, &m->hdr.scid, &m->hdr.dcid);

    for (uint8_t j = 0; j < ok_vers_len; j++)
        if (!is_vneg_vers(ok_vers[j]))
            enc4(&pos, end, ok_vers[j]);

    mx->udp_len = xv->len = (uint16_t)(pos - xv->buf);
    xv->addr = v->addr;
    xv->flags = v->flags;
    log_pkt("TX", xv, (struct sockaddr *)&xv->addr, 0, 0, 0);
    struct cid gid;
    mk_rand_cid(&gid);
    qlog_transport(pkt_tx, "DEFAULT", xv, mx, &gid);

#ifndef FUZZING
    w_tx(ws, &q);
    while (w_tx_pending(&q))
        w_nic_tx(ws->w);
#endif

    q_free(&q);
}


static void __attribute__((nonnull)) do_tx(struct q_conn * const c)
{
    // do it here instead of in on_pkt_sent()
    set_ld_timer(c);
    log_cc(c);

    c->needs_tx = false;

    if (unlikely(sq_empty(&c->txq)))
        return;

    c->i.pkts_out += sq_len(&c->txq);

    if (sq_len(&c->txq) > 1 && unlikely(is_lh(*sq_first(&c->txq)->buf)))
        coalesce(&c->txq);
#ifndef FUZZING
    // transmit encrypted/protected packets
    w_tx(c->sock, &c->txq);
    do
        w_nic_tx(c->w);
    while (w_tx_pending(&c->txq));
#endif

#if defined(DEBUG_BUFFERS) && (!defined(NDEBUG) || defined(NDEBUG_WITH_DLOG))
    const uint_t avail = sq_len(&c->w->iov);
    const uint_t sql = sq_len(&c->txq);
#endif

    // txq was allocated straight from warpcore, no metadata needs to be freed
    w_free(&c->txq);

#ifdef DEBUG_BUFFERS
    warn(DBG, "w_free %" PRIu " (avail %" PRIu "->%" PRIu ")", sql, avail,
         sq_len(&c->w->iov));
#endif

    log_sent_pkts(c);
}


static void __attribute__((nonnull))
restart_key_flip_alarm(struct q_conn * const c)
{
    const timeout_t t = c->tls_key_update_frequency * NS_PER_S;

#ifdef DEBUG_TIMERS
    warn(DBG, "next key flip alarm in %f sec", t / (double)NS_PER_S);
#endif

    timeouts_add(ped(c->w)->wheel, &c->key_flip_alarm, t);
}


void do_conn_fc(struct q_conn * const c, const uint16_t len)
{
    if (unlikely(c->state == conn_clsg || c->state == conn_drng))
        return;

    if (len && c->out_data_str + len + MAX_PKT_LEN > c->tp_out.max_data)
        c->blocked = true;

    // check if we need to do connection-level flow control
    if (c->in_data_str * 2 > c->tp_in.max_data) {
        c->tx_max_data = true;
        c->tp_in.max_data *= 2;
    }
}


static void __attribute__((nonnull)) do_conn_mgmt(struct q_conn * const c)
{
    if (c->state == conn_clsg || c->state == conn_drng)
        return;

    // do we need to make more stream IDs available?
    if (likely(c->state == conn_estb)) {
        do_stream_id_fc(c, c->cnt_uni, false, true);
        do_stream_id_fc(c, c->cnt_bidi, true, true);
    }

#ifndef NO_MIGRATION
    if (likely(c->tp_out.disable_migration == false) &&
        unlikely(c->do_migration == true) && c->scid) {
        if (splay_count(&c->scids_by_seq) >= 2) {
            // the peer has a CID for us that they can switch to
            const struct cid * const dcid =
                splay_max(cids_by_seq, &c->dcids_by_seq);
            // if higher-numbered destination CIDs are available, switch to next
            if (dcid && dcid->seq > c->dcid->seq) {
                use_next_dcid(c);
                // don't migrate again for a while
                c->do_migration = false;
                restart_key_flip_alarm(c);
            }
        }
        // send new CIDs if the peer doesn't have sufficient remaining
        c->tx_ncid = needs_more_ncids(c);
    }
#endif
}


static bool __attribute__((nonnull)) tx_stream(struct q_stream * const s)
{
    struct q_conn * const c = s->c;

    const bool has_data = (sq_len(&s->out) && out_fully_acked(s) == false);

#ifdef DEBUG_STREAMS
    warn(ERR,
         "%s strm id=" FMT_SID ", cnt=%" PRIu
         ", has_data=%u, needs_ctrl=%u, blocked=%u, lost_cnt=%" PRIu
         ", fully_acked=%u, "
         "limit=%" PRIu32,
         conn_type(c), s->id, sq_len(&s->out), has_data, needs_ctrl(s),
         s->blocked, s->lost_cnt, out_fully_acked(s), c->tx_limit);
#endif

    // check if we should skip TX on this stream
    if (has_data == false || (s->blocked && s->lost_cnt == 0) ||
        // unless for 0-RTT, is this a regular stream during conn open?
        unlikely(c->try_0rtt == false && s->id >= 0 && c->state != conn_estb)) {
#ifdef DEBUG_STREAMS
        warn(ERR, "skip " FMT_SID " %u %u", s->id, c->try_0rtt, c->state);
#endif
        return true;
    }

#ifdef DEBUG_STREAMS
    mk_cid_str(INF, c->scid, scid_str);
    warn(INF, "TX on %s conn %s strm " FMT_SID " w/%" PRIu " pkt%s in queue ",
         conn_type(c), scid_str, s->id, sq_len(&s->out),
         plural(sq_len(&s->out)));
#endif

    uint32_t encoded = 0;
    struct w_iov * v = s->out_una;
    sq_foreach_from (v, &s->out, next) {
        struct pkt_meta * const m = &meta(v);
        if (unlikely(has_wnd(c, v->len) == false && c->tx_limit == 0)) {
            c->no_wnd = true;
            break;
        }

        if (unlikely(m->acked)) {
#ifdef DEBUG_EXTRA
            warn(INF, "skip ACK'ed pkt " FMT_PNR_OUT, m->hdr.nr);
#endif
            continue;
        }

        if (c->tx_limit == 0 && m->txed && m->lost == false) {
#ifdef DEBUG_EXTRA
            warn(INF, "skip non-lost TX'ed pkt " FMT_PNR_OUT, m->hdr.nr);
#endif
            continue;
        }

        if (likely(c->state == conn_estb && s->id >= 0)) {
            do_stream_fc(s, v->len);
            do_conn_fc(c, v->len);
        }

        const bool do_rtx = m->lost || (c->tx_limit && m->txed);
        if (unlikely(do_rtx))
            rtx_pkt(v, m);

        if (unlikely(enc_pkt(s, do_rtx, true, c->tx_limit > 0, v, m) == false))
            continue;
        encoded++;

        if (unlikely(s->blocked || c->blocked))
            break;

        if (unlikely(c->tx_limit && encoded == c->tx_limit)) {
#ifdef DEBUG_STREAMS
            warn(INF, "tx limit %" PRIu32 " reached", c->tx_limit);
#endif
            break;
        }
    }

    return (unlikely(c->tx_limit) && encoded == c->tx_limit) ||
           c->no_wnd == false;
}


static bool __attribute__((nonnull))
tx_ack(struct q_conn * const c, const epoch_t e, const bool tx_ack_eliciting)
{
    do_conn_mgmt(c);
    if (unlikely(c->cstrms[e] == 0))
        return false;

    struct pkt_meta * m;
    struct w_iov * const v = alloc_iov(c->w, 0, 0, &m);
    return enc_pkt(c->cstrms[e], false, false, tx_ack_eliciting, v, m);
}


void tx(struct q_conn * const c)
{
    timeouts_del(ped(c->w)->wheel, &c->tx_w);

    if (unlikely(c->state == conn_drng))
        return;

    if (unlikely(c->state == conn_qlse)) {
        enter_closing(c);
        tx_ack(c, epoch_in(c), false);
        goto done;
    }

    if (unlikely(c->tx_rtry)) {
        tx_ack(c, ep_init, false);
        goto done;
    }

    if (unlikely(c->state == conn_opng) && c->is_clnt && c->try_0rtt &&
        c->pns[pn_data].data.out_0rtt.aead == 0) {
        // if we have no 0-rtt keys here, the ticket didn't have any - disable
        warn(NTE, "TLS ticket w/o 0-RTT keys, disabling 0-RTT");
        c->try_0rtt = false;
    }

    if (unlikely(c->blocked))
        goto done;

    do_conn_mgmt(c);

    if (likely(c->state != conn_clsg))
        for (epoch_t e = ep_init; e <= ep_data; e++) {
            if (c->cstrms[e] == 0)
                continue;
            if (tx_stream(c->cstrms[e]) == false)
                goto done;
        }

    struct q_stream * s;
    kh_foreach_value(&c->strms_by_id, s, {
        if (tx_stream(s) == false)
            break;
    });

done:;
    // make sure we sent enough packets when we have a TX limit
    uint_t sent = sq_len(&c->txq);
    while ((unlikely(c->tx_limit) && sent < c->tx_limit) ||
           (c->needs_tx && sent == 0)) {
        if (likely(tx_ack(c, epoch_in(c), c->tx_limit && sent < c->tx_limit)))
            sent++;
        else {
            warn(WRN, "no ACK sent");
            break;
        }
    }
    if (likely(sent))
        do_tx(c);
}


void conns_by_srt_ins(struct q_conn * const c, uint8_t * const srt)
{
    int ret;
    const khiter_t k = kh_put(conns_by_srt, &conns_by_srt, srt, &ret);
    if (unlikely(ret == 0)) {
        if (kh_val(&conns_by_srt, k) != c)
            die("srt already in use by different conn ");
        else {
            mk_srt_str(WRN, srt, srt_str);
            warn(WRN, "srt %s already used for conn", srt_str);
            return;
        }
    }
    kh_val(&conns_by_srt, k) = c;
}


static inline void __attribute__((nonnull))
conns_by_srt_del(uint8_t * const srt)
{
    const khiter_t k = kh_get(conns_by_srt, &conns_by_srt, srt);
    if (likely(k != kh_end(&conns_by_srt)))
        // if peer is reusing SRTs w/different CIDs, it may already be deleted
        kh_del(conns_by_srt, &conns_by_srt, k);
}


static inline void __attribute__((nonnull))
conns_by_id_ins(struct q_conn * const c, struct cid * const id)
{
    int ret;
    const khiter_t k = kh_put(conns_by_id, &conns_by_id, id, &ret);
    ensure(ret >= 1, "inserted returned %d", ret);
    kh_val(&conns_by_id, k) = c;
}


static inline void __attribute__((nonnull))
conns_by_id_del(struct cid * const id)
{
    const khiter_t k = kh_get(conns_by_id, &conns_by_id, id);
    ensure(k != kh_end(&conns_by_id), "found");
    kh_del(conns_by_id, &conns_by_id, k);
}


static void __attribute__((nonnull)) update_act_scid(struct q_conn * const c)
{
    // server picks a new random cid
    struct cid nscid = {.len = SCID_LEN_SERV, .has_srt = true};
    rand_bytes(nscid.id, sizeof(nscid.id) + sizeof(nscid.srt));
    cid_cpy(&c->odcid, c->scid);
    mk_cid_str(NTE, &nscid, nscid_str);
    mk_cid_str(NTE, c->scid, scid_str);
    warn(NTE, "hshk switch to scid %s for %s %s conn (was %s)", nscid_str,
         conn_state_str[c->state], conn_type(c), scid_str);
    conns_by_id_del(c->scid);
#ifndef NO_MIGRATION
    cids_by_id_del(&c->scids_by_id, c->scid);
#endif
    cid_cpy(c->scid, &nscid);
#ifndef NO_MIGRATION
    cids_by_id_ins(&c->scids_by_id, c->scid);
#endif
    conns_by_id_ins(c, c->scid);

    // we need to keep accepting the client-chosen odcid for 0-RTT pkts
#ifndef NO_MIGRATION
    cids_by_id_ins(&c->scids_by_id, &c->odcid);
#endif
    conns_by_id_ins(c, &c->odcid);
}


void add_scid(struct q_conn * const c, struct cid * const id)
{
    struct cid * const scid = calloc(1, sizeof(*scid));
    ensure(scid, "could not calloc");
    cid_cpy(scid, id);
#ifndef NO_MIGRATION
    ensure(splay_insert(cids_by_seq, &c->scids_by_seq, scid) == 0, "inserted");
    cids_by_id_ins(&c->scids_by_id, scid);
#endif
    if (c->scid == 0)
        c->scid = scid;
    conns_by_id_ins(c, scid);
}


void add_dcid(struct q_conn * const c, const struct cid * const id)
{
    struct cid * dcid =
#ifndef NO_MIGRATION
        splay_find(cids_by_seq, &c->dcids_by_seq, id);
#else
        c->dcid;
#endif
    if (dcid == 0) {
        dcid = calloc(1, sizeof(*dcid));
        ensure(dcid, "could not calloc");
        if (c->dcid == 0)
            c->dcid = dcid;
    } else {
        mk_cid_str(NTE, id, dcid_str_new);
        mk_cid_str(NTE, c->dcid, dcid_str_prev);
        warn(NTE, "hshk switch to dcid %s for %s conn (was %s)", dcid_str_new,
             conn_type(c), dcid_str_prev);
#ifndef NO_MIGRATION
        ensure(splay_remove(cids_by_seq, &c->dcids_by_seq, dcid), "removed");
#endif
        if (dcid->has_srt)
            conns_by_srt_del(dcid->srt);
    }
    cid_cpy(dcid, id);
    if (id->has_srt)
        conns_by_srt_ins(c, dcid->srt);
#ifndef NO_MIGRATION
    ensure(splay_insert(cids_by_seq, &c->dcids_by_seq, dcid) == 0, "inserted");
#endif
}


static void __attribute__((nonnull))
rx_crypto(struct q_conn * const c, const struct pkt_meta * const m_cur)
{
    struct q_stream * const s = c->cstrms[epoch_in(c)];
    while (!sq_empty(&s->in)) {
        // take the data out of the crypto stream
        struct w_iov * const v = sq_first(&s->in);
        sq_remove_head(&s->in, next);

        // ooo crypto pkts have stream cleared by dec_stream_or_crypto_frame()
        struct pkt_meta * const m = &meta(v);
        const bool free_ooo = m->strm == 0;
        // mark this (potential in-order) pkt for freeing in rx_pkts()
        m->strm = 0;

        const int ret = tls_io(s, v);
        if (free_ooo && m != m_cur)
            free_iov(v, m);
        if (ret)
            continue;

        if (c->state == conn_idle || c->state == conn_opng) {
            conn_to_state(c, conn_estb);
            if (c->is_clnt)
                maybe_api_return(q_connect, c, 0);
            else {
                // TODO: find a better way to send NEW_TOKEN
                make_rtry_tok(c);
                if (c->needs_accept == false) {
                    sl_insert_head(&accept_queue, c, node_aq);
                    c->needs_accept = true;
                }
                maybe_api_return(q_accept, 0, 0);
            }
        }
    }
}


static void __attribute__((nonnull)) free_cids(struct q_conn * const c)
{
    if (c->is_clnt == false && c->odcid.len) {
        // TODO: we should stop accepting pkts on the client odcid earlier
#ifndef NO_MIGRATION
        cids_by_id_del(&c->scids_by_id, &c->odcid);
#endif
        conns_by_id_del(&c->odcid);
    }

    if (c->scid == 0)
        conns_by_ipnp_del(c);
#ifndef NO_MIGRATION
    while (!splay_empty(&c->scids_by_seq)) {
        struct cid * const id = splay_min(cids_by_seq, &c->scids_by_seq);
        free_scid(c, id);
    }

    while (!splay_empty(&c->dcids_by_seq)) {
        struct cid * const id = splay_min(cids_by_seq, &c->dcids_by_seq);
        free_dcid(c, id);
    }
#else
    if (c->scid)
        free_scid(c, c->scid);
    if (c->dcid)
        free_dcid(c, c->dcid);
#endif

    c->scid = c->dcid = 0;
}


static void __attribute__((nonnull(1))) new_cids(struct q_conn * const c,
                                                 const bool zero_len_scid,
                                                 const struct cid * const dcid,
                                                 const struct cid * const scid)
{
    // init dcid
    if (c->is_clnt) {
        struct cid ndcid = {.seq = 0};
        mk_rand_cid(&ndcid);
        cid_cpy(&c->odcid, &ndcid);
        add_dcid(c, &ndcid);
    } else if (dcid)
        add_dcid(c, dcid);

    // init scid and add connection to global data structures
    struct cid nscid = {0};
    if (c->is_clnt) {
        nscid.len = zero_len_scid ? 0 : SCID_LEN_CLNT;
        if (nscid.len)
            rand_bytes(nscid.id, sizeof(nscid.id) + sizeof(nscid.srt));
    } else if (scid) {
        cid_cpy(&nscid, scid);
        if (nscid.has_srt == false) {
            rand_bytes(nscid.srt, sizeof(nscid.srt));
            nscid.has_srt = true;
        }
    }
    if (nscid.len)
        add_scid(c, &nscid);
    else if (c->scid == 0)
        conns_by_ipnp_ins(c);
}


static void __attribute__((nonnull))
vneg_or_rtry_resp(struct q_conn * const c, const bool is_vneg)
{
    // reset FC state
    c->in_data_str = c->out_data_str = 0;

    for (epoch_t e = ep_init; e <= ep_data; e++)
        if (c->cstrms[e])
            reset_stream(c->cstrms[e], true);

    struct q_stream * s;
    kh_foreach_value(&c->strms_by_id, s, reset_stream(s, false));

    // reset packet number spaces
    for (pn_t t = pn_init; t <= pn_data; t++)
        reset_pn(&c->pns[t]);

    if (is_vneg) {
        // reset CIDs
        const bool zero_len_scid = c->scid == 0;
        free_cids(c); // this zeros c->scid
        new_cids(c, zero_len_scid, 0, 0);
    }

    // reset CC state
    init_rec(c);

    // reset TLS state and create new CH
    const bool should_try_0rtt = c->try_0rtt;
    init_tls(c, (char *)c->tls.alpn.base);
    c->try_0rtt = should_try_0rtt;
    tls_io(c->cstrms[ep_init], 0);
}


#if !defined(NDEBUG) || defined(NDEBUG_WITH_DLOG)
static bool __attribute__((const))
pkt_ok_for_epoch(const uint8_t flags, const epoch_t epoch)
{
    switch (epoch) {
    case ep_init:
        return pkt_type(flags) == LH_INIT || pkt_type(flags) == LH_RTRY;
    case ep_0rtt:
    case ep_hshk:
        return is_lh(flags);
    case ep_data:
        return true;
    }
#ifdef PARTICLE
    return false; // old gcc doesn't seem to understand "noreturn" attribute
#endif
}
#endif


static bool __attribute__((nonnull)) rx_pkt(const struct w_sock * const ws,
                                            struct w_iov * v,
                                            struct pkt_meta * m,
                                            struct w_iov_sq * const x
#ifdef NO_OOO_0RTT
                                            __attribute__((unused))
#endif
                                            ,
                                            const struct cid * const odcid
#if defined(NDEBUG) && !defined(NDEBUG_WITH_DLOG)
                                            __attribute__((unused))
#endif
                                            ,
                                            const uint8_t * const tok,
                                            const uint16_t tok_len)
{
    struct q_conn * const c = m->pn->c;
    bool ok = false;

    log_pkt("RX", v, (struct sockaddr *)&v->addr, odcid, tok, tok_len);
    c->in_data += m->udp_len;

    switch (c->state) {
    case conn_idle:
        // this is a new connection
        c->vers = m->hdr.vers;

        // TODO: remove this interop hack eventually
        if (bswap16(get_sport(ws)) == 4434) {
            if (m->hdr.type == LH_INIT && tok_len) {
                if (verify_rtry_tok(c, tok, tok_len) == false) {
                    warn(ERR, "retry token verification failed");
                    enter_closing(c);
                    goto done;
                }
            } else {
                if (c->tx_rtry) {
                    warn(DBG, "already tx'ing retry, ignoring");
                    goto done;
                }
                warn(INF, "sending retry");
                // send a RETRY
                make_rtry_tok(c);
                ok = true;
                c->needs_tx = c->tx_rtry = true;
                update_act_scid(c);
                goto done;
            }
        }

#ifdef DEBUG_EXTRA
        warn(INF, "supporting clnt-requested vers 0x%0" PRIx32, c->vers);
#endif
        if (dec_frames(c, &v, &m) == false)
            goto done;

        // if the CH doesn't include any crypto frames, bail
        if (has_frm(m->frms, FRM_CRY) == false) {
            warn(ERR, "initial pkt w/o crypto frames");
            enter_closing(c);
            goto done;
        }

        init_tp(c);

#ifndef NO_OOO_0RTT
        // check if any reordered 0-RTT packets are cached for this CID
        const struct ooo_0rtt which = {.cid = m->hdr.dcid};
        struct ooo_0rtt * const zo =
            splay_find(ooo_0rtt_by_cid, &ooo_0rtt_by_cid, &which);
        if (zo) {
            mk_cid_str(INF, c->scid, scid_str);
            warn(INF, "have reordered 0-RTT pkt for %s conn %s", conn_type(c),
                 scid_str);
            ensure(splay_remove(ooo_0rtt_by_cid, &ooo_0rtt_by_cid, zo),
                   "removed");
            sq_insert_head(x, zo->v, next);
            free(zo);
        }
#endif
        conn_to_state(c, conn_opng);

        // server limits response to 3x incoming pkt
        c->path_val_win = 3 * m->udp_len;

        // server picks a new random cid
        update_act_scid(c);

        ok = true;
        break;

    case conn_opng:
        // this state is currently only in effect on the client

        if (m->hdr.vers == 0) {
            // this is a vneg pkt
            m->hdr.nr = UINT_T_MAX;
            if (c->vers != ok_vers[0]) {
                // we must have already reacted to a prior vneg pkt
                warn(INF, "ignoring spurious vneg response");
                goto done;
            }

            // check that the rx'ed CIDs match our tx'ed CIDs
            const bool rx_scid_ok = !cid_cmp(&m->hdr.scid, c->dcid);
            const bool rxed_dcid_ok =
                m->hdr.dcid.len == 0 || !cid_cmp(&m->hdr.dcid, c->scid);
            if (rx_scid_ok == false || rxed_dcid_ok == false) {
                mk_cid_str(INF, rx_scid_ok ? &m->hdr.dcid : &m->hdr.scid,
                           cid_str1);
                mk_cid_str(INF, rx_scid_ok ? c->scid : c->dcid, cid_str2);
                warn(INF, "vneg %ccid mismatch: rx %s != %s",
                     rx_scid_ok ? 'd' : 's', cid_str1, cid_str2);
                enter_closing(c);
                goto done;
            }

            // only do vneg for draft and vneg versions
            if (is_vneg_vers(c->vers) == false &&
                is_draft_vers(c->vers) == false) {
                err_close(c, ERR_PROTOCOL_VIOLATION, 0,
                          "must not vneg for tx vers 0x%0" PRIx32, c->vers);
                goto done;
            }

            // handle an incoming vneg packet
            const uint32_t try_vers =
                clnt_vneg(v->buf + m->hdr.hdr_len, v->buf + v->len);
            if (try_vers == 0) {
                // no version in common with serv
                enter_closing(c);
                goto done;
            }

            vneg_or_rtry_resp(c, true);
            c->vers = try_vers;
            warn(INF,
                 "serv didn't like vers 0x%0" PRIx32
                 ", retrying with 0x%0" PRIx32 "",
                 c->vers_initial, c->vers);
            ok = true;
            goto done;
        }

        if (unlikely(m->hdr.vers != c->vers)) {
            warn(ERR,
                 "serv response w/vers 0x%0" PRIx32 " to CI w/vers 0x%0" PRIx32
                 ", ignoring",
                 m->hdr.vers, c->vers);
            goto done;
        }

        if (m->hdr.type == LH_RTRY) {
            m->hdr.nr = UINT_T_MAX;
            if (c->tok_len) {
                // we already had an earlier RETRY on this connection
                warn(INF, "already handled a retry, ignoring");
                goto done;
            }

            // handle an incoming retry packet
            c->tok_len = tok_len;
            memcpy(c->tok, tok, c->tok_len);
            vneg_or_rtry_resp(c, false);
            mk_tok_str(INF, c->tok, c->tok_len, tok_str);
            warn(INF, "handling serv retry w/tok %s", tok_str);
            ok = true;
            goto done;
        }

        // server accepted version -
        // if we get here, this should be a regular server-hello
        ok = dec_frames(c, &v, &m);
        break;

    case conn_estb:
    case conn_qlse:
    case conn_clsg:
    case conn_drng:
        if (is_lh(m->hdr.flags) && m->hdr.vers == 0) {
            // we shouldn't get another vneg packet here, ignore
            warn(NTE, "ignoring spurious vneg response");
            goto done;
        }

        // ignore 0-RTT packets if we're not doing 0-RTT
        if (c->did_0rtt == false && m->hdr.type == LH_0RTT) {
            warn(NTE, "ignoring 0-RTT pkt");
            goto done;
        }

        if (dec_frames(c, &v, &m) == false)
            goto done;

        ok = true;
        break;

    case conn_clsd:
        warn(NTE, "ignoring pkt for closed %s conn", conn_type(c));
        break;
    }

done:
    if (unlikely(ok == false))
        return false;

    if (likely(m->hdr.nr != UINT_T_MAX)) {
        struct pn_space * const pn = pn_for_pkt_type(c, m->hdr.type);
        // update ECN info
        switch (v->flags & IPTOS_ECN_MASK) {
        case IPTOS_ECN_ECT1:
            pn->ect1_cnt++;
            break;
        case IPTOS_ECN_ECT0:
            pn->ect0_cnt++;
            break;
        case IPTOS_ECN_CE:
            pn->ce_cnt++;
            break;
        }
        pn->pkts_rxed_since_last_ack_tx++;
    }

#ifndef NO_QLOG
    // if pkt has STREAM or CRYPTO frame but no strm pointer, it's a dup
    static const struct frames qlog_dup_chk =
        bitset_t_initializer(1 << FRM_CRY | 1 << FRM_STR);
    const bool dup_strm =
        bit_overlap(FRM_MAX, &m->frms, &qlog_dup_chk) && m->strm == 0;
    qlog_transport(dup_strm ? pkt_dp : pkt_rx, "DEFAULT", v, m, &c->odcid);
#endif
    return true;
}


#ifdef FUZZING
void
#else
static void __attribute__((nonnull))
#endif
rx_pkts(struct w_iov_sq * const x,
        struct q_conn_sl * const crx,
        const struct w_sock * const ws)
{
    struct cid outer_dcid = {0};
    while (!sq_empty(x)) {
        struct w_iov * const xv = sq_first(x);
        sq_remove_head(x, next);

#ifdef DEBUG_BUFFERS
        warn(DBG, "rx idx %" PRIu32 " (avail %" PRIu ") len %u type 0x%02x",
             w_iov_idx(xv), sq_len(&xv->w->iov), xv->len, *xv->buf);
#endif

#if (!defined(NDEBUG) || defined(NDEBUG_WITH_DLOG)) && !defined(FUZZING) &&    \
    !defined(NO_FUZZER_CORPUS_COLLECTION)
        // when called from the fuzzer, v->addr.ss_family is zero
        if (xv->addr.ss_family)
            write_to_corpus(corpus_pkt_dir, xv->buf, xv->len);
#endif

        // allocate new w_iov for the (eventual) unencrypted data and meta-data
        struct pkt_meta * m;
        struct w_iov * const v = alloc_iov(ws->w, 0, 0, &m);
        v->addr = xv->addr;
        v->flags = xv->flags;
        v->len = xv->len; // this is just so that log_pkt can show the rx len
        m->t = loop_now();

        bool pkt_valid = false;
        const bool is_clnt = w_connected(ws);
        struct q_conn * c = 0;
        struct q_conn * const c_ipnp = // only our client can use zero-len cids
            is_clnt ? get_conn_by_ipnp(w_get_addr(ws, true),
                                       (struct sockaddr *)&v->addr)
                    : 0;
        struct cid odcid = {.len = 0};
        uint8_t tok[MAX_TOK_LEN];
        uint16_t tok_len = 0;
        if (unlikely(!dec_pkt_hdr_beginning(
                xv, v, m, is_clnt, &odcid, tok, &tok_len,
                is_clnt ? (c_ipnp ? 0 : SCID_LEN_CLNT) : SCID_LEN_SERV))) {
            // we might still need to send a vneg packet
            if (w_connected(ws) == false) {
                if (m->hdr.scid.len == 0 || m->hdr.scid.len >= 4) {
                    warn(ERR, "received invalid %u-byte %s pkt, sending vneg",
                         v->len, pkt_type_str(m->hdr.flags, &m->hdr.vers));
                    tx_vneg_resp(ws, v, m);
                } else {
                    log_pkt("RX", v, (struct sockaddr *)&v->addr, &odcid, tok,
                            tok_len);
                    warn(ERR,
                         "received invalid %u-byte %s pkt w/invalid scid len "
                         "%u, ignoring",
                         v->len, pkt_type_str(m->hdr.flags, &m->hdr.vers),
                         m->hdr.scid.len);
                    goto drop;
                }
            } else
                warn(ERR, "received invalid %u-byte %s pkt), ignoring", v->len,
                     pkt_type_str(m->hdr.flags, &m->hdr.vers));
            // can't log packet, because it may be too short for log_pkt()
            goto drop;
        }

        c = get_conn_by_cid(&m->hdr.dcid);
        if (c == 0 && m->hdr.dcid.len == 0)
            c = c_ipnp;
        if (likely(is_lh(m->hdr.flags)) && !is_clnt) {
            if (c && m->hdr.type == LH_0RTT) {
                mk_cid_str(WRN, c->scid, scid_str);
                mk_cid_str(WRN, &m->hdr.dcid, dcid_str);
                if (c->did_0rtt)
                    warn(INF,
                         "got 0-RTT pkt for orig cid %s, new is %s, "
                         "accepting",
                         dcid_str, scid_str);
                else {
                    log_pkt("RX", v, (struct sockaddr *)&v->addr, &odcid, tok,
                            tok_len);
                    warn(WRN,
                         "got 0-RTT pkt for orig cid %s, new is %s, "
                         "but rejected 0-RTT, ignoring",
                         dcid_str, scid_str);
                    goto drop;
                }
            } else if (m->hdr.type == LH_INIT && c == 0) {
                // validate minimum packet size
                if (xv->len < MIN_INI_LEN) {
                    log_pkt("RX", v, (struct sockaddr *)&v->addr, &odcid, tok,
                            tok_len);
                    warn(ERR, "%u-byte Initial pkt too short (< %u)", xv->len,
                         MIN_INI_LEN);
                    goto drop;
                }

                if (vers_supported(m->hdr.vers) == false ||
                    is_vneg_vers(m->hdr.vers)) {
                    log_pkt("RX", v, (struct sockaddr *)&v->addr, &odcid, tok,
                            tok_len);
                    warn(WRN,
                         "clnt-requested vers 0x%0" PRIx32 " not supported",
                         m->hdr.vers);
                    tx_vneg_resp(ws, v, m);
                    goto drop;
                }

#if !defined(NDEBUG) || defined(NDEBUG_WITH_DLOG)
                char ip[NI_MAXHOST];
                char port[NI_MAXSERV];
                ensure(getnameinfo((struct sockaddr *)&v->addr, sizeof(v->addr),
                                   ip, sizeof(ip), port, sizeof(port),
                                   NI_NUMERICHOST | NI_NUMERICSERV) == 0,
                       "getnameinfo");

                mk_cid_str(NTE, &m->hdr.dcid, dcid_str);
                warn(NTE, "new serv conn on port %u from %s:%s w/cid=%s",
                     bswap16(get_sport(ws)), ip, port, dcid_str);
#endif
                c = new_conn(w_engine(ws), m->hdr.vers, &m->hdr.scid,
                             &m->hdr.dcid, (struct sockaddr *)&v->addr, 0,
                             get_sport(ws), 0);
                init_tls(c, 0);
            }
        }

        if (likely(c)) {
            if (m->hdr.scid.len && cid_cmp(&m->hdr.scid, c->dcid) != 0) {
                if (m->hdr.vers && m->hdr.type == LH_RTRY &&
                    cid_cmp(&odcid, c->dcid) != 0) {
                    log_pkt("RX", v, (struct sockaddr *)&v->addr, &odcid, tok,
                            tok_len);
                    mk_cid_str(ERR, &odcid, odcid_str);
                    mk_cid_str(ERR, c->dcid, dcid_str);
                    warn(ERR, "retry dcid mismatch %s != %s, ignoring pkt",
                         odcid_str, dcid_str);
                    goto drop;
                }
                if (c->state == conn_opng)
                    add_dcid(c, &m->hdr.scid);
            }

            if (m->hdr.dcid.len && cid_cmp(&m->hdr.dcid, c->scid) != 0) {
                struct cid * const scid =
#ifndef NO_MIGRATION
                    get_cid_by_id(&c->scids_by_id, &m->hdr.dcid);
#else
                    c->scid;
#endif
                if (unlikely(scid == 0)) {
                    log_pkt("RX", v, (struct sockaddr *)&v->addr, &odcid, tok,
                            tok_len);
                    mk_cid_str(ERR, &m->hdr.dcid, dcid_str);
                    warn(ERR, "unknown scid %s, ignoring pkt", dcid_str);
                    goto drop;
                }

                mk_cid_str(DBG, scid, scid_str_new);
                if (scid->seq <= c->scid->seq)
                    warn(DBG, "pkt has prev scid %s, accepting", scid_str_new);
                else {
                    mk_cid_str(NTE, c->scid, scid_str_prev);
                    warn(NTE, "migration to scid %s for %s conn (was %s)",
                         scid_str_new, conn_type(c), scid_str_prev);
                    c->scid = scid;
                }
            }

        } else {
#if !defined(FUZZING) && !defined(NO_OOO_0RTT)
            // if this is a 0-RTT pkt, track it (may be reordered)
            if (m->hdr.type == LH_0RTT && m->hdr.vers) {
                struct ooo_0rtt * const zo = calloc(1, sizeof(*zo));
                ensure(zo, "could not calloc");
                cid_cpy(&zo->cid, &m->hdr.dcid);
                zo->v = v;
                ensure(splay_insert(ooo_0rtt_by_cid, &ooo_0rtt_by_cid, zo) == 0,
                       "inserted");
                log_pkt("RX", v, (struct sockaddr *)&v->addr, &odcid, tok,
                        tok_len);
                mk_cid_str(INF, &m->hdr.dcid, dcid_str);
                warn(INF, "caching 0-RTT pkt for unknown conn %s", dcid_str);
                goto next;
            }
#endif
            log_pkt("RX", v, (struct sockaddr *)&v->addr, &odcid, tok, tok_len);

            if (is_srt(xv, m)) {
                mk_srt_str(INF, &xv->buf[xv->len - SRT_LEN], srt_str);
                warn(INF, BLU BLD "STATELESS RESET" NRM " token=%s", srt_str);
                goto next;
            }

            mk_cid_str(INF, &m->hdr.dcid, dcid_str);
            warn(INF, "cannot find conn %s for %u-byte %s pkt, ignoring",
                 dcid_str, v->len, pkt_type_str(m->hdr.flags, &m->hdr.vers));
            // hexdump(v->buf, v->len);
            goto drop;
        }

        if (likely(has_pkt_nr(m->hdr.flags, m->hdr.vers))) {
            bool decoal;
            if (unlikely(m->hdr.type == LH_INIT && c->cstrms[ep_init] == 0)) {
                // we already abandoned Initial pkt processing, ignore
                log_pkt("RX", v, (struct sockaddr *)&v->addr, &odcid, tok,
                        tok_len);
                warn(INF, "ignoring %u-byte %s pkt due to abandoned processing",
                     v->len, pkt_type_str(m->hdr.flags, &m->hdr.vers));
                goto drop;
            } else if (unlikely(dec_pkt_hdr_remainder(xv, v, m, c, x,
                                                      &decoal) == false)) {
                v->len = xv->len;
                log_pkt("RX", v, (struct sockaddr *)&v->addr, &odcid, tok,
                        tok_len);
                if (m->is_reset) {
                    mk_srt_str(INF, &xv->buf[xv->len - SRT_LEN], srt_str);
                    warn(INF, BLU BLD "STATELESS RESET" NRM " token=%s",
                         srt_str);
                } else
                    warn(ERR, "%s %u-byte %s pkt, ignoring",
                         pkt_ok_for_epoch(m->hdr.flags, epoch_in(c))
                             ? "crypto fail on"
                             : "rx invalid",
                         v->len, pkt_type_str(m->hdr.flags, &m->hdr.vers));
                goto drop;
            }

            // that dcid in split-out coalesced pkt matches outer pkt
            if (unlikely(decoal) && outer_dcid.len == 0) {
                // save outer dcid for checking
                cid_cpy(&outer_dcid, &m->hdr.dcid);
                goto decoal_done;
            }

            if (unlikely(outer_dcid.len) &&
                cid_cmp(&outer_dcid, &m->hdr.dcid) != 0) {
                log_pkt("RX", v, (struct sockaddr *)&v->addr, &odcid, tok,
                        tok_len);
                mk_cid_str(ERR, &m->hdr.dcid, dcid_str);
                mk_cid_str(ERR, &outer_dcid, outer_dcid_str);
                warn(ERR,
                     "outer dcid %s != inner dcid %s during "
                     "decoalescing, ignoring %s pkt",
                     outer_dcid_str, dcid_str,
                     pkt_type_str(m->hdr.flags, &m->hdr.vers));
                goto drop;
            }

            if (likely(decoal == false))
                // forget outer dcid
                outer_dcid.len = 0;

            // check if this pkt came from a new source IP and/or port
            if (sockaddr_cmp((struct sockaddr *)&c->peer,
                             (struct sockaddr *)&v->addr) != 0 &&
                (c->tx_path_chlg == false ||
                 sockaddr_cmp((struct sockaddr *)&c->migr_peer,
                              (struct sockaddr *)&v->addr) != 0)) {

#if !defined(NDEBUG) || defined(NDEBUG_WITH_DLOG)
                char ip[NI_MAXHOST];
                char port[NI_MAXSERV];
                ensure(getnameinfo((struct sockaddr *)&v->addr, sizeof(v->addr),
                                   ip, sizeof(ip), port, sizeof(port),
                                   NI_NUMERICHOST | NI_NUMERICSERV) == 0,
                       "getnameinfo");
#endif

                struct pn_space * const pn = &c->pns[pn_data];
                if (m->hdr.nr <= diet_max(&pn->recv_all)) {
                    log_pkt("RX", v, (struct sockaddr *)&v->addr, &odcid, tok,
                            tok_len);
                    warn(NTE,
                         "pkt from new peer %s:%s, nr " FMT_PNR_IN
                         " <= max " FMT_PNR_IN ", ignoring",
                         ip, port, m->hdr.nr, diet_max(&pn->recv_all));
                    goto drop;
                }

                warn(NTE,
                     "pkt from new peer %s:%s, nr " FMT_PNR_IN
                     " > max " FMT_PNR_IN ", probing",
                     ip, port, m->hdr.nr, diet_max(&pn->recv_all));

                rand_bytes(&c->path_chlg_out, sizeof(c->path_chlg_out));
                c->migr_peer = v->addr;
                c->needs_tx = c->tx_path_chlg = true;
            }
        } else
            // this is a vneg or rtry pkt, dec_pkt_hdr_remainder not called
            m->pn = &c->pns[pn_init];

    decoal_done:
        if (likely(rx_pkt(ws, v, m, x, &odcid, tok, tok_len))) {
            rx_crypto(c, m);
            c->min_rx_epoch = c->had_rx ? MIN(c->min_rx_epoch,
                                              epoch_for_pkt_type(m->hdr.type))
                                        : epoch_for_pkt_type(m->hdr.type);

            if (likely(has_pkt_nr(m->hdr.flags, m->hdr.vers))) {
                struct pn_space * const pn = pn_for_pkt_type(c, m->hdr.type);
                diet_insert(&pn->recv, m->hdr.nr, m->t);
                diet_insert(&pn->recv_all, m->hdr.nr, 0);
            }
            pkt_valid = true;

            // remember that we had a RX event on this connection
            if (unlikely(!c->had_rx)) {
                c->had_rx = true;
                sl_insert_head(crx, c, node_rx_int);
            }
        }

        if (m->strm == 0)
            // we didn't place this pkt in any stream - bye!
            goto drop;
        else if (unlikely(m->strm->state == strm_clsd &&
                          sq_empty(&m->strm->in)))
            free_stream(m->strm);
        goto next;

    drop:
        if (pkt_valid == false)
            qlog_transport(pkt_dp, "DEFAULT", v, m, &m->hdr.dcid);
        free_iov(v, m);
    next:
        if (likely(c)) {
            if (likely(pkt_valid))
                c->i.pkts_in_valid++;
            else
                c->i.pkts_in_invalid++;
        }

#ifdef DEBUG_BUFFERS
        warn(DBG, "w_free_iov idx %" PRIu32 " (avail %" PRIu ")", w_iov_idx(xv),
             sq_len(&xv->w->iov) + 1);
#endif
        w_free_iov(xv);
    }
}


void restart_idle_alarm(struct q_conn * const c)
{
    const timeout_t t =
        MAX((timeout_t)c->tp_in.idle_to * NS_PER_MS, 3 * c->rec.ld_alarm_val);

#ifdef DEBUG_TIMERS
    warn(DBG, "next idle alarm in %f sec", t / (double)NS_PER_S);
#endif

    timeouts_add(ped(c->w)->wheel, &c->idle_alarm, t);
}


static void __attribute__((nonnull)) restart_ack_alarm(struct q_conn * const c)
{
    const timeout_t t = c->tp_out.max_ack_del * NS_PER_MS;

#ifdef DEBUG_TIMERS
    warn(DBG, "next ACK alarm in %f sec", t / (double)NS_PER_S);
#endif

    timeouts_add(ped(c->w)->wheel, &c->ack_alarm, t);
}


void rx(struct w_sock * const ws)
{
    struct w_iov_sq x = w_iov_sq_initializer(x);
    struct q_conn_sl crx = sl_head_initializer(crx);
    w_rx(ws, &x);
    rx_pkts(&x, &crx, ws);

    // for all connections that had RX events
    while (!sl_empty(&crx)) {
        struct q_conn * const c = sl_first(&crx);
        sl_remove_head(&crx, node_rx_int);

        // clear the helper flags set above
        c->had_rx = false;

        if (unlikely(c->state == conn_drng))
            continue;

        // reset idle timeout
        if (likely(c->pns[pn_data].data.out_kyph ==
                   c->pns[pn_data].data.in_kyph))
            restart_idle_alarm(c);

        // is a TX needed for this connection?
        if (c->needs_tx) {
            c->tx_limit = 0;
            tx(c); // clears c->needs_tx if we TX'ed
        }

        for (epoch_t e = c->min_rx_epoch; e <= ep_data; e++) {
            if (c->cstrms[e] == 0 || e == ep_0rtt)
                // don't ACK abandoned and 0rtt pn spaces
                continue;
            struct pn_space * const pn = pn_for_epoch(c, e);
            switch (needs_ack(pn)) {
            case imm_ack:
                // TODO: find a way to push this from the RX to TX path
                tx_ack(c, e, false);
                do_tx(c);
                break;
            case del_ack:
                if (likely(c->state != conn_clsg))
                    restart_ack_alarm(c);
                break;
            case no_ack:
            case grat_ack:
                break;
            }
        }

        if (unlikely(c->tx_rtry))
            // if we sent a retry, forget the entire connection existed
            free_conn(c);
        else if (c->have_new_data) {
            if (!c->in_c_ready) {
                sl_insert_head(&c_ready, c, node_rx_ext);
                c->in_c_ready = true;
                maybe_api_return(q_ready, 0, 0);
            }
        }
    }
}


void
#ifndef NO_ERR_REASONS
err_close
#else
err_close_noreason
#endif
(struct q_conn * const c,
               const uint_t code,
               const uint8_t frm
#ifndef NO_ERR_REASONS
               ,
               const char * const fmt,
               ...
#endif
)
{
#ifndef FUZZING
    if (unlikely(c->err_code)) {
#ifndef NO_ERR_REASONS
        warn(WRN,
             "ignoring new err 0x%" PRIx "; existing err is 0x%" PRIx " (%s) ",
             code, c->err_code, c->err_reason);
#endif
        return;
    }
#endif

#ifndef NO_ERR_REASONS
    va_list ap;
    va_start(ap, fmt);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
    const int ret = vsnprintf(c->err_reason, sizeof(c->err_reason), fmt, ap);
    ensure(ret >= 0, "vsnprintf() failed");
    va_end(ap);

    warn(ERR, "%s", c->err_reason);
    c->err_reason_len =
        (uint8_t)MIN((unsigned long)ret + 1, sizeof(c->err_reason));
#endif
    conn_to_state(c, conn_qlse);
    c->err_code = code;
    c->err_frm = frm;
    c->needs_tx = true;
    enter_closing(c);
}


static void __attribute__((nonnull)) key_flip(struct q_conn * const c)
{
    c->do_key_flip = c->key_flips_enabled;
#ifndef NO_MIGRATION
    // XXX we borrow the key flip timer for this
    c->do_migration = !c->tp_out.disable_migration;
#endif
}


static void __attribute__((nonnull)) stop_all_alarms(struct q_conn * const c)
{
    timeouts_del(ped(c->w)->wheel, &c->rec.ld_alarm);
    timeouts_del(ped(c->w)->wheel, &c->idle_alarm);
    timeouts_del(ped(c->w)->wheel, &c->key_flip_alarm);
    timeouts_del(ped(c->w)->wheel, &c->ack_alarm);
    timeouts_del(ped(c->w)->wheel, &c->closing_alarm);
}


static void __attribute__((nonnull)) enter_closed(struct q_conn * const c)
{
    conn_to_state(c, conn_clsd);
    stop_all_alarms(c);

    if (!c->in_c_ready) {
        sl_insert_head(&c_ready, c, node_rx_ext);
        c->in_c_ready = true;
    }

    // terminate whatever API call is currently active
    maybe_api_return(c, 0);
    maybe_api_return(q_ready, 0, 0);
}


void enter_closing(struct q_conn * const c)
{
    if (c->state == conn_clsg)
        return;

    stop_all_alarms(c);

#ifndef FUZZING
    if ((c->state == conn_idle || c->state == conn_opng) && c->err_code == 0) {
#endif
        // no need to go closing->draining in these cases
        timeouts_add(ped(c->w)->wheel, &c->closing_alarm, 0);
        return;
#ifndef FUZZING
    }
#endif

#ifndef FUZZING
    // if we're going closing->draining, don't start the timer again
    if (timeout_pending(&c->closing_alarm) == false) {
        // start closing/draining alarm (3 * RTO)
        const timeout_t dur =
            3 * (c->rec.cur.srtt == 0 ? kInitialRtt : c->rec.cur.srtt) +
            4 * c->rec.cur.rttvar;
        timeouts_add(ped(c->w)->wheel, &c->closing_alarm, dur);
#ifdef DEBUG_TIMERS
        mk_cid_str(DBG, c->scid, scid_str);
        warn(DBG, "closing/draining alarm in %f sec on %s conn %s",
             dur / (double)NS_PER_S, conn_type(c), scid_str);
#endif
    }
#endif

    if (c->state != conn_drng) {
        c->needs_tx = true;
        conn_to_state(c, conn_clsg);
        timeouts_add(ped(c->w)->wheel, &c->tx_w, 0);
    }
}


static void __attribute__((nonnull)) idle_alarm(struct q_conn * const c)
{
#ifdef DEBUG_TIMERS
    mk_cid_str(DBG, c->scid, scid_str);
    warn(DBG, "idle timeout on %s conn %s", conn_type(c), scid_str);
#endif
    enter_closing(c);
}


static void __attribute__((nonnull)) ack_alarm(struct q_conn * const c)
{
#ifdef DEBUG_TIMERS
    mk_cid_str(DBG, c->scid, scid_str);
    warn(DBG, "ACK timer fired on %s conn %s", conn_type(c), scid_str);
#endif
    if (needs_ack(&c->pns[pn_data]) != no_ack)
        if (tx_ack(c, ep_data, false))
            do_tx(c);
}


void update_conf(struct q_conn * const c, const struct q_conn_conf * const conf)
{
    c->spin_enabled = get_conf_uncond(conf, enable_spinbit);

    // (re)set idle alarm
    c->tp_in.idle_to = get_conf(conf, idle_timeout) * MS_PER_S;
    restart_idle_alarm(c);

    c->tp_in.disable_migration =
#ifndef NO_MIGRATION
        get_conf_uncond(conf, disable_migration);
#else
        true;
#endif
    c->key_flips_enabled = get_conf_uncond(conf, enable_tls_key_updates);

    if (c->tp_out.disable_migration == false || c->key_flips_enabled) {
        c->tls_key_update_frequency = get_conf(conf, tls_key_update_frequency);
        restart_key_flip_alarm(c);
    }

    c->sockopt.enable_udp_zero_checksums =
        get_conf_uncond(conf, enable_udp_zero_checksums);
    w_set_sockopt(c->sock, &c->sockopt);

#if !defined(NDEBUG) || defined(NDEBUG_WITH_DLOG)
    // XXX for testing, do a key flip and a migration ASAP (if enabled)
    c->do_key_flip = c->key_flips_enabled;
#ifndef NO_MIGRATION
    c->do_migration = !c->tp_out.disable_migration;
#endif
#endif
}


struct q_conn * new_conn(struct w_engine * const w,
                         const uint32_t vers,
                         const struct cid * const dcid,
                         const struct cid * const scid,
                         const struct sockaddr * const peer,
                         const char * const peer_name,
                         const uint16_t port,
                         const struct q_conn_conf * const conf)
{
    struct q_conn * const c = calloc(1, sizeof(*c));
    ensure(c, "could not calloc");

    if (peer)
        memcpy(&c->peer, peer, sizeof(*peer));

    if (peer_name) {
        c->is_clnt = true;
        ensure(c->peer_name = strdup(peer_name), "could not dup peer_name");
    }

    // initialize socket
    c->w = w;
    const struct sockaddr_in * const addr4 =
        (const struct sockaddr_in *)(const void *)peer;
    c->sock = w_get_sock(w, w->ip, port,
                         c->is_clnt && addr4 ? addr4->sin_addr.s_addr : 0,
                         c->is_clnt && addr4 ? addr4->sin_port : 0);
    if (c->sock == 0) {
        c->sockopt.enable_ecn = true;
        c->sockopt.enable_udp_zero_checksums =
            get_conf_uncond(conf, enable_udp_zero_checksums);
        c->sock = w_bind(w, port, &c->sockopt);
        if (unlikely(c->sock == 0))
            goto fail;
        c->holds_sock = true;
    } else if (unlikely(peer == 0))
        goto fail;

    // init CIDs
    c->next_sid_bidi = c->is_clnt ? 0 : STRM_FL_SRV;
    c->next_sid_uni = c->is_clnt ? STRM_FL_UNI : STRM_FL_UNI | STRM_FL_SRV;
#ifndef NO_MIGRATION
    splay_init(&c->dcids_by_seq);
    splay_init(&c->scids_by_seq);
#endif
    const bool zero_len_scid = get_conf(conf, enable_zero_len_cid);
    new_cids(c, zero_len_scid, dcid, scid);

    c->vers = c->vers_initial = vers;
    diet_init(&c->clsd_strms);
    sq_init(&c->txq);

    // initialize idle timeout
    timeout_setcb(&c->idle_alarm, idle_alarm, c);

    // initialize closing alarm
    timeout_setcb(&c->closing_alarm, enter_closed, c);

    // initialize key flip alarm (XXX also abused for migration)
    timeout_setcb(&c->key_flip_alarm, key_flip, c);

    // initialize ACK timeout
    timeout_setcb(&c->ack_alarm, ack_alarm, c);

    // initialize recovery state
    init_rec(c);
    if (c->is_clnt)
        c->path_val_win = UINT_T_MAX;

    // start a TX watcher
    timeout_init(&c->tx_w, TIMEOUT_ABS);
    timeout_setcb(&c->tx_w, tx, c);

    if (likely(c->is_clnt || c->holds_sock == false))
        update_conf(c, conf);

    // TODO most of these should become configurable via q_conn_conf
    c->tp_in.max_pkt = w_mtu(c->w);
    c->tp_in.ack_del_exp = c->tp_out.ack_del_exp = DEF_ACK_DEL_EXP;
    c->tp_in.max_ack_del = c->tp_out.max_ack_del = DEF_MAX_ACK_DEL;
    c->tp_in.max_strm_data_uni = c->is_clnt ? INIT_STRM_DATA_UNI : 0;
    c->tp_in.max_strms_uni = c->is_clnt ? INIT_MAX_UNI_STREAMS : 0;
    c->tp_in.max_strms_bidi =
        c->is_clnt ? INIT_MAX_BIDI_STREAMS * 2 : INIT_MAX_BIDI_STREAMS;
    c->tp_in.max_strm_data_bidi_local = c->tp_in.max_strm_data_bidi_remote =
        c->is_clnt ? INIT_STRM_DATA_BIDI : INIT_STRM_DATA_BIDI / 2;
    c->tp_in.max_data =
        c->tp_in.max_strms_bidi * c->tp_in.max_strm_data_bidi_local;
    c->tp_in.act_cid_lim =
        c->tp_in.disable_migration ? 0 : (c->is_clnt ? 4 : 2);

    // initialize packet number spaces
    for (pn_t t = pn_init; t <= pn_data; t++)
        init_pn(&c->pns[t], c, t);

    // create crypto streams
    for (epoch_t e = ep_init; e <= ep_data; e++)
        if (e != ep_0rtt)
            new_stream(c, crpt_strm_id(e));

    if (c->scid) {
        // FIXME: first connection sets the type for all future connections
        qlog_init(c);
        mk_cid_str(DBG, c->scid, scid_str);
        warn(DBG, "%s conn %s on port %u created", conn_type(c), scid_str,
             bswap16(get_sport(c->sock)));
    }

    conn_to_state(c, conn_idle);
    return c;

fail:
    free(c);
    return 0;
}


void free_scid(struct q_conn * const c
#ifdef NO_MIGRATION
               __attribute__((unused))
#endif
               ,
               struct cid * const id)
{
#ifndef NO_MIGRATION
    ensure(splay_remove(cids_by_seq, &c->scids_by_seq, id), "removed");
    cids_by_id_del(&c->scids_by_id, id);
#endif
    conns_by_id_del(id);
    free(id);
}


void free_dcid(struct q_conn * const c
#ifdef NO_MIGRATION
               __attribute__((unused))
#endif
               ,
               struct cid * const id)
{
    if (id->has_srt)
        conns_by_srt_del(id->srt);
#ifndef NO_MIGRATION
    ensure(splay_remove(cids_by_seq, &c->dcids_by_seq, id), "removed");
#endif
    free(id);
}


void free_conn(struct q_conn * const c)
{
    // exit any active API call on the connection
    maybe_api_return(c, 0);

    stop_all_alarms(c);

    struct q_stream * s;
    kh_foreach_value(&c->strms_by_id, s, { free_stream(s); });
    kh_release(strms_by_id, &c->strms_by_id);

    // free crypto streams
    for (epoch_t e = ep_init; e <= ep_data; e++)
        if (c->cstrms[e])
            free_stream(c->cstrms[e]);

    free_tls(c, false);

    // free packet number spaces
    for (pn_t t = pn_init; t <= pn_data; t++)
        free_pn(&c->pns[t]);

    timeouts_del(ped(c->w)->wheel, &c->tx_w);

    diet_free(&c->clsd_strms);
    free(c->peer_name);

    // remove connection from global lists and free CIDs
    free_cids(c);
#ifndef NO_MIGRATION
    kh_release(cids_by_id, &c->scids_by_id);
#endif

    if (c->holds_sock)
        // only close the socket for the final server connection
        w_close(c->sock);

    if (c->in_c_ready)
        sl_remove(&c_ready, c, q_conn, node_rx_ext);

    if (c->needs_accept)
        sl_remove(&accept_queue, c, q_conn, node_aq);

    free(c);
}


void conn_info_populate(struct q_conn * const c)
{
    // fill some q_conn_info fields based on other conn fields
    c->i.cwnd = c->rec.cur.cwnd;
    c->i.ssthresh = c->rec.cur.ssthresh;
    c->i.rtt = c->rec.cur.srtt;
    c->i.rttvar = c->rec.cur.rttvar;
}
