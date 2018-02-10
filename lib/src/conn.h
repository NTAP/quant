// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2016-2018, NetApp, Inc.
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

#pragma once

#include <inttypes.h>
#include <math.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#include <ev.h>
#include <warpcore/warpcore.h>

#include "diet.h"
#include "recovery.h"
#include "tls.h"


extern splay_head(ipnp_splay, q_conn) conns_by_ipnp;
extern splay_head(cid_splay, q_conn) conns_by_cid;


/// A QUIC connection.
struct q_conn {
    splay_entry(q_conn) node_ipnp;
    splay_entry(q_conn) node_cid;
    sl_entry(q_conn) next;

    uint64_t id; ///< Connection ID

    uint32_t vers;         ///< QUIC version in use for this connection.
    uint32_t vers_initial; ///< QUIC version first negotiated.
    uint64_t next_sid;     ///< Next stream ID to use on q_rsv_stream().

    uint8_t is_clnt : 1;  ///< We are the client on this connection.
    uint8_t omit_cid : 1; ///< We can omit the CID during TX on this connection.
    uint8_t had_rx : 1;   ///< We had an RX event on this connection.
    uint8_t needs_tx : 1; ///< We have a pending TX on this connection.
    uint8_t use_time_loss_det : 1; ///< UsingTimeLossDetection()
    uint8_t open_win : 1;          ///< We need to open the receive window.
    uint8_t blocked : 1;           ///< We are receive-window-blocked.
    uint8_t inc_sid : 1;           ///< Make more stream IDs available to peer.

    uint8_t state; ///< State of the connection.

    uint16_t peer_max_pkt;
    uint16_t local_idle_to;
    uint16_t peer_idle_to;
    uint64_t local_max_strm_data;
    uint64_t peer_max_strm_data;
    uint64_t local_max_data;
    uint64_t peer_max_data;
    uint64_t local_max_strm_uni;
    uint64_t peer_max_strm_uni;
    uint64_t local_max_strm_bidi;
    uint64_t peer_max_strm_bidi;
    uint8_t local_ack_del_exp;
    uint8_t peer_ack_del_exp;

    uint8_t _unused[4];
    uint16_t err_code;
    const char * err_reason;

    uint64_t in_data;
    uint64_t out_data;

    ev_timer idle_alarm;
    ev_timer closing_alarm;
    ev_timer ack_alarm;

    struct diet recv;    ///< Received packet numbers still needing to be ACKed.
    ev_tstamp lg_recv_t; ///< Time when lg_recv was received

    struct sockaddr_in peer; ///< Address of our peer.
    char * peer_name;

    splay_head(stream, q_stream) streams;
    struct diet closed_streams;

    struct w_sock * sock; ///< File descriptor (socket) for the connection.
    ev_io rx_w;           ///< RX watcher.
    ev_async tx_w;        ///< TX watcher.

    struct recovery rec; ///< Loss recovery state.
    struct tls tls;      ///< TLS state.

    uint8_t stateless_reset_token[16];
};


extern int __attribute__((nonnull))
ipnp_splay_cmp(const struct q_conn * const a, const struct q_conn * const b);

extern int __attribute__((nonnull))
cid_splay_cmp(const struct q_conn * const a, const struct q_conn * const b);

SPLAY_PROTOTYPE(ipnp_splay, q_conn, node_ipnp, ipnp_splay_cmp)
SPLAY_PROTOTYPE(cid_splay, q_conn, node_cid, cid_splay_cmp)


#define CONN_STAT_IDLE 0
#define CONN_STAT_CH_SENT 1
#define CONN_STAT_VERS_REJ 2
#define CONN_STAT_RTRY 3
#define CONN_STAT_HSHK_DONE 4
#define CONN_STAT_HSHK_FAIL 5
#define CONN_STAT_ESTB 6
#define CONN_STAT_CLNG 7
#define CONN_STAT_DRNG 8
#define CONN_STAT_CLSD 9


#define conn_type(c) (c->is_clnt ? "clnt" : "serv")


#define is_force_neg_vers(vers) (((vers)&0x0f0f0f0f) == 0x0a0a0a0a)


#define is_zero(t) (fpclassify(t) == FP_ZERO)


#define is_inf(t) (fpclassify(t) == FP_INFINITE)


#define conn_to_state(c, s)                                                    \
    do {                                                                       \
        warn(DBG, "conn %" PRIx64 " state %u -> %u", c->id, c->state, s);      \
        c->state = s;                                                          \
                                                                               \
        switch (s) {                                                           \
        case CONN_STAT_IDLE:                                                   \
        case CONN_STAT_CH_SENT:                                                \
        case CONN_STAT_VERS_REJ:                                               \
        case CONN_STAT_RTRY:                                                   \
        case CONN_STAT_HSHK_DONE:                                              \
        case CONN_STAT_HSHK_FAIL:                                              \
        case CONN_STAT_CLSD:                                                   \
            break;                                                             \
        case CONN_STAT_ESTB:                                                   \
            c->needs_tx = true;                                                \
            break;                                                             \
        case CONN_STAT_DRNG:                                                   \
        case CONN_STAT_CLNG:                                                   \
            enter_closing(c);                                                  \
            break;                                                             \
        default:                                                               \
            die("unhandled state %u", s);                                      \
        }                                                                      \
    } while (0)


struct ev_loop;

extern void __attribute__((nonnull))
cid_splay(struct q_conn * const c, const struct sockaddr_in * const peer);

extern void __attribute__((nonnull))
tx_w(struct ev_loop * const l, ev_async * const w, int e);

extern void __attribute__((nonnull))
tx(struct q_conn * const c, const bool rtx, const uint32_t limit);

extern void __attribute__((nonnull))
rx(struct ev_loop * const l, ev_io * const rx_w, int e);

extern struct q_conn * __attribute__((nonnull))
get_conn_by_ipnp(const struct sockaddr_in * const peer, const bool is_clnt);

extern struct q_conn * get_conn_by_cid(const uint64_t id, const bool is_clnt);

extern void * __attribute__((nonnull)) loop_run(void * const arg);

extern void __attribute__((nonnull))
loop_update(struct ev_loop * const l, ev_async * const w, int e);

extern void __attribute__((nonnull)) err_close(struct q_conn * const c,
                                               const uint16_t code,
                                               const char * const fmt,
                                               ...);

extern void __attribute__((nonnull)) enter_closing(struct q_conn * const c);

extern void __attribute__((nonnull))
ack_alarm(struct ev_loop * const l, ev_timer * const w, int e);
