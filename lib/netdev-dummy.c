/*
 * Copyright (c) 2010, 2011, 2012, 2013, 2015, 2016, 2017 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "dummy.h"

#include <errno.h>
#include <unistd.h>

#include "dp-packet.h"
#include "dpif-netdev.h"
#include "flow.h"
#include "netdev-offload-provider.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "odp-util.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/list.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "ovs-atomic.h"
#include "packets.h"
#include "pcap-file.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/shash.h"
#include "sset.h"
#include "stream.h"
#include "unaligned.h"
#include "timeval.h"
#include "unixctl.h"
#include "reconnect.h"

VLOG_DEFINE_THIS_MODULE(netdev_dummy);

#define C_STATS_SIZE 2

struct reconnect;

struct dummy_packet_stream {
    struct stream *stream;
    struct ovs_list txq;
    struct dp_packet rxbuf;
};

enum dummy_packet_conn_type {
    NONE,       /* No connection is configured. */
    PASSIVE,    /* Listener. */
    ACTIVE      /* Connect to listener. */
};

enum dummy_netdev_conn_state {
    CONN_STATE_CONNECTED,      /* Listener connected. */
    CONN_STATE_NOT_CONNECTED,  /* Listener not connected.  */
    CONN_STATE_UNKNOWN,        /* No relavent information.  */
};

struct dummy_packet_pconn {
    struct pstream *pstream;
    struct dummy_packet_stream **streams;
    size_t n_streams;
};

struct dummy_packet_rconn {
    struct dummy_packet_stream *rstream;
    struct reconnect *reconnect;
};

struct dummy_packet_conn {
    enum dummy_packet_conn_type type;
    union {
        struct dummy_packet_pconn pconn;
        struct dummy_packet_rconn rconn;
    };
};

struct pkt_list_node {
    struct dp_packet *pkt;
    struct ovs_list list_node;
};

struct offloaded_flow {
    struct hmap_node node;
    ovs_u128 ufid;
    struct match match;
    uint32_t mark;
};

struct netdev_dummy_q_stats {
    uint64_t bytes;
    uint64_t packets;
};

/* Protects 'dummy_list'. */
static struct ovs_mutex dummy_list_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dummy_dev's. */
static struct ovs_list dummy_list OVS_GUARDED_BY(dummy_list_mutex)
    = OVS_LIST_INITIALIZER(&dummy_list);

struct netdev_dummy {
    struct netdev up;

    /* In dummy_list. */
    struct ovs_list list_node OVS_GUARDED_BY(dummy_list_mutex);

    /* Protects all members below. */
    struct ovs_mutex mutex OVS_ACQ_AFTER(dummy_list_mutex);

    struct eth_addr hwaddr OVS_GUARDED;
    int mtu OVS_GUARDED;
    struct netdev_stats stats OVS_GUARDED;
    struct netdev_custom_counter custom_stats[C_STATS_SIZE] OVS_GUARDED;
    struct netdev_dummy_q_stats *rxq_stats OVS_GUARDED;
    struct netdev_dummy_q_stats *txq_stats OVS_GUARDED;
    enum netdev_flags flags OVS_GUARDED;
    int ifindex OVS_GUARDED;
    int numa_id OVS_GUARDED;

    struct dummy_packet_conn conn OVS_GUARDED;

    struct pcap_file *tx_pcap, *rxq_pcap OVS_GUARDED;

    struct ovs_list addrs OVS_GUARDED;
    struct ovs_list rxes OVS_GUARDED; /* List of child "netdev_rxq_dummy"s. */

    struct hmap offloaded_flows OVS_GUARDED;

    /* The following properties are for dummy-pmd and they cannot be changed
     * when a device is running, so we remember the request and update them
     * next time netdev_dummy_reconfigure() is called. */
    int requested_n_txq OVS_GUARDED;
    int requested_n_rxq OVS_GUARDED;
    int requested_numa_id OVS_GUARDED;

    /* Enable netdev IP csum offload. */
    bool ol_ip_csum OVS_GUARDED;
    /* Flag RX packet with good csum. */
    bool ol_ip_csum_set_good OVS_GUARDED;
};

/* Max 'recv_queue_len' in struct netdev_dummy. */
#define NETDEV_DUMMY_MAX_QUEUE 100

struct netdev_rxq_dummy {
    struct netdev_rxq up;
    struct ovs_list node;       /* In netdev_dummy's "rxes" list. */
    struct ovs_list recv_queue;
    int recv_queue_len;         /* ovs_list_size(&recv_queue). */
    struct seq *seq;            /* Reports newly queued packets. */
};

struct netdev_addr_dummy {
    struct in6_addr address;
    struct in6_addr netmask;
    struct ovs_list node;       /* In netdev_dummy's "addrs" list. */
};

static unixctl_cb_func netdev_dummy_set_admin_state;
static int netdev_dummy_construct(struct netdev *);
static void netdev_dummy_queue_packet(struct netdev_dummy *,
                                      struct dp_packet *, struct flow *, int);

static void dummy_packet_stream_close(struct dummy_packet_stream *);

static void pkt_list_delete(struct ovs_list *);
static void addr_list_delete(struct ovs_list *);

static bool
is_dummy_class(const struct netdev_class *class)
{
    return class->construct == netdev_dummy_construct;
}

static struct netdev_dummy *
netdev_dummy_cast(const struct netdev *netdev)
{
    ovs_assert(is_dummy_class(netdev_get_class(netdev)));
    return CONTAINER_OF(netdev, struct netdev_dummy, up);
}

static struct netdev_rxq_dummy *
netdev_rxq_dummy_cast(const struct netdev_rxq *rx)
{
    ovs_assert(is_dummy_class(netdev_get_class(rx->netdev)));
    return CONTAINER_OF(rx, struct netdev_rxq_dummy, up);
}

static void
dummy_packet_stream_init(struct dummy_packet_stream *s, struct stream *stream)
{
    int rxbuf_size = stream ? 2048 : 0;
    s->stream = stream;
    dp_packet_init(&s->rxbuf, rxbuf_size);
    ovs_list_init(&s->txq);
}

static struct dummy_packet_stream *
dummy_packet_stream_create(struct stream *stream)
{
    struct dummy_packet_stream *s;

    s = xzalloc_cacheline(sizeof *s);
    dummy_packet_stream_init(s, stream);

    return s;
}

static void
dummy_packet_stream_wait(struct dummy_packet_stream *s)
{
    stream_run_wait(s->stream);
    if (!ovs_list_is_empty(&s->txq)) {
        stream_send_wait(s->stream);
    }
    stream_recv_wait(s->stream);
}

static void
dummy_packet_stream_send(struct dummy_packet_stream *s, const void *buffer, size_t size)
{
    if (ovs_list_size(&s->txq) < NETDEV_DUMMY_MAX_QUEUE) {
        struct dp_packet *b;
        struct pkt_list_node *node;

        b = dp_packet_clone_data_with_headroom(buffer, size, 2);
        put_unaligned_be16(dp_packet_push_uninit(b, 2), htons(size));

        node = xmalloc(sizeof *node);
        node->pkt = b;
        ovs_list_push_back(&s->txq, &node->list_node);
    }
}

static int
dummy_packet_stream_run(struct netdev_dummy *dev, struct dummy_packet_stream *s)
{
    int error = 0;
    size_t n = 0;

    stream_run(s->stream);

    if (!ovs_list_is_empty(&s->txq)) {
        struct pkt_list_node *txbuf_node;
        struct dp_packet *txbuf;
        int retval;

        ASSIGN_CONTAINER(txbuf_node, ovs_list_front(&s->txq), list_node);
        txbuf = txbuf_node->pkt;
        retval = stream_send(s->stream, dp_packet_data(txbuf), dp_packet_size(txbuf));

        if (retval > 0) {
            dp_packet_pull(txbuf, retval);
            if (!dp_packet_size(txbuf)) {
                ovs_list_remove(&txbuf_node->list_node);
                free(txbuf_node);
                dp_packet_delete(txbuf);
            }
        } else if (retval != -EAGAIN) {
            error = -retval;
        }
    }

    if (!error) {
        if (dp_packet_size(&s->rxbuf) < 2) {
            n = 2 - dp_packet_size(&s->rxbuf);
        } else {
            uint16_t frame_len;

            frame_len = ntohs(get_unaligned_be16(dp_packet_data(&s->rxbuf)));
            if (frame_len < ETH_HEADER_LEN) {
                error = EPROTO;
                n = 0;
            } else {
                n = (2 + frame_len) - dp_packet_size(&s->rxbuf);
            }
        }
    }
    if (!error) {
        int retval;

        dp_packet_prealloc_tailroom(&s->rxbuf, n);
        retval = stream_recv(s->stream, dp_packet_tail(&s->rxbuf), n);

        if (retval > 0) {
            dp_packet_set_size(&s->rxbuf, dp_packet_size(&s->rxbuf) + retval);
            if (retval == n && dp_packet_size(&s->rxbuf) > 2) {
                dp_packet_pull(&s->rxbuf, 2);
                netdev_dummy_queue_packet(dev,
                                          dp_packet_clone(&s->rxbuf), NULL, 0);
                dp_packet_clear(&s->rxbuf);
            }
        } else if (retval != -EAGAIN) {
            error = (retval < 0 ? -retval
                     : dp_packet_size(&s->rxbuf) ? EPROTO
                     : EOF);
        }
    }

    return error;
}

static void
dummy_packet_stream_close(struct dummy_packet_stream *s)
{
    stream_close(s->stream);
    dp_packet_uninit(&s->rxbuf);
    pkt_list_delete(&s->txq);
}

static void
dummy_packet_conn_init(struct dummy_packet_conn *conn)
{
    memset(conn, 0, sizeof *conn);
    conn->type = NONE;
}

static void
dummy_packet_conn_get_config(struct dummy_packet_conn *conn, struct smap *args)
{

    switch (conn->type) {
    case PASSIVE:
        smap_add(args, "pstream", pstream_get_name(conn->pconn.pstream));
        break;

    case ACTIVE:
        smap_add(args, "stream", stream_get_name(conn->rconn.rstream->stream));
        break;

    case NONE:
    default:
        break;
    }
}

static void
dummy_packet_conn_close(struct dummy_packet_conn *conn)
{
    int i;
    struct dummy_packet_pconn *pconn = &conn->pconn;
    struct dummy_packet_rconn *rconn = &conn->rconn;

    switch (conn->type) {
    case PASSIVE:
        pstream_close(pconn->pstream);
        for (i = 0; i < pconn->n_streams; i++) {
            dummy_packet_stream_close(pconn->streams[i]);
            free_cacheline(pconn->streams[i]);
        }
        free(pconn->streams);
        pconn->pstream = NULL;
        pconn->streams = NULL;
        break;

    case ACTIVE:
        dummy_packet_stream_close(rconn->rstream);
        free_cacheline(rconn->rstream);
        rconn->rstream = NULL;
        reconnect_destroy(rconn->reconnect);
        rconn->reconnect = NULL;
        break;

    case NONE:
    default:
        break;
    }

    conn->type = NONE;
    memset(conn, 0, sizeof *conn);
}

static void
dummy_packet_conn_set_config(struct dummy_packet_conn *conn,
                             const struct smap *args)
{
    const char *pstream = smap_get(args, "pstream");
    const char *stream = smap_get(args, "stream");

    if (pstream && stream) {
         VLOG_WARN("Open failed: both %s and %s are configured",
                   pstream, stream);
         return;
    }

    switch (conn->type) {
    case PASSIVE:
        if (pstream &&
            !strcmp(pstream_get_name(conn->pconn.pstream), pstream)) {
            return;
        }
        dummy_packet_conn_close(conn);
        break;
    case ACTIVE:
        if (stream &&
            !strcmp(stream_get_name(conn->rconn.rstream->stream), stream)) {
            return;
        }
        dummy_packet_conn_close(conn);
        break;
    case NONE:
    default:
        break;
    }

    if (pstream) {
        int error;

        error = pstream_open(pstream, &conn->pconn.pstream, DSCP_DEFAULT);
        if (error) {
            VLOG_WARN("%s: open failed (%s)", pstream, ovs_strerror(error));
        } else {
            conn->type = PASSIVE;
        }
    }

    if (stream) {
        int error;
        struct stream *active_stream;
        struct reconnect *reconnect;

        reconnect = reconnect_create(time_msec());
        reconnect_set_name(reconnect, stream);
        reconnect_set_passive(reconnect, false, time_msec());
        reconnect_enable(reconnect, time_msec());
        reconnect_set_backoff(reconnect, 100, INT_MAX);
        reconnect_set_probe_interval(reconnect, 0);
        conn->rconn.reconnect = reconnect;
        conn->type = ACTIVE;

        error = stream_open(stream, &active_stream, DSCP_DEFAULT);
        conn->rconn.rstream = dummy_packet_stream_create(active_stream);

        switch (error) {
        case 0:
            reconnect_connected(reconnect, time_msec());
            break;

        case EAGAIN:
            reconnect_connecting(reconnect, time_msec());
            break;

        default:
            reconnect_connect_failed(reconnect, time_msec(), error);
            stream_close(active_stream);
            conn->rconn.rstream->stream = NULL;
            break;
        }
    }
}

static void
dummy_pconn_run(struct netdev_dummy *dev)
    OVS_REQUIRES(dev->mutex)
{
    struct stream *new_stream;
    struct dummy_packet_pconn *pconn = &dev->conn.pconn;
    int error;
    size_t i;

    error = pstream_accept(pconn->pstream, &new_stream);
    if (!error) {
        struct dummy_packet_stream *s;

        pconn->streams = xrealloc(pconn->streams,
                                ((pconn->n_streams + 1)
                                 * sizeof s));
        s = xmalloc_cacheline(sizeof *s);
        pconn->streams[pconn->n_streams++] = s;
        dummy_packet_stream_init(s, new_stream);
    } else if (error != EAGAIN) {
        VLOG_WARN("%s: accept failed (%s)",
                  pstream_get_name(pconn->pstream), ovs_strerror(error));
        pstream_close(pconn->pstream);
        pconn->pstream = NULL;
        dev->conn.type = NONE;
    }

    for (i = 0; i < pconn->n_streams; ) {
        struct dummy_packet_stream *s = pconn->streams[i];

        error = dummy_packet_stream_run(dev, s);
        if (error) {
            VLOG_DBG("%s: closing connection (%s)",
                     stream_get_name(s->stream),
                     ovs_retval_to_string(error));
            dummy_packet_stream_close(s);
            free_cacheline(s);
            pconn->streams[i] = pconn->streams[--pconn->n_streams];
        } else {
            i++;
        }
    }
}

static void
dummy_rconn_run(struct netdev_dummy *dev)
OVS_REQUIRES(dev->mutex)
{
    struct dummy_packet_rconn *rconn = &dev->conn.rconn;

    switch (reconnect_run(rconn->reconnect, time_msec())) {
    case RECONNECT_CONNECT:
        {
            int error;

            if (rconn->rstream->stream) {
                error = stream_connect(rconn->rstream->stream);
            } else {
                error = stream_open(reconnect_get_name(rconn->reconnect),
                                    &rconn->rstream->stream, DSCP_DEFAULT);
            }

            switch (error) {
            case 0:
                reconnect_connected(rconn->reconnect, time_msec());
                break;

            case EAGAIN:
                reconnect_connecting(rconn->reconnect, time_msec());
                break;

            default:
                reconnect_connect_failed(rconn->reconnect, time_msec(), error);
                stream_close(rconn->rstream->stream);
                rconn->rstream->stream = NULL;
                break;
            }
        }
        break;

    case RECONNECT_DISCONNECT:
    case RECONNECT_PROBE:
    default:
        break;
    }

    if (reconnect_is_connected(rconn->reconnect)) {
        int err;

        err = dummy_packet_stream_run(dev, rconn->rstream);

        if (err) {
            reconnect_disconnected(rconn->reconnect, time_msec(), err);
            stream_close(rconn->rstream->stream);
            rconn->rstream->stream = NULL;
        }
    }
}

static void
dummy_packet_conn_run(struct netdev_dummy *dev)
    OVS_REQUIRES(dev->mutex)
{
    switch (dev->conn.type) {
    case PASSIVE:
        dummy_pconn_run(dev);
        break;

    case ACTIVE:
        dummy_rconn_run(dev);
        break;

    case NONE:
    default:
        break;
    }
}

static void
dummy_packet_conn_wait(struct dummy_packet_conn *conn)
{
    int i;
    switch (conn->type) {
    case PASSIVE:
        pstream_wait(conn->pconn.pstream);
        for (i = 0; i < conn->pconn.n_streams; i++) {
            struct dummy_packet_stream *s = conn->pconn.streams[i];
            dummy_packet_stream_wait(s);
        }
        break;
    case ACTIVE:
        if (reconnect_is_connected(conn->rconn.reconnect)) {
            dummy_packet_stream_wait(conn->rconn.rstream);
        }
        break;

    case NONE:
    default:
        break;
    }
}

static void
dummy_packet_conn_send(struct dummy_packet_conn *conn,
                       const void *buffer, size_t size)
{
    int i;

    switch (conn->type) {
    case PASSIVE:
        for (i = 0; i < conn->pconn.n_streams; i++) {
            struct dummy_packet_stream *s = conn->pconn.streams[i];

            dummy_packet_stream_send(s, buffer, size);
            pstream_wait(conn->pconn.pstream);
        }
        break;

    case ACTIVE:
        if (reconnect_is_connected(conn->rconn.reconnect)) {
            dummy_packet_stream_send(conn->rconn.rstream, buffer, size);
            dummy_packet_stream_wait(conn->rconn.rstream);
        }
        break;

    case NONE:
    default:
        break;
    }
}

static enum dummy_netdev_conn_state
dummy_netdev_get_conn_state(struct dummy_packet_conn *conn)
{
    enum dummy_netdev_conn_state state;

    if (conn->type == ACTIVE) {
        if (reconnect_is_connected(conn->rconn.reconnect)) {
            state = CONN_STATE_CONNECTED;
        } else {
            state = CONN_STATE_NOT_CONNECTED;
        }
    } else {
        state = CONN_STATE_UNKNOWN;
    }

    return state;
}

static void
netdev_dummy_run(const struct netdev_class *netdev_class)
{
    struct netdev_dummy *dev;

    ovs_mutex_lock(&dummy_list_mutex);
    LIST_FOR_EACH (dev, list_node, &dummy_list) {
        if (netdev_get_class(&dev->up) != netdev_class) {
            continue;
        }
        ovs_mutex_lock(&dev->mutex);
        dummy_packet_conn_run(dev);
        ovs_mutex_unlock(&dev->mutex);
    }
    ovs_mutex_unlock(&dummy_list_mutex);
}

static void
netdev_dummy_wait(const struct netdev_class *netdev_class)
{
    struct netdev_dummy *dev;

    ovs_mutex_lock(&dummy_list_mutex);
    LIST_FOR_EACH (dev, list_node, &dummy_list) {
        if (netdev_get_class(&dev->up) != netdev_class) {
            continue;
        }
        ovs_mutex_lock(&dev->mutex);
        dummy_packet_conn_wait(&dev->conn);
        ovs_mutex_unlock(&dev->mutex);
    }
    ovs_mutex_unlock(&dummy_list_mutex);
}

static struct netdev *
netdev_dummy_alloc(void)
{
    struct netdev_dummy *netdev = xzalloc(sizeof *netdev);
    return &netdev->up;
}

static int
netdev_dummy_construct(struct netdev *netdev_)
{
    static atomic_count next_n = ATOMIC_COUNT_INIT(0xaa550000);
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);
    unsigned int n;

    n = atomic_count_inc(&next_n);

    ovs_mutex_init(&netdev->mutex);
    ovs_mutex_lock(&netdev->mutex);
    netdev->hwaddr.ea[0] = 0xaa;
    netdev->hwaddr.ea[1] = 0x55;
    netdev->hwaddr.ea[2] = n >> 24;
    netdev->hwaddr.ea[3] = n >> 16;
    netdev->hwaddr.ea[4] = n >> 8;
    netdev->hwaddr.ea[5] = n;
    netdev->mtu = 1500;
    netdev->flags = NETDEV_UP;
    netdev->ifindex = -EOPNOTSUPP;
    netdev->requested_n_rxq = netdev_->n_rxq;
    netdev->requested_n_txq = netdev_->n_txq;
    netdev->numa_id = 0;

    memset(&netdev->custom_stats, 0, sizeof(netdev->custom_stats));

    ovs_strlcpy(netdev->custom_stats[0].name,
                "rx_custom_packets_1", NETDEV_CUSTOM_STATS_NAME_SIZE);
    ovs_strlcpy(netdev->custom_stats[1].name,
                "rx_custom_packets_2", NETDEV_CUSTOM_STATS_NAME_SIZE);

    netdev->rxq_stats = xcalloc(netdev->up.n_rxq, sizeof *netdev->rxq_stats);
    netdev->txq_stats = xcalloc(netdev->up.n_rxq, sizeof *netdev->txq_stats);

    dummy_packet_conn_init(&netdev->conn);

    ovs_list_init(&netdev->rxes);
    ovs_list_init(&netdev->addrs);
    hmap_init(&netdev->offloaded_flows);
    ovs_mutex_unlock(&netdev->mutex);

    ovs_mutex_lock(&dummy_list_mutex);
    ovs_list_push_back(&dummy_list, &netdev->list_node);
    ovs_mutex_unlock(&dummy_list_mutex);

    return 0;
}

static void
netdev_dummy_destruct(struct netdev *netdev_)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);
    struct offloaded_flow *off_flow;

    ovs_mutex_lock(&dummy_list_mutex);
    ovs_list_remove(&netdev->list_node);
    ovs_mutex_unlock(&dummy_list_mutex);

    ovs_mutex_lock(&netdev->mutex);
    free(netdev->rxq_stats);
    free(netdev->txq_stats);
    if (netdev->rxq_pcap) {
        ovs_pcap_close(netdev->rxq_pcap);
    }
    if (netdev->tx_pcap && netdev->tx_pcap != netdev->rxq_pcap) {
        ovs_pcap_close(netdev->tx_pcap);
    }
    dummy_packet_conn_close(&netdev->conn);
    netdev->conn.type = NONE;

    HMAP_FOR_EACH_POP (off_flow, node, &netdev->offloaded_flows) {
        free(off_flow);
    }
    hmap_destroy(&netdev->offloaded_flows);
    addr_list_delete(&netdev->addrs);

    ovs_mutex_unlock(&netdev->mutex);
    ovs_mutex_destroy(&netdev->mutex);
}

static void
netdev_dummy_dealloc(struct netdev *netdev_)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);

    free(netdev);
}

static int
netdev_dummy_get_config(const struct netdev *dev, struct smap *args)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(dev);

    ovs_mutex_lock(&netdev->mutex);

    if (netdev->ifindex >= 0) {
        smap_add_format(args, "ifindex", "%d", netdev->ifindex);
    }

    dummy_packet_conn_get_config(&netdev->conn, args);

    /* pcap, rxq_pcap and tx_pcap cannot be recovered because filenames have
     * been discarded after opening file descriptors */

    if (netdev->ol_ip_csum) {
        smap_add_format(args, "ol_ip_csum", "%s", "true");
    }

    if (netdev->ol_ip_csum_set_good) {
        smap_add_format(args, "ol_ip_csum_set_good", "%s", "true");
    }

    /* 'dummy-pmd' specific config. */
    if (!netdev_is_pmd(dev)) {
        goto exit;
    }

    smap_add_format(args, "n_rxq", "%d", netdev->requested_n_rxq);
    smap_add_format(args, "n_txq", "%d", netdev->requested_n_txq);
    smap_add_format(args, "numa_id", "%d", netdev->requested_numa_id);

exit:
    ovs_mutex_unlock(&netdev->mutex);
    return 0;
}

static int
netdev_dummy_get_addr_list(const struct netdev *netdev_, struct in6_addr **paddr,
                           struct in6_addr **pmask, int *n_addr)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);
    int cnt = 0, i = 0, err = 0;
    struct in6_addr *addr, *mask;
    struct netdev_addr_dummy *addr_dummy;

    ovs_mutex_lock(&netdev->mutex);

    cnt = ovs_list_size(&netdev->addrs);
    if (!cnt) {
        err = EADDRNOTAVAIL;
        goto out;
    }
    addr = xmalloc(sizeof *addr * cnt);
    mask = xmalloc(sizeof *mask * cnt);

    LIST_FOR_EACH (addr_dummy, node, &netdev->addrs) {
        memcpy(&addr[i], &addr_dummy->address, sizeof *addr);
        memcpy(&mask[i], &addr_dummy->netmask, sizeof *mask);
        i++;
    }

    if (paddr) {
        *paddr = addr;
        *pmask = mask;
        *n_addr = cnt;
    } else {
        free(addr);
        free(mask);
    }
out:
    ovs_mutex_unlock(&netdev->mutex);

    return err;
}

static int
netdev_dummy_add_in4(struct netdev *netdev_, struct in_addr address,
                     struct in_addr netmask)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);
    struct netdev_addr_dummy *addr_dummy = xmalloc(sizeof *addr_dummy);

    ovs_mutex_lock(&netdev->mutex);
    in6_addr_set_mapped_ipv4(&addr_dummy->address, address.s_addr);
    in6_addr_set_mapped_ipv4(&addr_dummy->netmask, netmask.s_addr);
    ovs_list_push_back(&netdev->addrs, &addr_dummy->node);
    netdev_change_seq_changed(netdev_);
    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

static int
netdev_dummy_add_in6(struct netdev *netdev_, struct in6_addr *in6,
                     struct in6_addr *mask)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);
    struct netdev_addr_dummy *addr_dummy = xmalloc(sizeof *addr_dummy);

    ovs_mutex_lock(&netdev->mutex);
    addr_dummy->address = *in6;
    addr_dummy->netmask = *mask;
    ovs_list_push_back(&netdev->addrs, &addr_dummy->node);
    netdev_change_seq_changed(netdev_);
    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

#define DUMMY_MAX_QUEUES_PER_PORT 1024

static int
netdev_dummy_set_config(struct netdev *netdev_, const struct smap *args,
                        char **errp OVS_UNUSED)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);
    const char *pcap;
    int new_n_rxq, new_n_txq, new_numa_id;

    ovs_mutex_lock(&netdev->mutex);
    netdev->ifindex = smap_get_int(args, "ifindex", -EOPNOTSUPP);

    dummy_packet_conn_set_config(&netdev->conn, args);

    if (netdev->rxq_pcap) {
        ovs_pcap_close(netdev->rxq_pcap);
    }
    if (netdev->tx_pcap && netdev->tx_pcap != netdev->rxq_pcap) {
        ovs_pcap_close(netdev->tx_pcap);
    }
    netdev->rxq_pcap = netdev->tx_pcap = NULL;
    pcap = smap_get(args, "pcap");
    if (pcap) {
        netdev->rxq_pcap = netdev->tx_pcap = ovs_pcap_open(pcap, "ab");
    } else {
        const char *rxq_pcap = smap_get(args, "rxq_pcap");
        const char *tx_pcap = smap_get(args, "tx_pcap");

        if (rxq_pcap) {
            netdev->rxq_pcap = ovs_pcap_open(rxq_pcap, "ab");
        }
        if (tx_pcap) {
            netdev->tx_pcap = ovs_pcap_open(tx_pcap, "ab");
        }
    }

    netdev->ol_ip_csum_set_good = smap_get_bool(args, "ol_ip_csum_set_good",
                                                false);
    netdev->ol_ip_csum = smap_get_bool(args, "ol_ip_csum", false);
    if (netdev->ol_ip_csum) {
        netdev_->ol_flags |= NETDEV_TX_OFFLOAD_IPV4_CKSUM;
    }

    netdev_change_seq_changed(netdev_);

    /* 'dummy-pmd' specific config. */
    if (!netdev_->netdev_class->is_pmd) {
        goto exit;
    }

    new_n_rxq = MAX(smap_get_int(args, "n_rxq", NR_QUEUE), 1);
    new_n_txq = MAX(smap_get_int(args, "n_txq", NR_QUEUE), 1);

    if (new_n_rxq > DUMMY_MAX_QUEUES_PER_PORT ||
        new_n_txq > DUMMY_MAX_QUEUES_PER_PORT) {
        VLOG_WARN("The one or both of interface %s queues"
                  "(rxq: %d, txq: %d) exceed %d. Sets it %d.\n",
                  netdev_get_name(netdev_),
                  new_n_rxq,
                  new_n_txq,
                  DUMMY_MAX_QUEUES_PER_PORT,
                  DUMMY_MAX_QUEUES_PER_PORT);

        new_n_rxq = MIN(DUMMY_MAX_QUEUES_PER_PORT, new_n_rxq);
        new_n_txq = MIN(DUMMY_MAX_QUEUES_PER_PORT, new_n_txq);
    }

    new_numa_id = smap_get_int(args, "numa_id", 0);
    if (new_n_rxq != netdev->requested_n_rxq
        || new_n_txq != netdev->requested_n_txq
        || new_numa_id != netdev->requested_numa_id) {
        netdev->requested_n_rxq = new_n_rxq;
        netdev->requested_n_txq = new_n_txq;
        netdev->requested_numa_id = new_numa_id;
        netdev_request_reconfigure(netdev_);
    }

exit:
    ovs_mutex_unlock(&netdev->mutex);
    return 0;
}

static int
netdev_dummy_get_numa_id(const struct netdev *netdev_)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);

    ovs_mutex_lock(&netdev->mutex);
    int numa_id = netdev->numa_id;
    ovs_mutex_unlock(&netdev->mutex);

    return numa_id;
}

/* Sets the number of tx queues and rx queues for the dummy PMD interface. */
static int
netdev_dummy_reconfigure(struct netdev *netdev_)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);
    int old_n_txq = netdev_->n_txq;
    int old_n_rxq = netdev_->n_rxq;

    ovs_mutex_lock(&netdev->mutex);

    netdev_->n_txq = netdev->requested_n_txq;
    netdev_->n_rxq = netdev->requested_n_rxq;
    netdev->numa_id = netdev->requested_numa_id;

    if (netdev_->n_txq != old_n_txq || netdev_->n_rxq != old_n_rxq) {
        /* Resize the per queue stats arrays. */
        netdev->txq_stats = xrealloc(netdev->txq_stats,
                                     netdev_->n_txq *
                                     sizeof *netdev->txq_stats);
        netdev->rxq_stats = xrealloc(netdev->rxq_stats,
                                     netdev_->n_rxq *
                                     sizeof *netdev->rxq_stats);

        /* Reset all stats for consistency between per-queue and global
         * counters. */
        memset(&netdev->stats, 0, sizeof netdev->stats);
        netdev->custom_stats[0].value = 0;
        netdev->custom_stats[1].value = 0;
        memset(netdev->txq_stats, 0,
               netdev_->n_txq * sizeof *netdev->txq_stats);
        memset(netdev->rxq_stats, 0,
               netdev_->n_rxq * sizeof *netdev->rxq_stats);
    }

    ovs_mutex_unlock(&netdev->mutex);
    return 0;
}

static struct netdev_rxq *
netdev_dummy_rxq_alloc(void)
{
    struct netdev_rxq_dummy *rx = xzalloc(sizeof *rx);
    return &rx->up;
}

static int
netdev_dummy_rxq_construct(struct netdev_rxq *rxq_)
{
    struct netdev_rxq_dummy *rx = netdev_rxq_dummy_cast(rxq_);
    struct netdev_dummy *netdev = netdev_dummy_cast(rx->up.netdev);

    ovs_mutex_lock(&netdev->mutex);
    ovs_list_push_back(&netdev->rxes, &rx->node);
    ovs_list_init(&rx->recv_queue);
    rx->recv_queue_len = 0;
    rx->seq = seq_create();
    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

static void
netdev_dummy_rxq_destruct(struct netdev_rxq *rxq_)
{
    struct netdev_rxq_dummy *rx = netdev_rxq_dummy_cast(rxq_);
    struct netdev_dummy *netdev = netdev_dummy_cast(rx->up.netdev);

    ovs_mutex_lock(&netdev->mutex);
    ovs_list_remove(&rx->node);
    pkt_list_delete(&rx->recv_queue);
    ovs_mutex_unlock(&netdev->mutex);
    seq_destroy(rx->seq);
}

static void
netdev_dummy_rxq_dealloc(struct netdev_rxq *rxq_)
{
    struct netdev_rxq_dummy *rx = netdev_rxq_dummy_cast(rxq_);

    free(rx);
}

static int
netdev_dummy_rxq_recv(struct netdev_rxq *rxq_, struct dp_packet_batch *batch,
                      int *qfill)
{
    struct netdev_rxq_dummy *rx = netdev_rxq_dummy_cast(rxq_);
    struct netdev_dummy *netdev = netdev_dummy_cast(rx->up.netdev);
    struct dp_packet *packet;

    ovs_mutex_lock(&netdev->mutex);
    if (!ovs_list_is_empty(&rx->recv_queue)) {
        struct pkt_list_node *pkt_node;

        ASSIGN_CONTAINER(pkt_node, ovs_list_pop_front(&rx->recv_queue), list_node);
        packet = pkt_node->pkt;
        free(pkt_node);
        rx->recv_queue_len--;
    } else {
        packet = NULL;
    }
    ovs_mutex_unlock(&netdev->mutex);

    if (!packet) {
        if (netdev_is_pmd(&netdev->up)) {
            /* If 'netdev' is a PMD device, this is called as part of the PMD
             * thread busy loop.  We yield here (without quiescing) for two
             * reasons:
             *
             * - To reduce the CPU utilization during the testsuite
             * - To give valgrind a chance to switch thread. According
             *   to the valgrind documentation, there's a big lock that
             *   prevents multiple thread from being executed at the same
             *   time.  On my system, without this sleep, the pmd threads
             *   testcases fail under valgrind, because ovs-vswitchd becomes
             *   unresponsive. */
            sched_yield();
        }
        return EAGAIN;
    }
    ovs_mutex_lock(&netdev->mutex);
    netdev->stats.rx_packets++;
    netdev->rxq_stats[rxq_->queue_id].packets++;
    netdev->stats.rx_bytes += dp_packet_size(packet);
    netdev->rxq_stats[rxq_->queue_id].bytes += dp_packet_size(packet);
    netdev->custom_stats[0].value++;
    netdev->custom_stats[1].value++;
    if (netdev->ol_ip_csum_set_good) {
        /* The netdev hardware sets the flag when the packet has good csum. */
        dp_packet_ol_set_ip_csum_good(packet);
    }
    ovs_mutex_unlock(&netdev->mutex);

    dp_packet_batch_init_packet(batch, packet);

    if (qfill) {
        *qfill = -ENOTSUP;
    }

    return 0;
}

static void
netdev_dummy_rxq_wait(struct netdev_rxq *rxq_)
{
    struct netdev_rxq_dummy *rx = netdev_rxq_dummy_cast(rxq_);
    struct netdev_dummy *netdev = netdev_dummy_cast(rx->up.netdev);
    uint64_t seq = seq_read(rx->seq);

    ovs_mutex_lock(&netdev->mutex);
    if (!ovs_list_is_empty(&rx->recv_queue)) {
        poll_immediate_wake();
    } else {
        seq_wait(rx->seq, seq);
    }
    ovs_mutex_unlock(&netdev->mutex);
}

static int
netdev_dummy_rxq_drain(struct netdev_rxq *rxq_)
{
    struct netdev_rxq_dummy *rx = netdev_rxq_dummy_cast(rxq_);
    struct netdev_dummy *netdev = netdev_dummy_cast(rx->up.netdev);

    ovs_mutex_lock(&netdev->mutex);
    pkt_list_delete(&rx->recv_queue);
    rx->recv_queue_len = 0;
    ovs_mutex_unlock(&netdev->mutex);

    seq_change(rx->seq);

    return 0;
}

static int
netdev_dummy_send(struct netdev *netdev, int qid,
                  struct dp_packet_batch *batch,
                  bool concurrent_txq OVS_UNUSED)
{
    struct netdev_dummy *dev = netdev_dummy_cast(netdev);
    int error = 0;

    struct dp_packet *packet;
    DP_PACKET_BATCH_FOR_EACH(i, packet, batch) {
        const void *buffer = dp_packet_data(packet);
        size_t size = dp_packet_size(packet);

        if (!dp_packet_is_eth(packet)) {
            error = EPFNOSUPPORT;
            break;
        }

        if (size < ETH_HEADER_LEN) {
            error = EMSGSIZE;
            break;
        } else {
            const struct eth_header *eth = buffer;
            int max_size;

            ovs_mutex_lock(&dev->mutex);
            max_size = dev->mtu + ETH_HEADER_LEN;
            ovs_mutex_unlock(&dev->mutex);

            if (eth->eth_type == htons(ETH_TYPE_VLAN)) {
                max_size += VLAN_HEADER_LEN;
            }
            if (size > max_size) {
                error = EMSGSIZE;
                break;
            }
        }

        if (dp_packet_hwol_tx_ip_csum(packet) &&
            !dp_packet_ip_checksum_good(packet)) {
            dp_packet_ip_set_header_csum(packet);
            dp_packet_ol_set_ip_csum_good(packet);
        }

        ovs_mutex_lock(&dev->mutex);
        dev->stats.tx_packets++;
        dev->txq_stats[qid].packets++;
        dev->stats.tx_bytes += size;
        dev->txq_stats[qid].bytes += size;

        dummy_packet_conn_send(&dev->conn, buffer, size);

        /* Reply to ARP requests for 'dev''s assigned IP address. */
        struct netdev_addr_dummy *addr_dummy;
        LIST_FOR_EACH (addr_dummy, node, &dev->addrs) {
            ovs_be32 address = in6_addr_get_mapped_ipv4(&addr_dummy->address);

            struct dp_packet dp;
            struct flow flow;

            dp_packet_use_const(&dp, buffer, size);
            flow_extract(&dp, &flow);
            if (flow.dl_type == htons(ETH_TYPE_ARP)
                && flow.nw_proto == ARP_OP_REQUEST
                && flow.nw_dst == address) {
                struct dp_packet *reply = dp_packet_new(0);
                compose_arp(reply, ARP_OP_REPLY, dev->hwaddr, flow.dl_src,
                            false, flow.nw_dst, flow.nw_src);
                netdev_dummy_queue_packet(dev, reply, NULL, 0);
                break;
            }
        }

        if (dev->tx_pcap) {
            struct dp_packet dp;

            dp_packet_use_const(&dp, buffer, size);
            ovs_pcap_write(dev->tx_pcap, &dp);
        }

        ovs_mutex_unlock(&dev->mutex);
    }

    dp_packet_delete_batch(batch, true);

    return error;
}

static int
netdev_dummy_set_etheraddr(struct netdev *netdev, const struct eth_addr mac)
{
    struct netdev_dummy *dev = netdev_dummy_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    if (!eth_addr_equals(dev->hwaddr, mac)) {
        dev->hwaddr = mac;
        netdev_change_seq_changed(netdev);
    }
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dummy_get_etheraddr(const struct netdev *netdev, struct eth_addr *mac)
{
    struct netdev_dummy *dev = netdev_dummy_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    *mac = dev->hwaddr;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dummy_get_mtu(const struct netdev *netdev, int *mtup)
{
    struct netdev_dummy *dev = netdev_dummy_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    *mtup = dev->mtu;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

#define DUMMY_MIN_MTU 68
#define DUMMY_MAX_MTU 65535

static int
netdev_dummy_set_mtu(struct netdev *netdev, int mtu)
{
    if (mtu < DUMMY_MIN_MTU || mtu > DUMMY_MAX_MTU) {
        return EINVAL;
    }

    struct netdev_dummy *dev = netdev_dummy_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    if (dev->mtu != mtu) {
        dev->mtu = mtu;
        netdev_change_seq_changed(netdev);
    }
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dummy_get_stats(const struct netdev *netdev, struct netdev_stats *stats)
{
    struct netdev_dummy *dev = netdev_dummy_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    /* Passing only collected counters */
    stats->tx_packets = dev->stats.tx_packets;
    stats->tx_bytes = dev->stats.tx_bytes;
    stats->rx_packets = dev->stats.rx_packets;
    stats->rx_bytes = dev->stats.rx_bytes;
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dummy_get_custom_stats(const struct netdev *netdev,
                             struct netdev_custom_stats *custom_stats)
{
    int i, j;

    struct netdev_dummy *dev = netdev_dummy_cast(netdev);

    ovs_mutex_lock(&dev->mutex);

#define DUMMY_Q_STATS      \
    DUMMY_Q_STAT(bytes)    \
    DUMMY_Q_STAT(packets)

    custom_stats->size = C_STATS_SIZE;
#define DUMMY_Q_STAT(NAME) + netdev->n_rxq
    custom_stats->size += DUMMY_Q_STATS;
#undef DUMMY_Q_STAT
#define DUMMY_Q_STAT(NAME) + netdev->n_txq
    custom_stats->size += DUMMY_Q_STATS;
#undef DUMMY_Q_STAT

    custom_stats->counters = xcalloc(custom_stats->size,
                                     sizeof(struct netdev_custom_counter));

    j = 0;
    for (i = 0 ; i < C_STATS_SIZE ; i++) {
        custom_stats->counters[j].value = dev->custom_stats[i].value;
        ovs_strlcpy(custom_stats->counters[j++].name,
                    dev->custom_stats[i].name,
                    NETDEV_CUSTOM_STATS_NAME_SIZE);
    }

    for (i = 0; i < netdev->n_rxq; i++) {
#define DUMMY_Q_STAT(NAME) \
        snprintf(custom_stats->counters[j].name, \
                 NETDEV_CUSTOM_STATS_NAME_SIZE, "rx_q%d_"#NAME, i); \
        custom_stats->counters[j++].value = dev->rxq_stats[i].NAME;
        DUMMY_Q_STATS
#undef DUMMY_Q_STAT
    }

    for (i = 0; i < netdev->n_txq; i++) {
#define DUMMY_Q_STAT(NAME) \
        snprintf(custom_stats->counters[j].name, \
                 NETDEV_CUSTOM_STATS_NAME_SIZE, "tx_q%d_"#NAME, i); \
        custom_stats->counters[j++].value = dev->txq_stats[i].NAME;
        DUMMY_Q_STATS
#undef DUMMY_Q_STAT
    }

    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_dummy_get_queue(const struct netdev *netdev OVS_UNUSED,
                       unsigned int queue_id, struct smap *details OVS_UNUSED)
{
    if (queue_id == 0) {
        return 0;
    } else {
        return EINVAL;
    }
}

static void
netdev_dummy_init_queue_stats(struct netdev_queue_stats *stats)
{
    *stats = (struct netdev_queue_stats) {
        .tx_bytes = UINT64_MAX,
        .tx_packets = UINT64_MAX,
        .tx_errors = UINT64_MAX,
        .created = LLONG_MIN,
    };
}

static int
netdev_dummy_get_queue_stats(const struct netdev *netdev OVS_UNUSED,
                             unsigned int queue_id,
                             struct netdev_queue_stats *stats)
{
    if (queue_id == 0) {
        netdev_dummy_init_queue_stats(stats);
        return 0;
    } else {
        return EINVAL;
    }
}

struct netdev_dummy_queue_state {
    unsigned int next_queue;
};

static int
netdev_dummy_queue_dump_start(const struct netdev *netdev OVS_UNUSED,
                              void **statep)
{
    struct netdev_dummy_queue_state *state = xmalloc(sizeof *state);
    state->next_queue = 0;
    *statep = state;
    return 0;
}

static int
netdev_dummy_queue_dump_next(const struct netdev *netdev OVS_UNUSED,
                             void *state_,
                             unsigned int *queue_id,
                             struct smap *details OVS_UNUSED)
{
    struct netdev_dummy_queue_state *state = state_;
    if (state->next_queue == 0) {
        *queue_id = 0;
        state->next_queue++;
        return 0;
    } else {
        return EOF;
    }
}

static int
netdev_dummy_queue_dump_done(const struct netdev *netdev OVS_UNUSED,
                             void *state)
{
    free(state);
    return 0;
}

static int
netdev_dummy_dump_queue_stats(const struct netdev *netdev OVS_UNUSED,
                              void (*cb)(unsigned int queue_id,
                                         struct netdev_queue_stats *,
                                         void *aux),
                              void *aux)
{
    struct netdev_queue_stats stats;
    netdev_dummy_init_queue_stats(&stats);
    cb(0, &stats, aux);
    return 0;
}

static int
netdev_dummy_get_ifindex(const struct netdev *netdev)
{
    struct netdev_dummy *dev = netdev_dummy_cast(netdev);
    int ifindex;

    ovs_mutex_lock(&dev->mutex);
    ifindex = dev->ifindex;
    ovs_mutex_unlock(&dev->mutex);

    return ifindex;
}

static int
netdev_dummy_update_flags__(struct netdev_dummy *netdev,
                            enum netdev_flags off, enum netdev_flags on,
                            enum netdev_flags *old_flagsp)
    OVS_REQUIRES(netdev->mutex)
{
    if ((off | on) & ~(NETDEV_UP | NETDEV_PROMISC)) {
        return EINVAL;
    }

    *old_flagsp = netdev->flags;
    netdev->flags |= on;
    netdev->flags &= ~off;
    if (*old_flagsp != netdev->flags) {
        netdev_change_seq_changed(&netdev->up);
    }

    return 0;
}

static int
netdev_dummy_update_flags(struct netdev *netdev_,
                          enum netdev_flags off, enum netdev_flags on,
                          enum netdev_flags *old_flagsp)
{
    struct netdev_dummy *netdev = netdev_dummy_cast(netdev_);
    int error;

    ovs_mutex_lock(&netdev->mutex);
    error = netdev_dummy_update_flags__(netdev, off, on, old_flagsp);
    ovs_mutex_unlock(&netdev->mutex);

    return error;
}

/* Flow offload API. */
static uint32_t
netdev_dummy_flow_hash(const ovs_u128 *ufid)
{
    return ufid->u32[0];
}

static struct offloaded_flow *
find_offloaded_flow(const struct hmap *offloaded_flows, const ovs_u128 *ufid)
{
    uint32_t hash = netdev_dummy_flow_hash(ufid);
    struct offloaded_flow *data;

    HMAP_FOR_EACH_WITH_HASH (data, node, hash, offloaded_flows) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            return data;
        }
    }

    return NULL;
}

static int
netdev_dummy_flow_put(struct netdev *netdev, struct match *match,
                      struct nlattr *actions OVS_UNUSED,
                      size_t actions_len OVS_UNUSED,
                      const ovs_u128 *ufid, struct offload_info *info,
                      struct dpif_flow_stats *stats)
{
    struct netdev_dummy *dev = netdev_dummy_cast(netdev);
    struct offloaded_flow *off_flow;
    bool modify = true;

    ovs_mutex_lock(&dev->mutex);

    off_flow = find_offloaded_flow(&dev->offloaded_flows, ufid);
    if (!off_flow) {
        /* Create new offloaded flow. */
        off_flow = xzalloc(sizeof *off_flow);
        memcpy(&off_flow->ufid, ufid, sizeof *ufid);
        hmap_insert(&dev->offloaded_flows, &off_flow->node,
                    netdev_dummy_flow_hash(ufid));
        modify = false;
    }

    off_flow->mark = info->flow_mark;
    memcpy(&off_flow->match, match, sizeof *match);

    /* As we have per-netdev 'offloaded_flows', we don't need to match
     * the 'in_port' for received packets. This will also allow offloading for
     * packets passed to 'receive' command without specifying the 'in_port'. */
    off_flow->match.wc.masks.in_port.odp_port = 0;

    ovs_mutex_unlock(&dev->mutex);

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        ds_put_format(&ds, "%s: flow put[%s]: ", netdev_get_name(netdev),
                      modify ? "modify" : "create");
        odp_format_ufid(ufid, &ds);
        ds_put_cstr(&ds, " flow match: ");
        match_format(match, NULL, &ds, OFP_DEFAULT_PRIORITY);
        ds_put_format(&ds, ", mark: %"PRIu32, info->flow_mark);

        VLOG_DBG("%s", ds_cstr(&ds));
        ds_destroy(&ds);
    }

    if (stats) {
        memset(stats, 0, sizeof *stats);
    }
    return 0;
}

static int
netdev_dummy_flow_del(struct netdev *netdev, const ovs_u128 *ufid,
                      struct dpif_flow_stats *stats)
{
    struct netdev_dummy *dev = netdev_dummy_cast(netdev);
    struct offloaded_flow *off_flow;
    const char *error = NULL;
    uint32_t mark;

    ovs_mutex_lock(&dev->mutex);

    off_flow = find_offloaded_flow(&dev->offloaded_flows, ufid);
    if (!off_flow) {
        error = "No such flow.";
        goto exit;
    }

    mark = off_flow->mark;
    hmap_remove(&dev->offloaded_flows, &off_flow->node);
    free(off_flow);

exit:
    ovs_mutex_unlock(&dev->mutex);

    if (error || VLOG_IS_DBG_ENABLED()) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        ds_put_format(&ds, "%s: ", netdev_get_name(netdev));
        if (error) {
            ds_put_cstr(&ds, "failed to ");
        }
        ds_put_cstr(&ds, "flow del: ");
        odp_format_ufid(ufid, &ds);
        if (error) {
            ds_put_format(&ds, " error: %s", error);
        } else {
            ds_put_format(&ds, " mark: %"PRIu32, mark);
        }
        VLOG(error ? VLL_WARN : VLL_DBG, "%s", ds_cstr(&ds));
        ds_destroy(&ds);
    }

    if (stats) {
        memset(stats, 0, sizeof *stats);
    }
    return error ? -1 : 0;
}

#define NETDEV_DUMMY_CLASS_COMMON                       \
    .run = netdev_dummy_run,                            \
    .wait = netdev_dummy_wait,                          \
    .alloc = netdev_dummy_alloc,                        \
    .construct = netdev_dummy_construct,                \
    .destruct = netdev_dummy_destruct,                  \
    .dealloc = netdev_dummy_dealloc,                    \
    .get_config = netdev_dummy_get_config,              \
    .set_config = netdev_dummy_set_config,              \
    .get_numa_id = netdev_dummy_get_numa_id,            \
    .send = netdev_dummy_send,                          \
    .set_etheraddr = netdev_dummy_set_etheraddr,        \
    .get_etheraddr = netdev_dummy_get_etheraddr,        \
    .get_mtu = netdev_dummy_get_mtu,                    \
    .set_mtu = netdev_dummy_set_mtu,                    \
    .get_ifindex = netdev_dummy_get_ifindex,            \
    .get_stats = netdev_dummy_get_stats,                \
    .get_custom_stats = netdev_dummy_get_custom_stats,  \
    .get_queue = netdev_dummy_get_queue,                \
    .get_queue_stats = netdev_dummy_get_queue_stats,    \
    .queue_dump_start = netdev_dummy_queue_dump_start,  \
    .queue_dump_next = netdev_dummy_queue_dump_next,    \
    .queue_dump_done = netdev_dummy_queue_dump_done,    \
    .dump_queue_stats = netdev_dummy_dump_queue_stats,  \
    .get_addr_list = netdev_dummy_get_addr_list,        \
    .update_flags = netdev_dummy_update_flags,          \
    .rxq_alloc = netdev_dummy_rxq_alloc,                \
    .rxq_construct = netdev_dummy_rxq_construct,        \
    .rxq_destruct = netdev_dummy_rxq_destruct,          \
    .rxq_dealloc = netdev_dummy_rxq_dealloc,            \
    .rxq_recv = netdev_dummy_rxq_recv,                  \
    .rxq_wait = netdev_dummy_rxq_wait,                  \
    .rxq_drain = netdev_dummy_rxq_drain

static const struct netdev_class dummy_class = {
    NETDEV_DUMMY_CLASS_COMMON,
    .type = "dummy"
};

static const struct netdev_class dummy_internal_class = {
    NETDEV_DUMMY_CLASS_COMMON,
    .type = "dummy-internal"
};

static const struct netdev_class dummy_pmd_class = {
    NETDEV_DUMMY_CLASS_COMMON,
    .type = "dummy-pmd",
    .is_pmd = true,
    .reconfigure = netdev_dummy_reconfigure
};

static int
netdev_dummy_offloads_init_flow_api(struct netdev *netdev)
{
    return is_dummy_class(netdev->netdev_class) ? 0 : EOPNOTSUPP;
}

static const struct netdev_flow_api netdev_offload_dummy = {
    .type = "dummy",
    .flow_put = netdev_dummy_flow_put,
    .flow_del = netdev_dummy_flow_del,
    .init_flow_api = netdev_dummy_offloads_init_flow_api,
};


/* Helper functions. */

static void
pkt_list_delete(struct ovs_list *l)
{
    struct pkt_list_node *pkt;

    LIST_FOR_EACH_POP(pkt, list_node, l) {
        dp_packet_delete(pkt->pkt);
        free(pkt);
    }
}

static void
addr_list_delete(struct ovs_list *l)
{
    struct netdev_addr_dummy *addr_dummy;

    LIST_FOR_EACH_POP (addr_dummy, node, l) {
        free(addr_dummy);
    }
}

static struct dp_packet *
eth_from_packet(const char *s)
{
    struct dp_packet *packet;
    eth_from_hex(s, &packet);
    return packet;
}

static struct dp_packet *
eth_from_flow_str(const char *s, size_t packet_size,
                  struct flow *flow, char **errorp)
{
    *errorp = NULL;

    enum odp_key_fitness fitness;
    struct dp_packet *packet;
    struct ofpbuf odp_key;
    int error;

    /* Convert string to datapath key.
     *
     * It would actually be nicer to parse an OpenFlow-like flow key here, but
     * the code for that currently calls exit() on parse error.  We have to
     * settle for parsing a datapath key for now.
     */
    ofpbuf_init(&odp_key, 0);
    error = odp_flow_from_string(s, NULL, &odp_key, NULL, errorp);
    if (error) {
        ofpbuf_uninit(&odp_key);
        return NULL;
    }

    /* Convert odp_key to flow. */
    fitness = odp_flow_key_to_flow(odp_key.data, odp_key.size, flow, errorp);
    if (fitness == ODP_FIT_ERROR) {
        ofpbuf_uninit(&odp_key);
        return NULL;
    }

    packet = dp_packet_new(0);
    if (packet_size) {
        flow_compose(packet, flow, NULL, 0, false);
        if (dp_packet_size(packet) < packet_size) {
            packet_expand(packet, flow, packet_size);
        } else if (dp_packet_size(packet) > packet_size){
            dp_packet_delete(packet);
            packet = NULL;
        }
    } else {
        flow_compose(packet, flow, NULL, 64, false);
    }

    ofpbuf_uninit(&odp_key);
    return packet;
}

static void
netdev_dummy_queue_packet__(struct netdev_rxq_dummy *rx, struct dp_packet *packet)
{
    struct pkt_list_node *pkt_node = xmalloc(sizeof *pkt_node);

    pkt_node->pkt = packet;
    ovs_list_push_back(&rx->recv_queue, &pkt_node->list_node);
    rx->recv_queue_len++;
    seq_change(rx->seq);
}

static void
netdev_dummy_queue_packet(struct netdev_dummy *dummy, struct dp_packet *packet,
                          struct flow *flow, int queue_id)
    OVS_REQUIRES(dummy->mutex)
{
    struct netdev_rxq_dummy *rx, *prev;
    struct offloaded_flow *data;
    struct flow packet_flow;

    if (dummy->rxq_pcap) {
        ovs_pcap_write(dummy->rxq_pcap, packet);
    }

    if (!flow) {
        flow = &packet_flow;
        flow_extract(packet, flow);
    }
    HMAP_FOR_EACH (data, node, &dummy->offloaded_flows) {
        if (flow_equal_except(flow, &data->match.flow, &data->match.wc)) {

            dp_packet_set_flow_mark(packet, data->mark);

            if (VLOG_IS_DBG_ENABLED()) {
                struct ds ds = DS_EMPTY_INITIALIZER;

                ds_put_format(&ds, "%s: packet: ",
                              netdev_get_name(&dummy->up));
                /* 'flow' does not contain proper port number here.
                 * Let's just clear it as it wildcarded anyway. */
                flow->in_port.ofp_port = 0;
                flow_format(&ds, flow, NULL);

                ds_put_cstr(&ds, " matches with flow: ");
                odp_format_ufid(&data->ufid, &ds);
                ds_put_cstr(&ds, " ");
                match_format(&data->match, NULL, &ds, OFP_DEFAULT_PRIORITY);
                ds_put_format(&ds, " with mark: %"PRIu32, data->mark);

                VLOG_DBG("%s", ds_cstr(&ds));
                ds_destroy(&ds);
            }
            break;
        }
    }

    prev = NULL;
    LIST_FOR_EACH (rx, node, &dummy->rxes) {
        if (rx->up.queue_id == queue_id &&
            rx->recv_queue_len < NETDEV_DUMMY_MAX_QUEUE) {
            if (prev) {
                netdev_dummy_queue_packet__(prev, dp_packet_clone(packet));
            }
            prev = rx;
        }
    }
    if (prev) {
        netdev_dummy_queue_packet__(prev, packet);
    } else {
        dp_packet_delete(packet);
    }
}

static void
netdev_dummy_receive(struct unixctl_conn *conn,
                     int argc, const char *argv[],
                     enum ovs_output_fmt fmt OVS_UNUSED, void *aux OVS_UNUSED)
{
    struct netdev_dummy *dummy_dev;
    struct netdev *netdev;
    int i, k = 1, rx_qid = 0;

    netdev = netdev_from_name(argv[k++]);
    if (!netdev || !is_dummy_class(netdev->netdev_class)) {
        unixctl_command_reply_error(conn, "no such dummy netdev");
        goto exit_netdev;
    }
    dummy_dev = netdev_dummy_cast(netdev);

    ovs_mutex_lock(&dummy_dev->mutex);

    if (argc > k + 1 && !strcmp(argv[k], "--qid")) {
        rx_qid = strtol(argv[k + 1], NULL, 10);
        if (rx_qid < 0 || rx_qid >= netdev->n_rxq) {
            unixctl_command_reply_error(conn, "bad rx queue id.");
            goto exit;
        }
        k += 2;
    }

    for (i = k; i < argc; i++) {
        struct dp_packet *packet;
        struct flow flow;

        /* Try to parse 'argv[i]' as packet in hex. */
        packet = eth_from_packet(argv[i]);

        if (!packet) {
            int packet_size = 0;
            const char *flow_str = argv[i];

            /* Parse optional --len argument immediately follows a 'flow'.  */
            if (argc >= i + 2 && !strcmp(argv[i + 1], "--len")) {
                packet_size = strtol(argv[i + 2], NULL, 10);

                if (packet_size < ETH_TOTAL_MIN) {
                    unixctl_command_reply_error(conn, "too small packet len");
                    goto exit;
                }
                i += 2;
            }
            /* Try parse 'argv[i]' as odp flow. */
            char *error_s;
            packet = eth_from_flow_str(flow_str, packet_size, &flow, &error_s);
            if (!packet) {
                unixctl_command_reply_error(conn, error_s);
                free(error_s);
                goto exit;
            }
        } else {
            flow_extract(packet, &flow);
        }

        netdev_dummy_queue_packet(dummy_dev, packet, &flow, rx_qid);
    }

    unixctl_command_reply(conn, NULL);

exit:
    ovs_mutex_unlock(&dummy_dev->mutex);
exit_netdev:
    netdev_close(netdev);
}

static void
netdev_dummy_set_admin_state__(struct netdev_dummy *dev, bool admin_state)
    OVS_REQUIRES(dev->mutex)
{
    enum netdev_flags old_flags;

    if (admin_state) {
        netdev_dummy_update_flags__(dev, 0, NETDEV_UP, &old_flags);
    } else {
        netdev_dummy_update_flags__(dev, NETDEV_UP, 0, &old_flags);
    }
}

static void
netdev_dummy_set_admin_state(struct unixctl_conn *conn, int argc,
                             const char *argv[],
                             enum ovs_output_fmt fmt OVS_UNUSED,
                             void *aux OVS_UNUSED)
{
    bool up;

    if (!strcasecmp(argv[argc - 1], "up")) {
        up = true;
    } else if ( !strcasecmp(argv[argc - 1], "down")) {
        up = false;
    } else {
        unixctl_command_reply_error(conn, "Invalid Admin State");
        return;
    }

    if (argc > 2) {
        struct netdev *netdev = netdev_from_name(argv[1]);
        if (netdev && is_dummy_class(netdev->netdev_class)) {
            struct netdev_dummy *dummy_dev = netdev_dummy_cast(netdev);

            ovs_mutex_lock(&dummy_dev->mutex);
            netdev_dummy_set_admin_state__(dummy_dev, up);
            ovs_mutex_unlock(&dummy_dev->mutex);

            netdev_close(netdev);
        } else {
            unixctl_command_reply_error(conn, "Unknown Dummy Interface");
            netdev_close(netdev);
            return;
        }
    } else {
        struct netdev_dummy *netdev;

        ovs_mutex_lock(&dummy_list_mutex);
        LIST_FOR_EACH (netdev, list_node, &dummy_list) {
            ovs_mutex_lock(&netdev->mutex);
            netdev_dummy_set_admin_state__(netdev, up);
            ovs_mutex_unlock(&netdev->mutex);
        }
        ovs_mutex_unlock(&dummy_list_mutex);
    }
    unixctl_command_reply(conn, "OK");
}

static void
display_conn_state__(struct ds *s, const char *name,
                     enum dummy_netdev_conn_state state)
{
    ds_put_format(s, "%s: ", name);

    switch (state) {
    case CONN_STATE_CONNECTED:
        ds_put_cstr(s, "connected\n");
        break;

    case CONN_STATE_NOT_CONNECTED:
        ds_put_cstr(s, "disconnected\n");
        break;

    case CONN_STATE_UNKNOWN:
    default:
        ds_put_cstr(s, "unknown\n");
        break;
    };
}

static void
netdev_dummy_conn_state(struct unixctl_conn *conn, int argc,
                        const char *argv[],
                        enum ovs_output_fmt fmt OVS_UNUSED,
                        void *aux OVS_UNUSED)
{
    enum dummy_netdev_conn_state state = CONN_STATE_UNKNOWN;
    struct ds s;

    ds_init(&s);

    if (argc > 1) {
        const char *dev_name = argv[1];
        struct netdev *netdev = netdev_from_name(dev_name);

        if (netdev && is_dummy_class(netdev->netdev_class)) {
            struct netdev_dummy *dummy_dev = netdev_dummy_cast(netdev);

            ovs_mutex_lock(&dummy_dev->mutex);
            state = dummy_netdev_get_conn_state(&dummy_dev->conn);
            ovs_mutex_unlock(&dummy_dev->mutex);

            netdev_close(netdev);
        }
        display_conn_state__(&s, dev_name, state);
    } else {
        struct netdev_dummy *netdev;

        ovs_mutex_lock(&dummy_list_mutex);
        LIST_FOR_EACH (netdev, list_node, &dummy_list) {
            ovs_mutex_lock(&netdev->mutex);
            state = dummy_netdev_get_conn_state(&netdev->conn);
            ovs_mutex_unlock(&netdev->mutex);
            if (state != CONN_STATE_UNKNOWN) {
                display_conn_state__(&s, netdev->up.name, state);
            }
        }
        ovs_mutex_unlock(&dummy_list_mutex);
    }

    unixctl_command_reply(conn, ds_cstr(&s));
    ds_destroy(&s);
}

static void
netdev_dummy_ip4addr(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[],
                     enum ovs_output_fmt fmt OVS_UNUSED,
                     void *aux OVS_UNUSED)
{
    struct netdev *netdev = netdev_from_name(argv[1]);

    if (netdev && is_dummy_class(netdev->netdev_class)) {
        struct in_addr ip, mask;
        char *error;

        error = ip_parse_masked(argv[2], &ip.s_addr, &mask.s_addr);
        if (!error) {
            netdev_dummy_add_in4(netdev, ip, mask);
            unixctl_command_reply(conn, "OK");
        } else {
            unixctl_command_reply_error(conn, error);
            free(error);
        }
    } else {
        unixctl_command_reply_error(conn, "Unknown Dummy Interface");
    }

    netdev_close(netdev);
}

static void
netdev_dummy_ip6addr(struct unixctl_conn *conn, int argc OVS_UNUSED,
                     const char *argv[], enum ovs_output_fmt fmt OVS_UNUSED,
                     void *aux OVS_UNUSED)
{
    struct netdev *netdev = netdev_from_name(argv[1]);

    if (netdev && is_dummy_class(netdev->netdev_class)) {
        struct in6_addr ip6;
        char *error;
        uint32_t plen;

        error = ipv6_parse_cidr(argv[2], &ip6, &plen);
        if (!error) {
            struct in6_addr mask;

            mask = ipv6_create_mask(plen);
            netdev_dummy_add_in6(netdev, &ip6, &mask);
            unixctl_command_reply(conn, "OK");
        } else {
            unixctl_command_reply_error(conn, error);
            free(error);
        }
    } else {
        unixctl_command_reply_error(conn, "Unknown Dummy Interface");
    }

    netdev_close(netdev);
}


static void
netdev_dummy_override(const char *type)
{
    if (!netdev_unregister_provider(type)) {
        struct netdev_class *class;
        int error;

        class = xmemdup(&dummy_class, sizeof dummy_class);
        class->type = xstrdup(type);
        error = netdev_register_provider(class);
        if (error) {
            VLOG_ERR("%s: failed to register netdev provider (%s)",
                     type, ovs_strerror(error));
            free(CONST_CAST(char *, class->type));
            free(class);
        }
    }
}

void
netdev_dummy_register(enum dummy_level level)
{
    unixctl_command_register("netdev-dummy/receive",
                             "name [--qid queue_id] packet|flow [--len packet_len]",
                             2, INT_MAX, OVS_OUTPUT_FMT_TEXT,
                             netdev_dummy_receive, NULL);
    unixctl_command_register("netdev-dummy/set-admin-state",
                             "[netdev] up|down", 1, 2, OVS_OUTPUT_FMT_TEXT,
                             netdev_dummy_set_admin_state, NULL);
    unixctl_command_register("netdev-dummy/conn-state",
                             "[netdev]", 0, 1, OVS_OUTPUT_FMT_TEXT,
                             netdev_dummy_conn_state, NULL);
    unixctl_command_register("netdev-dummy/ip4addr",
                             "[netdev] ipaddr/mask-prefix-len", 2, 2,
                             OVS_OUTPUT_FMT_TEXT, netdev_dummy_ip4addr,
                             NULL);
    unixctl_command_register("netdev-dummy/ip6addr",
                             "[netdev] ip6addr", 2, 2, OVS_OUTPUT_FMT_TEXT,
                             netdev_dummy_ip6addr, NULL);

    if (level == DUMMY_OVERRIDE_ALL) {
        struct sset types;
        const char *type;

        sset_init(&types);
        netdev_enumerate_types(&types);
        SSET_FOR_EACH (type, &types) {
            if (strcmp(type, "patch")) {
                netdev_dummy_override(type);
            }
        }
        sset_destroy(&types);
    } else if (level == DUMMY_OVERRIDE_SYSTEM) {
        netdev_dummy_override("system");
    }
    netdev_register_provider(&dummy_class);
    netdev_register_provider(&dummy_internal_class);
    netdev_register_provider(&dummy_pmd_class);

    netdev_register_flow_api_provider(&netdev_offload_dummy);

    netdev_vport_tunnel_register();
}
