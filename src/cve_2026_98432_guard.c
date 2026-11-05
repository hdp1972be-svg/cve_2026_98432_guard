// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * CVE-2026-98432 temporary XDP mitigation
 *
 * Policy:
 *   - Detect IPv4/TCP packets with IPv4 options (IHL > 5).
 *   - Permit explicitly whitelisted source IPv4 addresses.
 *   - Permit explicitly whitelisted /24 prefixes.
 *   - Pass unrelated traffic and malformed/truncated packets.
 *
 * Independent controls:
 *
 *   config map key 0: WAKE
 *     0 = normal operation
 *     1 = bypass detection; matching packets pass immediately
 *
 *   config map key 1: MODE
 *     0 = ENFORCE: capture, count and drop
 *     1 = MONITOR: capture, count and pass
 *
 *   WAKE takes precedence over MODE.
 *
 * Events:
 *   [struct meta_event (8 bytes)][caplen bytes of raw frame]
 *
 *   META_MAGIC          = enforced drop
 *   META_MAGIC_MONITOR  = monitor detection
 *
 *   The high bit distinguishes monitor events without changing
 *   the metadata structure or packet payload offset.
 *
 * Compatibility:
 *   - Linux 4.18 through 6.x
 *   - LEGACY_MAPS=1: struct bpf_map_def
 *   - LEGACY_MAPS=0: BTF-style maps
 *   - No includes
 *   - Explicit VLAN parsing for older verifier compatibility
 *
 * GPL licensed.
 */

#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;
typedef __u16              __be16;
typedef __u32              __be32;

#ifndef NULL
#define NULL ((void *)0)
#endif

#define ETH_P_8021Q   0x8100
#define ETH_P_8021AD  0x88A8
#define ETH_P_IP      0x0800
#define IPPROTO_TCP   6

#define BPF_MAP_TYPE_HASH             1
#define BPF_MAP_TYPE_ARRAY            2
#define BPF_MAP_TYPE_PERCPU_ARRAY     6
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4
#define BPF_MAP_TYPE_LRU_HASH         9

#define BPF_FUNC_MAP_LOOKUP_ELEM   1
#define BPF_FUNC_MAP_UPDATE_ELEM   2
#define BPF_FUNC_PERF_EVENT_OUTPUT 25

#define BPF_ANY           0
#define BPF_NOEXIST       1
#define BPF_F_CURRENT_CPU 0xffffffffULL

#define XDP_ABORTED  0
#define XDP_DROP     1
#define XDP_PASS     2
#define XDP_TX       3
#define XDP_REDIRECT 4

#define MAX_CAPTURE 9216

#define META_MAGIC         0x5043544DU
#define META_MAGIC_MONITOR (META_MAGIC | 0x80000000U)

/*
 * Configuration map keys.
 *
 * Key 0 is deliberately retained for the original wake switch.
 * Key 1 is the independent monitor/enforce mode.
 */

#define CONFIG_KEY_WAKE 0
#define CONFIG_KEY_MODE 1

#define MODE_ENFORCE 0
#define MODE_MONITOR 1

struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
} __attribute__((packed));

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
} __attribute__((packed));

struct iphdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u8 ihl:4;
    __u8 version:4;
#else
    __u8 version:4;
    __u8 ihl:4;
#endif
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __be32 saddr;
    __be32 daddr;
} __attribute__((packed));

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

struct meta_event {
    __u32 magic;
    __u32 ifindex;
};

/*
 * Statistics:
 *
 * 0 = enforced drops
 * 1 = malformed IPv4 passed
 * 2 = wake bypasses
 * 3 = monitor detections
 */

#define STAT_TCP_IP_OPTIONS_DROP     0
#define STAT_MALFORMED_IPV4_PASS     1
#define STAT_TCP_IP_OPTIONS_WAKE     2
#define STAT_TCP_IP_OPTIONS_MONITOR  3

#define STATS_ENTRIES 4

#define WHITELIST_ENTRIES 4096
#define PREFIX_ENTRIES    4096
#define DROP_IPS_ENTRIES  4096
#define EVENTS_ENTRIES    1024

#ifndef LEGACY_MAPS
#define LEGACY_MAPS 0
#endif

#if LEGACY_MAPS

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

struct bpf_map_def SEC("maps") cve_2026_98432_stats = {
    BPF_MAP_TYPE_PERCPU_ARRAY,
    sizeof(__u32),
    sizeof(__u64),
    STATS_ENTRIES,
    0
};

struct bpf_map_def SEC("maps") cve_2026_98432_whitelist = {
    BPF_MAP_TYPE_HASH,
    sizeof(__u32),
    sizeof(__u8),
    WHITELIST_ENTRIES,
    0
};

struct bpf_map_def SEC("maps") cve_2026_98432_whitelist_bm = {
    BPF_MAP_TYPE_HASH,
    sizeof(__u32),
    sizeof(__u8),
    PREFIX_ENTRIES,
    0
};

struct bpf_map_def SEC("maps") cve_2026_98432_drop_ips = {
    BPF_MAP_TYPE_LRU_HASH,
    sizeof(__u32),
    sizeof(__u64),
    DROP_IPS_ENTRIES,
    0
};

struct bpf_map_def SEC("maps") cve_2026_98432_events = {
    BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    sizeof(__u32),
    sizeof(__u32),
    EVENTS_ENTRIES,
    0
};

/*
 * Two independent configuration entries:
 *   [0] wake
 *   [1] mode
 */
struct bpf_map_def SEC("maps") cve_2026_98432_config = {
    BPF_MAP_TYPE_ARRAY,
    sizeof(__u32),
    sizeof(__u32),
    2,
    0
};

struct bpf_map_def SEC("maps") cve_2026_98432_meta = {
    BPF_MAP_TYPE_PERCPU_ARRAY,
    sizeof(__u32),
    sizeof(struct meta_event),
    1,
    0
};

#else

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} cve_2026_98432_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, WHITELIST_ENTRIES);
    __type(key, __u32);
    __type(value, __u8);
} cve_2026_98432_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PREFIX_ENTRIES);
    __type(key, __u32);
    __type(value, __u8);
} cve_2026_98432_whitelist_bm SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, DROP_IPS_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} cve_2026_98432_drop_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, EVENTS_ENTRIES);
} cve_2026_98432_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} cve_2026_98432_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct meta_event);
} cve_2026_98432_meta SEC(".maps");

#endif

static void *(*bpf_map_lookup_elem)(void *, const void *) =
    (void *)BPF_FUNC_MAP_LOOKUP_ELEM;

static long (*bpf_map_update_elem)(
    void *,
    const void *,
    const void *,
    __u64
) = (void *)BPF_FUNC_MAP_UPDATE_ELEM;

static long (*bpf_perf_event_output)(
    void *,
    void *,
    __u64,
    void *,
    __u64
) = (void *)BPF_FUNC_PERF_EVENT_OUTPUT;

static __always_inline __u16 swap16(__u16 value)
{
    return __builtin_bswap16(value);
}

static __always_inline __u32 prefix24(__u32 ip)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ip & 0x00ffffffU;
#else
    return ip & 0xffffff00U;
#endif
}

static __always_inline void increment_stat(__u32 index)
{
    __u64 *value = bpf_map_lookup_elem(
        &cve_2026_98432_stats,
        &index
    );

    if (value)
        __sync_fetch_and_add(value, 1);
}

static __always_inline int is_whitelisted(__u32 ip)
{
    __u8 *value;
    __u32 network;

    value = bpf_map_lookup_elem(
        &cve_2026_98432_whitelist,
        &ip
    );

    if (value)
        return 1;

    network = prefix24(ip);

    value = bpf_map_lookup_elem(
        &cve_2026_98432_whitelist_bm,
        &network
    );

    return value != 0;
}

/*
 * WAKE:
 *
 * Config key 0.
 *
 * This is the original bypass switch. It remains independent
 * of monitor/enforce mode.
 */
static __always_inline int wake_enabled(void)
{
    __u32 key = CONFIG_KEY_WAKE;

    __u32 *val = bpf_map_lookup_elem(
        &cve_2026_98432_config,
        &key
    );

    return val && *val;
}

/*
 * MODE:
 *
 * Config key 1.
 *
 * Missing or invalid values default to ENFORCE.
 */
static __always_inline __u32 guard_mode(void)
{
    __u32 key = CONFIG_KEY_MODE;

    __u32 *val = bpf_map_lookup_elem(
        &cve_2026_98432_config,
        &key
    );

    if (val && *val == MODE_MONITOR)
        return MODE_MONITOR;

    return MODE_ENFORCE;
}

/*
 * Per-source matching-packet counter.
 *
 * Counts both monitor detections and enforced drops.
 * Wake bypasses are deliberately excluded.
 */
static __always_inline void count_source(__u32 source_ip)
{
    __u64 initial = 1;

    __u64 *counter = bpf_map_lookup_elem(
        &cve_2026_98432_drop_ips,
        &source_ip
    );

    if (counter) {
        __sync_fetch_and_add(counter, 1);
    } else {
        bpf_map_update_elem(
            &cve_2026_98432_drop_ips,
            &source_ip,
            &initial,
            BPF_NOEXIST
        );
    }
}

/*
 * Emit:
 *
 *   [8-byte metadata][captured packet bytes]
 *
 * Monitor events use META_MAGIC_MONITOR.
 * Enforced drops use META_MAGIC.
 */
static __always_inline void emit_event(
    struct xdp_md *ctx,
    void *data,
    void *data_end,
    __u32 mode
)
{
    __u32 meta_key = 0;

    struct meta_event *meta = bpf_map_lookup_elem(
        &cve_2026_98432_meta,
        &meta_key
    );

    if (!meta)
        return;

    meta->magic = (mode == MODE_MONITOR)
        ? META_MAGIC_MONITOR
        : META_MAGIC;

    meta->ifindex = ctx->ingress_ifindex;

    __u64 pkt_len = (__u64)(
        (char *)data_end - (char *)data
    );

    __u32 cap = pkt_len > MAX_CAPTURE
        ? MAX_CAPTURE
        : (__u32)pkt_len;

    __u64 flags = BPF_F_CURRENT_CPU;
    flags |= ((__u64)cap) << 32;

    bpf_perf_event_output(
        ctx,
        &cve_2026_98432_events,
        flags,
        meta,
        sizeof(*meta)
    );
}

SEC("xdp")
int xdp_cve_2026_98432_guard(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip;

    __u16 protocol;
    __u32 ihl_length;
    __u32 source_ip;

    void *cursor;

    /*
     * Ethernet header.
     */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    protocol = swap16(eth->h_proto);
    cursor = eth + 1;

    /*
     * First VLAN tag.
     */
    if (protocol == ETH_P_8021Q ||
        protocol == ETH_P_8021AD ||
        protocol == 0x9100) {

        struct vlan_hdr *vlan = cursor;

        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;

        protocol = swap16(
            vlan->h_vlan_encapsulated_proto
        );

        cursor = vlan + 1;

        /*
         * Second VLAN tag.
         */
        if (protocol == ETH_P_8021Q ||
            protocol == ETH_P_8021AD ||
            protocol == 0x9100) {

            vlan = cursor;

            if ((void *)(vlan + 1) > data_end)
                return XDP_PASS;

            protocol = swap16(
                vlan->h_vlan_encapsulated_proto
            );

            cursor = vlan + 1;
        }
    }

    /*
     * Only IPv4.
     */
    if (protocol != ETH_P_IP)
        return XDP_PASS;

    ip = cursor;

    /*
     * Minimum IPv4 header.
     */
    if ((void *)(ip + 1) > data_end) {
        increment_stat(STAT_MALFORMED_IPV4_PASS);
        return XDP_PASS;
    }

    if (ip->version != 4 || ip->ihl < 5) {
        increment_stat(STAT_MALFORMED_IPV4_PASS);
        return XDP_PASS;
    }

    ihl_length = (__u32)ip->ihl * 4;

    /*
     * Validate complete IPv4 header including options.
     */
    if ((void *)ip + ihl_length > data_end) {
        increment_stat(STAT_MALFORMED_IPV4_PASS);
        return XDP_PASS;
    }

    /*
     * Only TCP with IPv4 options.
     */
    if (ip->protocol != IPPROTO_TCP ||
        ihl_length == sizeof(*ip))
        return XDP_PASS;

    source_ip = ip->saddr;

    /*
     * Explicit whitelist bypass.
     */
    if (is_whitelisted(source_ip))
        return XDP_PASS;

    /*
     * WAKE BYPASS.
     *
     * This deliberately happens before:
     *   - source counter increment
     *   - perf event generation
     *   - monitor/enforce mode evaluation
     *
     * Wake therefore preserves the original bypass semantics.
     */
    if (wake_enabled()) {
        increment_stat(STAT_TCP_IP_OPTIONS_WAKE);
        return XDP_PASS;
    }

    /*
     * From here onward the packet is a genuine detection.
     *
     * Both monitor and enforce count and capture it.
     */
    count_source(source_ip);

    {
        __u32 mode = guard_mode();

        emit_event(
            ctx,
            data,
            data_end,
            mode
        );

        /*
         * MONITOR:
         * Detection and forensic capture, but no mitigation.
         */
        if (mode == MODE_MONITOR) {
            increment_stat(STAT_TCP_IP_OPTIONS_MONITOR);
            return XDP_PASS;
        }
    }

    /*
     * ENFORCE:
     * Detection, forensic capture and packet drop.
     */
    increment_stat(STAT_TCP_IP_OPTIONS_DROP);

    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
