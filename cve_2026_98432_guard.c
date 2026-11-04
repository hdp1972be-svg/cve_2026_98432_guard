/*
 * CVE-2026-98432 temporary XDP mitigation
 *
 * Policy:
 *   - Drop IPv4/TCP packets with IPv4 options (IHL > 5).
 *   - Permit explicitly whitelisted source IPv4 addresses.
 *   - Permit explicitly whitelisted IPv4 /24 prefixes.
 *   - Pass unrelated traffic and malformed/truncated packets.
 *   - When the wake flag is set (config map key 0 != 0), the drop is
 *     bypassed: matching packets are passed instead. Operators can
 *     toggle enforcement on/off without detaching the XDP program.
 *
 * Compatibility:
 *   - Supports Linux 4.18 through 6.x.
 *   - Two map-definition paths, selected at build time:
 *       LEGACY_MAPS=1  -> struct bpf_map_def (4.18 .. 5.17, old toolchains)
 *       LEGACY_MAPS=0  -> BTF-style maps       (5.3+ / 6.x, modern libbpf)
 *   - No includes: all types, constants and structs are declared locally.
 *   - VLAN parsing is expanded explicitly (no bounded loop) so the 4.18
 *     verifier accepts the program.
 *
 * GPL licensed.
 */

#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* ── Local scalar typedefs ───────────────────────────────────────────── */
typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;
typedef signed int         __s32;
typedef __u16              __be16;
typedef __u32              __be32;

/* ── Local constants ─────────────────────────────────────────────────── */
#ifndef NULL
#define NULL ((void *)0)
#endif

#define ETH_P_8021Q   0x8100
#define ETH_P_8021AD  0x88A8
#define ETH_P_IP      0x0800

#define IPPROTO_TCP   6

/* BPF map types */
#define BPF_MAP_TYPE_HASH             1
#define BPF_MAP_TYPE_ARRAY            2
#define BPF_MAP_TYPE_PERCPU_ARRAY     6
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4
#define BPF_MAP_TYPE_LRU_HASH         9

/* BPF helper IDs */
#define BPF_FUNC_MAP_LOOKUP_ELEM   1
#define BPF_FUNC_MAP_UPDATE_ELEM   2
#define BPF_FUNC_PERF_EVENT_OUTPUT 25

/* BPF update flags / misc */
#define BPF_ANY           0
#define BPF_NOEXIST       1
#define BPF_F_CURRENT_CPU 0xffffffffULL

/* XDP action codes */
#define XDP_ABORTED 0
#define XDP_DROP    1
#define XDP_PASS    2
#define XDP_TX      3
#define XDP_REDIRECT 4

/* ── Local packet structs (packed, no headers needed) ────────────────── */
struct ethhdr {
    unsigned char  h_dest[6];
    unsigned char  h_source[6];
    __be16         h_proto;
} __attribute__((packed));

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
} __attribute__((packed));

struct iphdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u8   ihl:4;
    __u8   version:4;
#else
    __u8   version:4;
    __u8   ihl:4;
#endif
    __u8   tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8   ttl;
    __u8   protocol;
    __u16  check;
    __be32 saddr;
    __be32 daddr;
} __attribute__((packed));

/* XDP context as exposed to BPF programs. */
struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

/* ── Application structs ─────────────────────────────────────────────── */
struct drop_event {
    __u32 src_ip;
    __u64 count;
};

#define STAT_TCP_IP_OPTIONS_DROP  0
#define STAT_MALFORMED_IPV4_PASS  1
/* New: packets that would have been dropped but were passed because
 * the wake flag was set. Distinct from both drop and whitelist-pass,
 * so operators can see how much "wake mode" is masking enforcement. */
#define STAT_TCP_IP_OPTIONS_WAKE  2

#define STATS_ENTRIES 3

#define WHITELIST_ENTRIES 4096
#define PREFIX_ENTRIES    4096
#define DROP_IPS_ENTRIES  4096
#define EVENTS_ENTRIES    1024

/*
 * Map definitions.
 *
 * Build with -DLEGACY_MAPS=1 for kernels 4.18 .. 5.17 (or old toolchains
 * that cannot emit BTF). Build without it (default) for 5.3+ / 6.x.
 */
#ifndef LEGACY_MAPS
#define LEGACY_MAPS 0
#endif

#if LEGACY_MAPS

/* Legacy map ABI: struct bpf_map_def. */
struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

/* Statistics: per-CPU counters (3 slots now). */
struct bpf_map_def SEC("maps") cve_2026_98432_stats = {
    BPF_MAP_TYPE_PERCPU_ARRAY, sizeof(__u32), sizeof(__u64), STATS_ENTRIES, 0
};

/* Exact IPv4 whitelist. */
struct bpf_map_def SEC("maps") cve_2026_98432_whitelist = {
    BPF_MAP_TYPE_HASH, sizeof(__u32), sizeof(__u8), WHITELIST_ENTRIES, 0
};

/* Historical map name retained for pin-path compatibility (/24 keys). */
struct bpf_map_def SEC("maps") cve_2026_98432_whitelist_bm = {
    BPF_MAP_TYPE_HASH, sizeof(__u32), sizeof(__u8), PREFIX_ENTRIES, 0
};

/* Per-source drop counters. */
struct bpf_map_def SEC("maps") cve_2026_98432_drop_ips = {
    BPF_MAP_TYPE_LRU_HASH, sizeof(__u32), sizeof(__u64), DROP_IPS_ENTRIES, 0
};

/* perf_event_output requires PERF_EVENT_ARRAY. */
struct bpf_map_def SEC("maps") cve_2026_98432_events = {
    BPF_MAP_TYPE_PERF_EVENT_ARRAY, sizeof(__u32), sizeof(__u32), EVENTS_ENTRIES, 0
};

/* Runtime configuration (key 0 = wake flag). */
struct bpf_map_def SEC("maps") cve_2026_98432_config = {
    BPF_MAP_TYPE_ARRAY, sizeof(__u32), sizeof(__u32), 1, 0
};

#else /* !LEGACY_MAPS */

/* BTF-style map definitions, macros declared locally. */
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
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} cve_2026_98432_config SEC(".maps");

#endif /* LEGACY_MAPS */

/* ── Helper prototypes, declared locally ─────────────────────────────── */
static void *(*bpf_map_lookup_elem)(void *, const void *) =
    (void *)BPF_FUNC_MAP_LOOKUP_ELEM;

static long (*bpf_map_update_elem)(
    void *, const void *, const void *, __u64
) = (void *)BPF_FUNC_MAP_UPDATE_ELEM;

static long (*bpf_perf_event_output)(
    void *, void *, __u64, void *, __u64
) = (void *)BPF_FUNC_PERF_EVENT_OUTPUT;

/* ── Inline helpers ──────────────────────────────────────────────────── */
static __always_inline __u16 swap16(__u16 value)
{
    return __builtin_bswap16(value);
}

/*
 * ip->saddr is kept in its native packet representation.
 * On little-endian systems, masking the low 24 bits produces
 * the network-order /24 key.
 */
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
    __u64 *value;

    value = bpf_map_lookup_elem(
        &cve_2026_98432_stats, &index
    );

    if (value)
        __sync_fetch_and_add(value, 1);
}

static __always_inline int is_whitelisted(__u32 ip)
{
    __u8 *value;
    __u32 network;

    value = bpf_map_lookup_elem(
        &cve_2026_98432_whitelist, &ip
    );

    if (value)
        return 1;

    network = prefix24(ip);

    value = bpf_map_lookup_elem(
        &cve_2026_98432_whitelist_bm, &network
    );

    return value != 0;
}

/*
 * Returns 1 if wake mode is enabled (bypass drop), 0 otherwise.
 * Also forces the compiler to keep cve_2026_98432_config in the
 * generated object: without a reference, the map is dropped and
 * userspace cannot write to it, which is what caused `wake on|off`
 * to fail with ENOENT earlier.
 */
static __always_inline int wake_enabled(void)
{
    __u32 key = 0;
    __u32 *val;

    val = bpf_map_lookup_elem(&cve_2026_98432_config, &key);
    return val && *val;
}

/* ── XDP entry point ─────────────────────────────────────────────────── */
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

    struct drop_event event = {};

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    protocol = swap16(eth->h_proto);
    cursor = eth + 1;

    /*
     * Support up to two VLAN headers.
     * Expanded explicitly (no loop) so the 4.18 verifier, which cannot
     * handle bounded loops, accepts the program.
     */
    if (protocol == ETH_P_8021Q ||
        protocol == ETH_P_8021AD ||
        protocol == 0x9100) {
        struct vlan_hdr *vlan = cursor;

        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;

        protocol = swap16(vlan->h_vlan_encapsulated_proto);
        cursor = vlan + 1;

        if (protocol == ETH_P_8021Q ||
            protocol == ETH_P_8021AD ||
            protocol == 0x9100) {
            vlan = cursor;

            if ((void *)(vlan + 1) > data_end)
                return XDP_PASS;

            protocol = swap16(vlan->h_vlan_encapsulated_proto);
            cursor = vlan + 1;
        }
    }

    if (protocol != ETH_P_IP)
        return XDP_PASS;

    ip = cursor;

    if ((void *)(ip + 1) > data_end) {
        increment_stat(STAT_MALFORMED_IPV4_PASS);
        return XDP_PASS;
    }

    if (ip->version != 4 || ip->ihl < 5) {
        increment_stat(STAT_MALFORMED_IPV4_PASS);
        return XDP_PASS;
    }

    ihl_length = (__u32)ip->ihl * 4;

    if ((void *)ip + ihl_length > data_end) {
        increment_stat(STAT_MALFORMED_IPV4_PASS);
        return XDP_PASS;
    }

    /* Only TCP packets with IPv4 options are in scope. */
    if (ip->protocol != IPPROTO_TCP || ihl_length == sizeof(*ip))
        return XDP_PASS;

    source_ip = ip->saddr;

    if (is_whitelisted(source_ip))
        return XDP_PASS;

    /*
     * Wake mode: bypass the drop while still counting it separately,
     * so operators can see exactly how many packets would have been
     * dropped had enforcement been active.
     */
    if (wake_enabled()) {
        increment_stat(STAT_TCP_IP_OPTIONS_WAKE);
        return XDP_PASS;
    }

    /*
     * Update approximate per-source counters.
     * Atomic increment prevents lost increments when the key exists.
     */
    {
        __u64 initial = 1;
        __u64 *counter;

        counter = bpf_map_lookup_elem(
            &cve_2026_98432_drop_ips, &source_ip
        );

        if (counter) {
            __sync_fetch_and_add(counter, 1);
            initial = *counter;
        } else {
            bpf_map_update_elem(
                &cve_2026_98432_drop_ips,
                &source_ip,
                &initial,
                BPF_NOEXIST
            );
        }

        event.src_ip = source_ip;
        event.count = initial;
    }

    bpf_perf_event_output(
        ctx,
        &cve_2026_98432_events,
        BPF_F_CURRENT_CPU,
        &event,
        sizeof(event)
    );

    increment_stat(STAT_TCP_IP_OPTIONS_DROP);

    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
