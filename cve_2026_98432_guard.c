
/*
 * cve_2026_98432_guard.c
 *
 * Temporary XDP mitigation:
 * Drop IPv4 TCP packets carrying IPv4 options (IHL > 5).
 *
 * Pass:
 *   - Non-IPv4 traffic
 *   - Non-TCP IPv4 traffic
 *   - IPv4 TCP packets without IPv4 options
 *   - Malformed or truncated packets
 *
 * Supports Ethernet and up to two VLAN tags.
 *
 * Per-CPU statistics:
 *   key 0: IPv4 TCP packets dropped due to IP options
 *   key 1: Malformed/truncated IPv4 packets passed
 */

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;

#define XDP_DROP 1
#define XDP_PASS 2

#define ETH_P_IP       0x0800
#define ETH_P_8021Q    0x8100
#define ETH_P_8021AD   0x88A8
#define ETH_P_9100     0x9100

#define IPPROTO_TCP    6

#define STAT_TCP_IP_OPTIONS_DROP  0
#define STAT_MALFORMED_IPV4_PASS  1

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

struct ethhdr {
    __u8  h_dest[6];
    __u8  h_source[6];
    __u16 h_proto;
};

struct vlan_hdr {
    __u16 tci;
    __u16 encapsulated_proto;
};

struct iphdr {
    __u8  version_ihl;
    __u8  tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
};

struct {
    __uint(type, 6);       /* BPF_MAP_TYPE_PERCPU_ARRAY */
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} cve_2026_98432_stats SEC(".maps");

/* BPF helper: bpf_map_lookup_elem, helper ID 1 */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
    (void *)1;

static __inline __u16 ntohs(__u16 value)
{
    return __builtin_bswap16(value);
}

static __inline void count_stat(__u32 key)
{
    __u64 *counter;

    counter = bpf_map_lookup_elem(&cve_2026_98432_stats, &key);

    if (counter)
        (*counter)++;
}

SEC("xdp")
int xdp_cve_2026_98432_guard(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth;
    struct vlan_hdr *vlan;
    struct iphdr *ip;

    __u16 proto;
    __u8 version;
    __u8 ihl;
    __u32 ip_header_length;

    /* Ethernet header */
    eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    proto = ntohs(eth->h_proto);

    /* First VLAN tag */
    if (proto == ETH_P_8021Q ||
        proto == ETH_P_8021AD ||
        proto == ETH_P_9100) {

        vlan = (void *)(eth + 1);

        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;

        proto = ntohs(vlan->encapsulated_proto);

        /* Second VLAN tag */
        if (proto == ETH_P_8021Q ||
            proto == ETH_P_8021AD ||
            proto == ETH_P_9100) {

            vlan = (void *)(vlan + 1);

            if ((void *)(vlan + 1) > data_end)
                return XDP_PASS;

            proto = ntohs(vlan->encapsulated_proto);
        }

        ip = (void *)(vlan + 1);
    } else {
        ip = (void *)(eth + 1);
    }

    /* Only IPv4 */
    if (proto != ETH_P_IP)
        return XDP_PASS;

    /* Fixed IPv4 header must be present */
    if ((void *)(ip + 1) > data_end) {
        count_stat(STAT_MALFORMED_IPV4_PASS);
        return XDP_PASS;
    }

    version = ip->version_ihl >> 4;
    ihl = ip->version_ihl & 0x0f;

    /* Validate IPv4 version and IHL */
    if (version != 4 || ihl < 5 || ihl > 15) {
        count_stat(STAT_MALFORMED_IPV4_PASS);
        return XDP_PASS;
    }

    ip_header_length = (__u32)ihl * 4;

    /* Verify complete IPv4 header, including options */
    if ((void *)ip + ip_header_length > data_end) {
        count_stat(STAT_MALFORMED_IPV4_PASS);
        return XDP_PASS;
    }

    /*
     * Drop TCP packets with IPv4 options.
     * TCP options are unaffected; they are in the TCP header.
     */
    if (ip->protocol == IPPROTO_TCP && ihl > 5) {
        count_stat(STAT_TCP_IP_OPTIONS_DROP);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
