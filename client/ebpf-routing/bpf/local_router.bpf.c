#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "router_common.h"

/* Maps */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct wg_endpoint);
} wg_endpoint_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} bypass_v4_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct ipv6_lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} bypass_v6_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct router_config);
} router_config_map SEC(".maps");

static __always_inline void apply_mark(struct bpf_sock_addr *ctx) {
    __u32 zero = 0;
    struct router_config *cfg = bpf_map_lookup_elem(&router_config_map, &zero);
    if (!cfg || !cfg->enabled)
        return;
    __u32 mark = cfg->fwmark;
    bpf_setsockopt(ctx, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
}

static __always_inline bool should_bypass_ip4_common(__u32 user_ip4, __u16 user_port_be) {
    __u32 ip = bpf_ntohl(user_ip4);

    /* Bypass Loopback (127.0.0.0/8) */
    if ((ip >> 24) == 127) return true;
    /* Bypass Multicast (224.0.0.0/4) & Broadcast */
    if ((ip >> 28) == 14 || ip == 0xffffffff) return true;

    /* Check WireGuard Endpoint */
    __u32 zero = 0;
    struct wg_endpoint *ep = bpf_map_lookup_elem(&wg_endpoint_map, &zero);
    if (ep && ep->enabled && ep->family == AF_INET) {
        if (user_ip4 == ep->ip4 && (ep->port == 0 || user_port_be == ep->port))
            return true;
    }

    /* Check LPM Trie */
    struct ipv4_lpm_key key = {
        .prefixlen = 32,
        .data = user_ip4,
    };
    if (bpf_map_lookup_elem(&bypass_v4_map, &key))
        return true;

    return false;
}

static __always_inline bool should_bypass_ip6_common(__u32 ip0, __u32 ip1, __u32 ip2, __u32 ip3, __u16 user_port_be) {
    /* Bypass Loopback (::1) */
    if (ip0 == 0 && ip1 == 0 && ip2 == 0 && ip3 == bpf_htonl(1))
        return true;

    /* Bypass Link-local (fe80::/10) */
    if ((bpf_ntohl(ip0) & 0xffc00000) == 0xfe800000)
        return true;

    /* Bypass Multicast (ff00::/8) */
    if ((bpf_ntohl(ip0) & 0xff000000) == 0xff000000)
        return true;

    /* Check WireGuard Endpoint */
    __u32 zero = 0;
    struct wg_endpoint *ep = bpf_map_lookup_elem(&wg_endpoint_map, &zero);
    if (ep && ep->enabled && ep->family == AF_INET6) {
        if (ip0 == ep->ip6[0] &&
            ip1 == ep->ip6[1] &&
            ip2 == ep->ip6[2] &&
            ip3 == ep->ip6[3] &&
            (ep->port == 0 || user_port_be == ep->port))
            return true;
    }

    /* Check LPM Trie */
    struct ipv6_lpm_key key = {
        .prefixlen = 128,
        .data32 = { ip0, ip1, ip2, ip3 },
    };
    if (bpf_map_lookup_elem(&bypass_v6_map, &key))
        return true;

    return false;
}

static __always_inline bool should_bypass_v4(struct bpf_sock_addr *ctx) {
    return should_bypass_ip4_common(ctx->user_ip4, (__u16)ctx->user_port);
}

static __always_inline bool should_bypass_v6(struct bpf_sock_addr *ctx) {
    return should_bypass_ip6_common(ctx->user_ip6[0], ctx->user_ip6[1],
                                    ctx->user_ip6[2], ctx->user_ip6[3],
                                    (__u16)ctx->user_port);
}

SEC("cgroup/connect4")
int sock_connect4(struct bpf_sock_addr *ctx) {
    if (should_bypass_v4(ctx))
        return 1;
    apply_mark(ctx);
    return 1;
}

SEC("cgroup/sendmsg4")
int sock_sendmsg4(struct bpf_sock_addr *ctx) {
    if (should_bypass_v4(ctx))
        return 1;
    apply_mark(ctx);
    return 1;
}

SEC("cgroup/connect6")
int sock_connect6(struct bpf_sock_addr *ctx) {
    if (should_bypass_v6(ctx))
        return 1;
    apply_mark(ctx);
    return 1;
}

SEC("cgroup/sendmsg6")
int sock_sendmsg6(struct bpf_sock_addr *ctx) {
    if (should_bypass_v6(ctx))
        return 1;
    apply_mark(ctx);
    return 1;
}

SEC("tc")
int tc_router_ingress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    __u32 zero = 0;
    struct router_config *cfg = bpf_map_lookup_elem(&router_config_map, &zero);
    if (!cfg || !cfg->enabled)
        return TC_ACT_OK;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    __u16 proto = bpf_ntohs(eth->h_proto);
    void *nh = eth + 1;

    /* Handle 802.1Q and 802.1ad VLAN encapsulations */
    if (proto == ETH_P_8021Q || proto == ETH_P_8021AD) {
        struct {
            __be16 tci;
            __be16 encap_proto;
        } *vlan = nh;
        if ((void *)(vlan + 1) > data_end)
            return TC_ACT_OK;
        proto = bpf_ntohs(vlan->encap_proto);
        nh = vlan + 1;
    }

    if (proto == ETH_P_IP) {
        struct iphdr *iph = nh;
        if ((void *)(iph + 1) > data_end)
            return TC_ACT_OK;
        if (iph->version != 4 || iph->ihl < 5)
            return TC_ACT_OK;

        __u16 dst_port = 0;
        if (iph->protocol == IPPROTO_UDP) {
            void *trans = (void *)iph + ((iph->ihl & 0x0f) * 4);
            struct udphdr *udp = trans;
            if ((void *)(udp + 1) <= data_end) {
                dst_port = udp->dest;
            }
        }

        if (should_bypass_ip4_common(iph->daddr, dst_port))
            return TC_ACT_OK;

        skb->mark = cfg->fwmark;
        return TC_ACT_OK;
    } else if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = nh;
        if ((void *)(ip6h + 1) > data_end)
            return TC_ACT_OK;
        if (ip6h->version != 6)
            return TC_ACT_OK;

        __u16 dst_port = 0;
        if (ip6h->nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = (void *)(ip6h + 1);
            if ((void *)(udp + 1) <= data_end) {
                dst_port = udp->dest;
            }
        }

        __u32 *daddr = (__u32 *)&ip6h->daddr;
        if (should_bypass_ip6_common(daddr[0], daddr[1], daddr[2], daddr[3], dst_port))
            return TC_ACT_OK;

        skb->mark = cfg->fwmark;
        return TC_ACT_OK;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
