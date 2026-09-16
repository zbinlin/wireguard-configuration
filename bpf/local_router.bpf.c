#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SOL_SOCKET 1
#define SO_MARK 36

#define AF_INET  2
#define AF_INET6 10

struct wg_endpoint {
    __u32 ip4;           /* Network byte order */
    __u32 ip6[4];        /* Network byte order */
    __u16 port;          /* Network byte order */
    __u8  family;        /* AF_INET or AF_INET6 */
    __u8  enabled;       /* 1 = enabled, 0 = disabled */
};

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 data;          /* Network byte order */
};

struct ipv6_lpm_key {
    __u32 prefixlen;
    __u32 data[4];       /* Network byte order */
};

struct router_config {
    __u32 fwmark;
    __u32 enabled;
};

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

static __always_inline bool should_bypass_v4(struct bpf_sock_addr *ctx) {
    __u32 user_ip4 = ctx->user_ip4;
    __u32 user_port = ctx->user_port;
    __u32 ip = bpf_ntohl(user_ip4);

    /* Bypass Loopback (127.0.0.0/8) */
    if ((ip >> 24) == 127) return true;
    /* Bypass Multicast (224.0.0.0/4) & Broadcast */
    if ((ip >> 28) == 14 || ip == 0xffffffff) return true;

    /* Check WireGuard Endpoint */
    __u32 zero = 0;
    struct wg_endpoint *ep = bpf_map_lookup_elem(&wg_endpoint_map, &zero);
    if (ep && ep->enabled && ep->family == AF_INET) {
        if (user_ip4 == ep->ip4 && (ep->port == 0 || (__u16)user_port == ep->port))
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

static __always_inline bool should_bypass_v6(struct bpf_sock_addr *ctx) {
    __u32 ip0 = ctx->user_ip6[0];
    __u32 ip1 = ctx->user_ip6[1];
    __u32 ip2 = ctx->user_ip6[2];
    __u32 ip3 = ctx->user_ip6[3];
    __u32 user_port = ctx->user_port;

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
            (ep->port == 0 || (__u16)user_port == ep->port))
            return true;
    }

    /* Check LPM Trie */
    struct ipv6_lpm_key key = {
        .prefixlen = 128,
        .data = { ip0, ip1, ip2, ip3 },
    };
    if (bpf_map_lookup_elem(&bypass_v6_map, &key))
        return true;

    return false;
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

char _license[] SEC("license") = "GPL";
