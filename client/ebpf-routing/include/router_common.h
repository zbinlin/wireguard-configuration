#ifndef __ROUTER_COMMON_H__
#define __ROUTER_COMMON_H__

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define DEFAULT_PIN_DIR "/sys/fs/bpf/wg_routing"
#define DEFAULT_CGROUP_PATH "/sys/fs/cgroup"
#define DEFAULT_FWMARK 0x100

#ifndef SOL_SOCKET
#define SOL_SOCKET 1
#endif

#ifndef SO_MARK
#define SO_MARK 36
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

struct wg_endpoint {
    __u32 ip4;           /* Network byte order */
    __u32 ip6[4];        /* Network byte order */
    __u16 port;          /* Network byte order */
    __u8  family;        /* 2 = AF_INET, 10 = AF_INET6 */
    __u8  enabled;       /* 1 = enabled, 0 = disabled */
};

struct router_config {
    __u32 fwmark;
    __u32 enabled;
};

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 data;          /* Network byte order */
};

struct ipv6_lpm_key {
    __u32 prefixlen;
    union {
        __u32 data32[4]; /* Network byte order */
        __u8  data[16];  /* Network byte order */
    };
};

#endif /* __ROUTER_COMMON_H__ */
