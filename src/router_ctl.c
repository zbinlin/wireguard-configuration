#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "local_router.skel.h"

#define DEFAULT_PIN_DIR "/sys/fs/bpf/wg_routing"
#define DEFAULT_CGROUP_PATH "/sys/fs/cgroup"

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
    __u8  data[16];      /* Network byte order */
};

static char *trim(char *str) {
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

static int ensure_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        return -ENOTDIR;
    }
    if (mkdir(path, 0755) != 0) {
        return -errno;
    }
    return 0;
}

static int remove_pinned(const char *pin_dir, const char *name) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", pin_dir, name);
    if (unlink(path) != 0 && errno != ENOENT) {
        fprintf(stderr, "Warning: failed to unlink %s: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

static void range_to_cidrs(uint32_t start, uint32_t end, void (*cb)(uint32_t net_be, uint32_t prefixlen, void *arg), void *arg) {
    while (start <= end) {
        uint64_t max_size = start & (-start);
        if (max_size == 0) max_size = 0x100000000ULL;

        uint64_t diff = (uint64_t)end - start + 1;
        while (max_size > diff) {
            max_size >>= 1;
        }

        uint32_t prefixlen = 32 - __builtin_ctzll(max_size);
        cb(htonl(start), prefixlen, arg);

        if (start > UINT32_MAX - max_size) break;
        start += max_size;
    }
}

static int parse_endpoint(const char *str, struct wg_endpoint *ep) {
    memset(ep, 0, sizeof(*ep));
    if (!str || strlen(str) == 0) return -1;

    char buf[256];
    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *t = trim(buf);

    if (t[0] == '[') { // IPv6 in brackets: [addr] or [addr]:port
        char *close_bracket = strchr(t, ']');
        if (!close_bracket) {
            fprintf(stderr, "Error: Missing closing bracket ']' in IPv6 endpoint '%s'\n", str);
            return -1;
        }
        *close_bracket = '\0';
        char *ip_part = t + 1;
        char *port_part = close_bracket + 1;

        if (inet_pton(AF_INET6, ip_part, ep->ip6) != 1) {
            fprintf(stderr, "Error: Invalid IPv6 address '%s'\n", ip_part);
            return -1;
        }

        if (*port_part == ':') {
            port_part++;
            int port = atoi(port_part);
            if (port <= 0 || port > 65535) {
                fprintf(stderr, "Error: Invalid port '%s'\n", port_part);
                return -1;
            }
            ep->port = htons((uint16_t)port);
        } else if (*port_part == '\0') {
            ep->port = 0; // Any port
        } else {
            fprintf(stderr, "Error: Unexpected trailing characters in '%s'\n", str);
            return -1;
        }

        ep->family = 10; // AF_INET6
        ep->enabled = 1;
        return 0;
    }

    char *colon = strchr(t, ':');
    if (colon) {
        if (strchr(colon + 1, ':') != NULL) {
            // Multiple colons -> Plain IPv6 without port (e.g. 2001:db8::1)
            if (inet_pton(AF_INET6, t, ep->ip6) == 1) {
                ep->port = 0; // Any port
                ep->family = 10; // AF_INET6
                ep->enabled = 1;
                return 0;
            } else {
                fprintf(stderr, "Error: Invalid IPv6 address '%s'\n", str);
                return -1;
            }
        } else {
            // Exactly one colon -> IPv4 with port (e.g. 198.51.100.1:51820)
            *colon = '\0';
            char *ip_part = t;
            char *port_part = colon + 1;

            if (inet_pton(AF_INET, ip_part, &ep->ip4) != 1) {
                fprintf(stderr, "Error: Invalid IPv4 address '%s'\n", ip_part);
                return -1;
            }
            int port = atoi(port_part);
            if (port <= 0 || port > 65535) {
                fprintf(stderr, "Error: Invalid port '%s'\n", port_part);
                return -1;
            }
            ep->port = htons((uint16_t)port);
            ep->family = 2; // AF_INET
            ep->enabled = 1;
            return 0;
        }
    } else {
        // No colon -> Plain IPv4 without port (e.g. 198.51.100.1)
        if (inet_pton(AF_INET, t, &ep->ip4) == 1) {
            ep->port = 0; // Any port
            ep->family = 2; // AF_INET
            ep->enabled = 1;
            return 0;
        } else {
            fprintf(stderr, "Error: Invalid IPv4 address '%s'\n", str);
            return -1;
        }
    }
}

static int clear_lpm_map(int map_fd) {
    char key[64] = {0};
    int count = 0;
    while (bpf_map_get_next_key(map_fd, NULL, key) == 0) {
        if (bpf_map_delete_elem(map_fd, key) != 0) {
            break;
        }
        count++;
    }
    return count;
}

static int count_map_keys(int map_fd) {
    char key[64] = {0};
    char next_key[64] = {0};
    void *p_prev = NULL;
    int count = 0;
    while (bpf_map_get_next_key(map_fd, p_prev, next_key) == 0) {
        count++;
        memcpy(key, next_key, sizeof(key));
        p_prev = key;
    }
    return count;
}

struct v4_cb_arg {
    int fd;
    int count;
};

static void v4_cidr_cb(uint32_t net_be, uint32_t prefixlen, void *arg) {
    struct v4_cb_arg *ctx = (struct v4_cb_arg *)arg;
    struct ipv4_lpm_key key = {
        .prefixlen = prefixlen,
        .data = net_be,
    };
    uint8_t val = 1;
    if (bpf_map_update_elem(ctx->fd, &key, &val, BPF_ANY) == 0) {
        ctx->count++;
    }
}

static int apply_nft_rules(const char *rule_file, const char *wg_endpoint_str, const char *fwmark_override_str, const char *pin_dir) {
    FILE *f = fopen(rule_file, "r");
    if (!f) {
        fprintf(stderr, "Error: Failed to open rule file '%s': %s\n",
                rule_file, strerror(errno));
        return -1;
    }

    printf("[*] Opening pinned BPF maps at %s...\n", pin_dir);
    char path[512];
    snprintf(path, sizeof(path), "%s/router_config_map", pin_dir);
    int cfg_fd = bpf_obj_get(path);
    snprintf(path, sizeof(path), "%s/wg_endpoint_map", pin_dir);
    int ep_fd = bpf_obj_get(path);
    snprintf(path, sizeof(path), "%s/bypass_v4_map", pin_dir);
    int v4_fd = bpf_obj_get(path);
    snprintf(path, sizeof(path), "%s/bypass_v6_map", pin_dir);
    int v6_fd = bpf_obj_get(path);

    if (cfg_fd < 0 || ep_fd < 0 || v4_fd < 0 || v6_fd < 0) {
        fprintf(stderr, "Error: Failed to open pinned maps. Is the router loaded?\n");
        fclose(f);
        if (cfg_fd >= 0) close(cfg_fd);
        if (ep_fd >= 0) close(ep_fd);
        if (v4_fd >= 0) close(v4_fd);
        if (v6_fd >= 0) close(v6_fd);
        return -1;
    }

    uint32_t fwmark = 0x100;
    char file_endpoint[256] = {0};
    char line[512];
    int section = 0; // 0=none, 1=v4, 2=v6

    clear_lpm_map(v4_fd);
    clear_lpm_map(v6_fd);

    struct v4_cb_arg v4_ctx = { .fd = v4_fd, .count = 0 };
    int v6_count = 0;

    while (fgets(line, sizeof(line), f)) {
        char *p = strchr(line, '#');
        if (p) *p = '\0';
        char *t = trim(line);
        if (*t == '\0') continue;

        if (strncasecmp(t, "define FWMARK", 13) == 0) {
            char *eq = strchr(t, '=');
            if (eq) {
                fwmark = (uint32_t)strtoul(trim(eq + 1), NULL, 0);
            }
            continue;
        }

        if (strncasecmp(t, "define WG_ENDPOINT", 18) == 0) {
            char *eq = strchr(t, '=');
            if (eq) {
                char *v = trim(eq + 1);
                if (*v == '"' || *v == '\'') v++;
                char *end = v + strlen(v) - 1;
                if (end > v && (*end == '"' || *end == '\'')) *end = '\0';
                strncpy(file_endpoint, v, sizeof(file_endpoint)-1);
            }
            continue;
        }

        if (strcasestr(t, "IPV4_ELEMENTS") && strchr(t, '{')) {
            section = 1;
            continue;
        }
        if (strcasestr(t, "IPV6_ELEMENTS") && strchr(t, '{')) {
            section = 2;
            continue;
        }
        if (strchr(t, '}')) {
            section = 0;
            continue;
        }

        if (section == 1) { // IPv4
            char *comma = strchr(t, ',');
            if (comma) *comma = '\0';
            t = trim(t);
            if (*t == '\0') continue;

            if (strchr(t, '-')) {
                char s_ip[64] = {0}, e_ip[64] = {0};
                if (sscanf(t, "%63[^-]-%63s", s_ip, e_ip) == 2) {
                    uint32_t s = 0, e = 0;
                    if (inet_pton(AF_INET, trim(s_ip), &s) == 1 &&
                        inet_pton(AF_INET, trim(e_ip), &e) == 1) {
                        range_to_cidrs(ntohl(s), ntohl(e), v4_cidr_cb, &v4_ctx);
                    }
                }
            } else if (strchr(t, '/')) {
                char ip_str[64] = {0};
                uint32_t plen = 32;
                if (sscanf(t, "%63[^/]/%u", ip_str, &plen) == 2) {
                    uint32_t net = 0;
                    if (inet_pton(AF_INET, trim(ip_str), &net) == 1) {
                        v4_cidr_cb(net, plen, &v4_ctx);
                    }
                }
            } else {
                uint32_t net = 0;
                if (inet_pton(AF_INET, t, &net) == 1) {
                    v4_cidr_cb(net, 32, &v4_ctx);
                }
            }
        } else if (section == 2) { // IPv6
            char *comma = strchr(t, ',');
            if (comma) *comma = '\0';
            t = trim(t);
            if (*t == '\0') continue;

            char ip_str[64] = {0};
            uint32_t plen = 128;
            if (strchr(t, '/')) {
                sscanf(t, "%63[^/]/%u", ip_str, &plen);
            } else {
                strncpy(ip_str, t, sizeof(ip_str)-1);
            }
            struct ipv6_lpm_key k6 = { .prefixlen = plen };
            if (inet_pton(AF_INET6, trim(ip_str), k6.data) == 1) {
                uint8_t val = 1;
                if (bpf_map_update_elem(v6_fd, &k6, &val, BPF_ANY) == 0) {
                    v6_count++;
                }
            }
        }
    }
    fclose(f);

    if (fwmark_override_str) {
        fwmark = (uint32_t)strtoul(fwmark_override_str, NULL, 0);
    }

    /* 1. Update Config Map */
    uint32_t zero = 0;
    struct router_config cfg = {
        .fwmark = fwmark,
        .enabled = 1,
    };
    bpf_map_update_elem(cfg_fd, &zero, &cfg, BPF_ANY);
    printf("  -> Configured FWMARK: 0x%x (%u)\n", fwmark, fwmark);

    /* 2. Update WireGuard Endpoint */
    const char *target_ep = (wg_endpoint_str && strlen(wg_endpoint_str) > 0) ? wg_endpoint_str : file_endpoint;
    struct wg_endpoint ep;
    if (target_ep && strlen(target_ep) > 0 && parse_endpoint(target_ep, &ep) == 0) {
        bpf_map_update_elem(ep_fd, &zero, &ep, BPF_ANY);
        printf("  -> WireGuard Endpoint (Anti-loopback): %s\n", target_ep);
    } else {
        memset(&ep, 0, sizeof(ep));
        bpf_map_update_elem(ep_fd, &zero, &ep, BPF_ANY);
        printf("  -> WireGuard Endpoint: Disabled\n");
    }

    printf("  -> Loaded %d IPv4 CIDR rules into bypass_v4_map (including decomposed ranges)\n", v4_ctx.count);
    printf("  -> Loaded %d IPv6 CIDR rules into bypass_v6_map\n", v6_count);
    printf("[✔] Successfully applied all routing rules!\n");

    close(cfg_fd);
    close(ep_fd);
    close(v4_fd);
    close(v6_fd);
    return 0;
}

static int do_stop(const char *pin_dir) {
    printf("[*] Stopping eBPF router and cleaning up pinned objects at %s...\n", pin_dir);
    remove_pinned(pin_dir, "link_connect4");
    remove_pinned(pin_dir, "link_sendmsg4");
    remove_pinned(pin_dir, "link_connect6");
    remove_pinned(pin_dir, "link_sendmsg6");

    remove_pinned(pin_dir, "wg_endpoint_map");
    remove_pinned(pin_dir, "bypass_v4_map");
    remove_pinned(pin_dir, "bypass_v6_map");
    remove_pinned(pin_dir, "router_config_map");

    rmdir(pin_dir);
    printf("[✔] Successfully stopped and unpinned.\n");
    return 0;
}

static int do_start(const char *cgroup_path, const char *rule_file, const char *wg_endpoint, const char *fwmark, const char *pin_dir) {
    if (!rule_file) {
        fprintf(stderr, "Error: --rule-file is required for start.\n");
        return 1;
    }

    if (!cgroup_path) cgroup_path = DEFAULT_CGROUP_PATH;
    if (!pin_dir) pin_dir = DEFAULT_PIN_DIR;

    int cgroup_fd = open(cgroup_path, O_RDONLY | O_DIRECTORY);
    if (cgroup_fd < 0) {
        fprintf(stderr, "Error: Failed to open cgroup path '%s': %s\n", cgroup_path, strerror(errno));
        return 1;
    }

    if (ensure_dir(pin_dir) != 0) {
        fprintf(stderr, "Error: Failed to create bpffs dir %s: %s\n", pin_dir, strerror(errno));
        close(cgroup_fd);
        return 1;
    }

    /* Clean up any leftover pinned objects from previous runs */
    remove_pinned(pin_dir, "link_connect4");
    remove_pinned(pin_dir, "link_sendmsg4");
    remove_pinned(pin_dir, "link_connect6");
    remove_pinned(pin_dir, "link_sendmsg6");
    remove_pinned(pin_dir, "wg_endpoint_map");
    remove_pinned(pin_dir, "bypass_v4_map");
    remove_pinned(pin_dir, "bypass_v6_map");
    remove_pinned(pin_dir, "router_config_map");

    /* Also clean up any accidental root bpffs pins from earlier versions */
    unlink("/sys/fs/bpf/wg_endpoint_map");
    unlink("/sys/fs/bpf/bypass_v4_map");
    unlink("/sys/fs/bpf/bypass_v6_map");
    unlink("/sys/fs/bpf/router_config_map");

    struct local_router_bpf *skel = local_router_bpf__open();
    if (!skel) {
        fprintf(stderr, "Error: Failed to open BPF skeleton\n");
        close(cgroup_fd);
        return 1;
    }

    int err = local_router_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Error: Failed to load BPF skeleton: %d (%s)\n", err, strerror(-err));
        goto cleanup;
    }

    err = bpf_object__pin_maps(skel->obj, pin_dir);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Error: Failed to pin maps: %d\n", err);
        goto cleanup;
    }

    char link_path[512];
    skel->links.sock_connect4 = bpf_program__attach_cgroup(skel->progs.sock_connect4, cgroup_fd);
    if (!skel->links.sock_connect4) {
        fprintf(stderr, "Error: Failed to attach sock_connect4\n");
        err = -errno;
        goto cleanup;
    }
    snprintf(link_path, sizeof(link_path), "%s/link_connect4", pin_dir);
    bpf_link__pin(skel->links.sock_connect4, link_path);

    skel->links.sock_sendmsg4 = bpf_program__attach_cgroup(skel->progs.sock_sendmsg4, cgroup_fd);
    if (!skel->links.sock_sendmsg4) {
        fprintf(stderr, "Error: Failed to attach sock_sendmsg4\n");
        err = -errno;
        goto cleanup;
    }
    snprintf(link_path, sizeof(link_path), "%s/link_sendmsg4", pin_dir);
    bpf_link__pin(skel->links.sock_sendmsg4, link_path);

    skel->links.sock_connect6 = bpf_program__attach_cgroup(skel->progs.sock_connect6, cgroup_fd);
    if (!skel->links.sock_connect6) {
        fprintf(stderr, "Error: Failed to attach sock_connect6\n");
        err = -errno;
        goto cleanup;
    }
    snprintf(link_path, sizeof(link_path), "%s/link_connect6", pin_dir);
    bpf_link__pin(skel->links.sock_connect6, link_path);

    skel->links.sock_sendmsg6 = bpf_program__attach_cgroup(skel->progs.sock_sendmsg6, cgroup_fd);
    if (!skel->links.sock_sendmsg6) {
        fprintf(stderr, "Error: Failed to attach sock_sendmsg6\n");
        err = -errno;
        goto cleanup;
    }
    snprintf(link_path, sizeof(link_path), "%s/link_sendmsg6", pin_dir);
    bpf_link__pin(skel->links.sock_sendmsg6, link_path);

    printf("[+] Successfully loaded and attached eBPF programs to cgroup '%s'!\n", cgroup_path);

    /* Apply rules */
    err = apply_nft_rules(rule_file, wg_endpoint, fwmark, pin_dir);

cleanup:
    close(cgroup_fd);
    local_router_bpf__destroy(skel);
    return err ? 1 : 0;
}

static int do_set_endpoint(const char *endpoint_str, const char *pin_dir) {
    if (!pin_dir) pin_dir = DEFAULT_PIN_DIR;
    char path[512];
    snprintf(path, sizeof(path), "%s/wg_endpoint_map", pin_dir);
    int ep_fd = bpf_obj_get(path);
    if (ep_fd < 0) {
        fprintf(stderr, "Error: Failed to open wg_endpoint_map at %s. Is the router loaded?\n", pin_dir);
        return 1;
    }

    struct wg_endpoint ep;
    if (parse_endpoint(endpoint_str, &ep) != 0) {
        close(ep_fd);
        return 1;
    }

    uint32_t zero = 0;
    if (bpf_map_update_elem(ep_fd, &zero, &ep, BPF_ANY) != 0) {
        fprintf(stderr, "Error: Failed to update wg_endpoint_map: %s\n", strerror(errno));
        close(ep_fd);
        return 1;
    }
    close(ep_fd);
    printf("[✔] WireGuard anti-loopback endpoint updated to: %s\n", endpoint_str);
    return 0;
}

static int do_status(const char *pin_dir) {
    if (!pin_dir) pin_dir = DEFAULT_PIN_DIR;
    if (access(pin_dir, F_OK) != 0) {
        printf("[!] eBPF router is NOT running (Pinned directory %s does not exist).\n", pin_dir);
        return 0;
    }

    printf("[+] eBPF Router Status:\n");
    printf("  Pinned Directory: %s\n", pin_dir);

    char path[512];
    snprintf(path, sizeof(path), "%s/router_config_map", pin_dir);
    int cfg_fd = bpf_obj_get(path);
    if (cfg_fd >= 0) {
        uint32_t zero = 0;
        struct router_config cfg;
        if (bpf_map_lookup_elem(cfg_fd, &zero, &cfg) == 0) {
            printf("  Enabled: %s, FWMARK: 0x%x (%u)\n", cfg.enabled ? "true" : "false", cfg.fwmark, cfg.fwmark);
        }
        close(cfg_fd);
    }

    snprintf(path, sizeof(path), "%s/wg_endpoint_map", pin_dir);
    int ep_fd = bpf_obj_get(path);
    if (ep_fd >= 0) {
        uint32_t zero = 0;
        struct wg_endpoint ep;
        if (bpf_map_lookup_elem(ep_fd, &zero, &ep) == 0) {
            if (ep.enabled) {
                uint16_t port = ntohs(ep.port);
                if (ep.family == 2) {
                    char ip_buf[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &ep.ip4, ip_buf, sizeof(ip_buf));
                    if (port == 0) {
                        printf("  WireGuard Endpoint: %s (all ports)\n", ip_buf);
                    } else {
                        printf("  WireGuard Endpoint: %s:%u\n", ip_buf, port);
                    }
                } else {
                    char ip_buf[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, ep.ip6, ip_buf, sizeof(ip_buf));
                    if (port == 0) {
                        printf("  WireGuard Endpoint: [%s] (all ports)\n", ip_buf);
                    } else {
                        printf("  WireGuard Endpoint: [%s]:%u\n", ip_buf, port);
                    }
                }
            } else {
                printf("  WireGuard Endpoint: None\n");
            }
        }
        close(ep_fd);
    }

    snprintf(path, sizeof(path), "%s/bypass_v4_map", pin_dir);
    int v4_fd = bpf_obj_get(path);
    if (v4_fd >= 0) {
        printf("  Bypass IPv4 CIDRs in kernel map: %d\n", count_map_keys(v4_fd));
        close(v4_fd);
    }

    snprintf(path, sizeof(path), "%s/bypass_v6_map", pin_dir);
    int v6_fd = bpf_obj_get(path);
    if (v6_fd >= 0) {
        printf("  Bypass IPv6 CIDRs in kernel map: %d\n", count_map_keys(v6_fd));
        close(v6_fd);
    }

    return 0;
}

static void print_usage(const char *prog) {
    printf("Usage: %s <start|stop|reload|set-endpoint|status> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  start          Load eBPF, attach to cgroup, and apply nftables rules\n");
    printf("                 Options: --cgroup-path <path>    (default: /sys/fs/cgroup)\n");
    printf("                          --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n");
    printf("                          --wg-endpoint <IP[:Port]>\n");
    printf("                          --rule-file <var.nft>   (required)\n");
    printf("                          --fwmark <mark>         (optional override)\n\n");
    printf("  stop           Detach eBPF programs and remove pinned objects\n");
    printf("                 Options: --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n\n");
    printf("  reload         Hot-reload nftables rule file into BPF maps (no detach)\n");
    printf("                 Options: --rule-file <var.nft>   (required)\n");
    printf("                          --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n");
    printf("                          --wg-endpoint <IP[:Port]>\n");
    printf("                          --fwmark <mark>\n\n");
    printf("  set-endpoint   Dynamically update WireGuard endpoint (IP[:Port])\n");
    printf("                 Options: --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n");
    printf("                 Usage:   %s set-endpoint <IP[:Port]> [--pin-dir <path>]\n\n", prog);
    printf("  status         Show current eBPF router status and map statistics\n");
    printf("                 Options: --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];
    const char *pin_dir = DEFAULT_PIN_DIR;

    if (strcmp(cmd, "start") == 0 || strcmp(cmd, "load") == 0) {
        const char *cgroup_path = DEFAULT_CGROUP_PATH;
        const char *rule_file = NULL;
        const char *wg_endpoint = NULL;
        const char *fwmark = NULL;

        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--cgroup-path") == 0 && i + 1 < argc) {
                cgroup_path = argv[++i];
            } else if (strcmp(argv[i], "--pin-dir") == 0 && i + 1 < argc) {
                pin_dir = argv[++i];
            } else if (strcmp(argv[i], "--rule-file") == 0 && i + 1 < argc) {
                rule_file = argv[++i];
            } else if (strcmp(argv[i], "--wg-endpoint") == 0 && i + 1 < argc) {
                wg_endpoint = argv[++i];
            } else if (strcmp(argv[i], "--fwmark") == 0 && i + 1 < argc) {
                fwmark = argv[++i];
            } else {
                fprintf(stderr, "Unknown argument '%s'\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        }
        return do_start(cgroup_path, rule_file, wg_endpoint, fwmark, pin_dir);
    } else if (strcmp(cmd, "stop") == 0 || strcmp(cmd, "unload") == 0) {
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--pin-dir") == 0 && i + 1 < argc) {
                pin_dir = argv[++i];
            } else {
                fprintf(stderr, "Unknown argument '%s'\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        }
        return do_stop(pin_dir);
    } else if (strcmp(cmd, "reload") == 0 || strcmp(cmd, "apply") == 0) {
        const char *rule_file = NULL;
        const char *wg_endpoint = NULL;
        const char *fwmark = NULL;

        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--rule-file") == 0 && i + 1 < argc) {
                rule_file = argv[++i];
            } else if (strcmp(argv[i], "--pin-dir") == 0 && i + 1 < argc) {
                pin_dir = argv[++i];
            } else if (strcmp(argv[i], "--wg-endpoint") == 0 && i + 1 < argc) {
                wg_endpoint = argv[++i];
            } else if (strcmp(argv[i], "--fwmark") == 0 && i + 1 < argc) {
                fwmark = argv[++i];
            } else {
                fprintf(stderr, "Unknown argument '%s'\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        }
        if (!rule_file) {
            fprintf(stderr, "Error: --rule-file is required for reload.\n");
            return 1;
        }
        return apply_nft_rules(rule_file, wg_endpoint, fwmark, pin_dir);
    } else if (strcmp(cmd, "set-endpoint") == 0) {
        const char *ep_str = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--pin-dir") == 0 && i + 1 < argc) {
                pin_dir = argv[++i];
            } else if (!ep_str && argv[i][0] != '-') {
                ep_str = argv[i];
            } else {
                fprintf(stderr, "Unknown argument '%s'\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        }
        if (!ep_str) {
            fprintf(stderr, "Error: missing endpoint argument. Usage: %s set-endpoint <IP[:Port]> [--pin-dir <path>]\n", argv[0]);
            return 1;
        }
        return do_set_endpoint(ep_str, pin_dir);
    } else if (strcmp(cmd, "status") == 0) {
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--pin-dir") == 0 && i + 1 < argc) {
                pin_dir = argv[++i];
            } else {
                fprintf(stderr, "Unknown argument '%s'\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        }
        return do_status(pin_dir);
    } else {
        fprintf(stderr, "Unknown command '%s'\n", cmd);
        print_usage(argv[0]);
        return 1;
    }
}
