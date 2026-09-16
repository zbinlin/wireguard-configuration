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
#include <net/if.h>
#include <stdarg.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "router_common.h"
#include "local_router.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG && !getenv("LIBBPF_DEBUG"))
        return 0;

    char buf[512];
    va_list args_copy;
    va_copy(args_copy, args);
    vsnprintf(buf, sizeof(buf), format, args_copy);
    va_end(args_copy);

    /* "Exclusivity flag on, cannot modify" is sent via netlink extack when clsact qdisc
     * already exists on the interface during bpf_tc_hook_create(). It is benign and expected. */
    if (strstr(buf, "Exclusivity flag on, cannot modify")) {
        return 0;
    }

    return vfprintf(stderr, format, args);
}

struct lan_ifaces {
    char names[MAX_LAN_IFACES][IFNAMSIZ];
    int count;
};

static char *trim(char *str) {
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

static void add_lan_iface(struct lan_ifaces *list, const char *arg) {
    if (!arg || !list) return;
    char buf[256];
    strncpy(buf, arg, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *saveptr = NULL;
    char *tok = strtok_r(buf, " ,\t", &saveptr);
    while (tok) {
        char *name = trim(tok);
        if (*name) {
            bool exists = false;
            for (int i = 0; i < list->count; i++) {
                if (strcmp(list->names[i], name) == 0) {
                    exists = true;
                    break;
                }
            }
            if (!exists && list->count < MAX_LAN_IFACES) {
                strncpy(list->names[list->count], name, IFNAMSIZ - 1);
                list->names[list->count][IFNAMSIZ - 1] = '\0';
                list->count++;
            }
        }
        tok = strtok_r(NULL, " ,\t", &saveptr);
    }
}

static void remove_lan_iface(struct lan_ifaces *list, const char *arg) {
    if (!arg || !list) return;
    char buf[256];
    strncpy(buf, arg, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *saveptr = NULL;
    char *tok = strtok_r(buf, " ,\t", &saveptr);
    while (tok) {
        char *name = trim(tok);
        if (*name) {
            for (int i = 0; i < list->count; i++) {
                if (strcmp(list->names[i], name) == 0) {
                    for (int j = i; j < list->count - 1; j++) {
                        memcpy(list->names[j], list->names[j + 1], IFNAMSIZ);
                    }
                    list->count--;
                    i--;
                }
            }
        }
        tok = strtok_r(NULL, " ,\t", &saveptr);
    }
}

static void save_lan_ifaces(const char *pin_dir, const struct lan_ifaces *list) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", pin_dir, LAN_IFACES_FILENAME);
    if (!list || list->count == 0) {
        unlink(path);
        return;
    }
    FILE *f = fopen(path, "w");
    if (!f) return;
    for (int i = 0; i < list->count; i++) {
        fprintf(f, "%s\n", list->names[i]);
    }
    fclose(f);
}

static void load_lan_ifaces(const char *pin_dir, struct lan_ifaces *list) {
    list->count = 0;
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", pin_dir, LAN_IFACES_FILENAME);
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        char *t = trim(line);
        if (*t && list->count < MAX_LAN_IFACES) {
            strncpy(list->names[list->count], t, IFNAMSIZ - 1);
            list->names[list->count][IFNAMSIZ - 1] = '\0';
            list->count++;
        }
    }
    fclose(f);
}

static int tc_attach_interface(int prog_fd, const char *ifname) {
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Error: Network interface '%s' not found: %s\n", ifname, strerror(errno));
        return -1;
    }

    /* 1. Create clsact qdisc/hook on the interface */
    struct bpf_tc_hook hook = {
        .sz = sizeof(hook),
        .ifindex = (int)ifindex,
        .attach_point = BPF_TC_INGRESS,
    };
    int err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Error: Failed to create TC clsact hook on %s: %d (%s)\n",
                ifname, err, strerror(-err));
        return -1;
    }

    /* 2. Attach TC ingress filter */
    struct bpf_tc_opts opts = {
        .sz = sizeof(opts),
        .prog_fd = prog_fd,
        .flags = BPF_TC_F_REPLACE,
    };
    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        fprintf(stderr, "Error: Failed to attach TC ingress filter to %s: %d (%s)\n",
                ifname, err, strerror(-err));
        return -1;
    }

    printf("[+] Successfully attached TC ingress filter to '%s' (idx %u)!\n", ifname, ifindex);
    return 0;
}

static int tc_detach_interface(const char *ifname) {
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        return 0;
    }

    struct bpf_tc_hook hook = {
        .sz = sizeof(hook),
        .ifindex = (int)ifindex,
        .attach_point = BPF_TC_INGRESS,
    };
    int err = bpf_tc_hook_destroy(&hook);
    if (err && err != -ENOENT) {
        struct bpf_tc_opts opts = {
            .sz = sizeof(opts),
            .prog_id = 0,
        };
        bpf_tc_detach(&hook, &opts);
    }
    return 0;
}

static bool is_tc_ingress_attached(const char *ifname) {
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        return false;
    }

    struct bpf_tc_hook hook = {
        .sz = sizeof(hook),
        .ifindex = (int)ifindex,
        .attach_point = BPF_TC_INGRESS,
    };
    struct bpf_tc_opts opts = {
        .sz = sizeof(opts),
    };
    return bpf_tc_query(&hook, &opts) == 0;
}

static int ensure_dir(const char *path) {
    if (!path || !*path) return -EINVAL;
    char tmp[512];
    size_t len = strnlen(path, sizeof(tmp));
    if (len >= sizeof(tmp)) return -ENAMETOOLONG;
    memcpy(tmp, path, len + 1);

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                struct stat st;
                if (stat(tmp, &st) != 0 || !S_ISDIR(st.st_mode))
                    return -errno;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        struct stat st;
        if (stat(tmp, &st) != 0 || !S_ISDIR(st.st_mode))
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

static int parse_port(const char *port_str, uint16_t *out_port) {
    if (!port_str) return -1;
    while (isspace((unsigned char)*port_str)) port_str++;
    if (*port_str == '\0') return -1;

    char *endptr = NULL;
    errno = 0;
    long val = strtol(port_str, &endptr, 10);
    if (errno != 0 || endptr == port_str) {
        return -1;
    }
    while (isspace((unsigned char)*endptr)) endptr++;
    if (*endptr != '\0') {
        return -1;
    }
    if (val <= 0 || val > 65535) {
        return -1;
    }
    *out_port = (uint16_t)val;
    return 0;
}

static int parse_fwmark(const char *str, uint32_t *out_mark) {
    if (!str) return -1;
    while (isspace((unsigned char)*str)) str++;
    if (*str == '\0') return -1;

    char *endptr = NULL;
    errno = 0;
    unsigned long val = strtoul(str, &endptr, 0);
    if (errno != 0 || endptr == str) {
        return -1;
    }
    while (isspace((unsigned char)*endptr)) endptr++;
    if (*endptr != '\0') {
        return -1;
    }
    if (val == 0 || val > UINT32_MAX) {
        return -1; /* fwmark = 0 is invalid / unsafe (causes traffic leak) */
    }
    *out_mark = (uint32_t)val;
    return 0;
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
            uint16_t port = 0;
            if (parse_port(port_part, &port) != 0) {
                fprintf(stderr, "Error: Invalid port '%s' in endpoint '%s'\n", port_part, str);
                return -1;
            }
            ep->port = htons(port);
        } else if (*port_part == '\0') {
            ep->port = 0; // Any port
        } else {
            fprintf(stderr, "Error: Unexpected trailing characters in endpoint '%s'\n", str);
            return -1;
        }

        ep->family = AF_INET6;
        ep->enabled = 1;
        return 0;
    }

    char *colon = strchr(t, ':');
    if (colon) {
        if (strchr(colon + 1, ':') != NULL) {
            // Multiple colons -> Plain IPv6 without port (e.g. 2001:db8::1)
            if (inet_pton(AF_INET6, t, ep->ip6) == 1) {
                ep->port = 0; // Any port
                ep->family = AF_INET6;
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
            uint16_t port = 0;
            if (parse_port(port_part, &port) != 0) {
                fprintf(stderr, "Error: Invalid port '%s' in endpoint '%s'\n", port_part, str);
                return -1;
            }
            ep->port = htons(port);
            ep->family = AF_INET;
            ep->enabled = 1;
            return 0;
        }
    } else {
        // No colon -> Plain IPv4 without port (e.g. 198.51.100.1)
        if (inet_pton(AF_INET, t, &ep->ip4) == 1) {
            ep->port = 0; // Any port
            ep->family = AF_INET;
            ep->enabled = 1;
            return 0;
        } else {
            fprintf(stderr, "Error: Invalid IPv4 address '%s'\n", str);
            return -1;
        }
    }
}

static bool match_keyword(const char *str, const char *keyword) {
    size_t kwlen = strlen(keyword);
    if (strncasecmp(str, keyword, kwlen) != 0)
        return false;
    char next = str[kwlen];
    return (next == '\0' || isspace((unsigned char)next) || next == '=');
}

static const char *find_element_block(const char *line, const char *name) {
    size_t name_len = strlen(name);
    const char *p = line;
    while ((p = strcasestr(p, name)) != NULL) {
        if (p > line && (isalnum((unsigned char)*(p - 1)) || *(p - 1) == '_')) {
            p += name_len;
            continue;
        }
        char after = *(p + name_len);
        if (after != '\0' && (isalnum((unsigned char)after) || after == '_')) {
            p += name_len;
            continue;
        }
        return p;
    }
    return NULL;
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

struct rule_collector {
    uint32_t fwmark;
    bool has_fwmark;
    char endpoint[256];
    bool has_endpoint;

    struct ipv4_lpm_key *v4_keys;
    size_t v4_count;
    size_t v4_cap;

    struct ipv6_lpm_key *v6_keys;
    size_t v6_count;
    size_t v6_cap;
};

static void v4_collect_cb(uint32_t net_be, uint32_t prefixlen, void *arg) {
    struct rule_collector *rc = (struct rule_collector *)arg;
    if (rc->v4_count >= rc->v4_cap) {
        size_t new_cap = rc->v4_cap ? rc->v4_cap * 2 : 64;
        struct ipv4_lpm_key *new_keys = realloc(rc->v4_keys, new_cap * sizeof(*new_keys));
        if (!new_keys) return;
        rc->v4_keys = new_keys;
        rc->v4_cap = new_cap;
    }
    rc->v4_keys[rc->v4_count].prefixlen = prefixlen;
    rc->v4_keys[rc->v4_count].data = net_be;
    rc->v4_count++;
}

static int add_v6_rule(struct rule_collector *rc, const uint8_t *ip6_bytes, uint32_t prefixlen) {
    if (rc->v6_count >= rc->v6_cap) {
        size_t new_cap = rc->v6_cap ? rc->v6_cap * 2 : 64;
        struct ipv6_lpm_key *new_keys = realloc(rc->v6_keys, new_cap * sizeof(*new_keys));
        if (!new_keys) return -1;
        rc->v6_keys = new_keys;
        rc->v6_cap = new_cap;
    }
    rc->v6_keys[rc->v6_count].prefixlen = prefixlen;
    memcpy(rc->v6_keys[rc->v6_count].data, ip6_bytes, 16);
    rc->v6_count++;
    return 0;
}

static void free_rule_collector(struct rule_collector *rc) {
    free(rc->v4_keys);
    free(rc->v6_keys);
    rc->v4_keys = NULL;
    rc->v6_keys = NULL;
    rc->v4_count = rc->v4_cap = 0;
    rc->v6_count = rc->v6_cap = 0;
}

static int parse_rule_file(const char *rule_file, struct rule_collector *rc) {
    FILE *f = fopen(rule_file, "r");
    if (!f) {
        fprintf(stderr, "Error: Failed to open rule file '%s': %s\n",
                rule_file, strerror(errno));
        return -1;
    }

    rc->fwmark = DEFAULT_FWMARK;
    char line[512];
    int line_num = 0;
    int section = 0; // 0=none, 1=v4, 2=v6

    while (fgets(line, sizeof(line), f)) {
        line_num++;
        char *p = strchr(line, '#');
        if (p) *p = '\0';
        char *t = trim(line);
        if (*t == '\0') continue;

        if (section == 0) {
            if (match_keyword(t, "define FWMARK")) {
                char *eq = strchr(t, '=');
                if (!eq) {
                    fprintf(stderr, "Error [line %d]: Malformed FWMARK definition (missing '='): %s\n", line_num, t);
                    fclose(f);
                    return -1;
                }
                char *v = trim(eq + 1);
                if (parse_fwmark(v, &rc->fwmark) != 0) {
                    fprintf(stderr, "Error [line %d]: Invalid or zero FWMARK value '%s'. A non-zero FWMARK is strictly required to prevent traffic leaks.\n", line_num, v);
                    fclose(f);
                    return -1;
                }
                rc->has_fwmark = true;
                continue;
            }

            if (match_keyword(t, "define WG_ENDPOINT")) {
                char *eq = strchr(t, '=');
                if (!eq) {
                    fprintf(stderr, "Error [line %d]: Malformed WG_ENDPOINT definition (missing '='): %s\n", line_num, t);
                    fclose(f);
                    return -1;
                }
                char *v = trim(eq + 1);
                if (*v == '"' || *v == '\'') v++;
                char *end = v + strlen(v) - 1;
                if (end > v && (*end == '"' || *end == '\'')) *end = '\0';
                v = trim(v);
                struct wg_endpoint tmp_ep;
                if (parse_endpoint(v, &tmp_ep) != 0) {
                    fprintf(stderr, "Error [line %d]: Invalid WG_ENDPOINT '%s'\n", line_num, v);
                    fclose(f);
                    return -1;
                }
                strncpy(rc->endpoint, v, sizeof(rc->endpoint) - 1);
                rc->has_endpoint = true;
                continue;
            }

            const char *blk_v4 = find_element_block(t, "IPV4_ELEMENTS");
            const char *blk_v6 = find_element_block(t, "IPV6_ELEMENTS");
            if (blk_v4) {
                const char *ob = strchr(blk_v4, '{');
                if (!ob) {
                    fprintf(stderr, "Error [line %d]: Missing '{' in IPV4_ELEMENTS definition\n", line_num);
                    fclose(f);
                    return -1;
                }
                section = 1;
                t = (char *)(ob + 1);
            } else if (blk_v6) {
                const char *ob = strchr(blk_v6, '{');
                if (!ob) {
                    fprintf(stderr, "Error [line %d]: Missing '{' in IPV6_ELEMENTS definition\n", line_num);
                    fclose(f);
                    return -1;
                }
                section = 2;
                t = (char *)(ob + 1);
            } else {
                continue;
            }
        }

        if (section != 0) {
            int cur_section = section;
            char *cb = strchr(t, '}');
            if (cb) {
                *cb = '\0';
                section = 0;
            }

            char *saveptr = NULL;
            char *token = strtok_r(t, " ,\t\r\n", &saveptr);
            while (token) {
                if (cur_section == 1) { // IPv4
                    if (strchr(token, '-')) {
                        char s_ip[64] = {0}, e_ip[64] = {0};
                        if (sscanf(token, "%63[^-]-%63s", s_ip, e_ip) != 2) {
                            fprintf(stderr, "Error [line %d]: Malformed IPv4 range '%s'\n", line_num, token);
                            fclose(f);
                            return -1;
                        }
                        uint32_t s = 0, e = 0;
                        if (inet_pton(AF_INET, trim(s_ip), &s) != 1) {
                            fprintf(stderr, "Error [line %d]: Invalid start IP '%s' in range '%s'\n", line_num, s_ip, token);
                            fclose(f);
                            return -1;
                        }
                        if (inet_pton(AF_INET, trim(e_ip), &e) != 1) {
                            fprintf(stderr, "Error [line %d]: Invalid end IP '%s' in range '%s'\n", line_num, e_ip, token);
                            fclose(f);
                            return -1;
                        }
                        if (ntohl(s) > ntohl(e)) {
                            fprintf(stderr, "Error [line %d]: Inverted IPv4 range '%s' (start > end)\n", line_num, token);
                            fclose(f);
                            return -1;
                        }
                        range_to_cidrs(ntohl(s), ntohl(e), v4_collect_cb, rc);
                    } else if (strchr(token, '/')) {
                        char ip_str[64] = {0};
                        uint32_t plen = 32;
                        if (sscanf(token, "%63[^/]/%u", ip_str, &plen) != 2) {
                            fprintf(stderr, "Error [line %d]: Malformed IPv4 CIDR '%s'\n", line_num, token);
                            fclose(f);
                            return -1;
                        }
                        if (plen > 32) {
                            fprintf(stderr, "Error [line %d]: Invalid IPv4 prefix length /%u in '%s'\n", line_num, plen, token);
                            fclose(f);
                            return -1;
                        }
                        uint32_t net = 0;
                        if (inet_pton(AF_INET, trim(ip_str), &net) != 1) {
                            fprintf(stderr, "Error [line %d]: Invalid IPv4 address '%s' in '%s'\n", line_num, ip_str, token);
                            fclose(f);
                            return -1;
                        }
                        v4_collect_cb(net, plen, rc);
                    } else {
                        uint32_t net = 0;
                        if (inet_pton(AF_INET, token, &net) != 1) {
                            fprintf(stderr, "Error [line %d]: Invalid IPv4 address '%s'\n", line_num, token);
                            fclose(f);
                            return -1;
                        }
                        v4_collect_cb(net, 32, rc);
                    }
                } else if (cur_section == 2) { // IPv6
                    char ip_str[64] = {0};
                    uint32_t plen = 128;
                    if (strchr(token, '/')) {
                        if (sscanf(token, "%63[^/]/%u", ip_str, &plen) != 2) {
                            fprintf(stderr, "Error [line %d]: Malformed IPv6 CIDR '%s'\n", line_num, token);
                            fclose(f);
                            return -1;
                        }
                        if (plen > 128) {
                            fprintf(stderr, "Error [line %d]: Invalid IPv6 prefix length /%u in '%s'\n", line_num, plen, token);
                            fclose(f);
                            return -1;
                        }
                    } else {
                        strncpy(ip_str, token, sizeof(ip_str) - 1);
                    }
                    uint8_t ip6_buf[16] = {0};
                    if (inet_pton(AF_INET6, trim(ip_str), ip6_buf) != 1) {
                        fprintf(stderr, "Error [line %d]: Invalid IPv6 address '%s'\n", line_num, ip_str);
                        fclose(f);
                        return -1;
                    }
                    if (add_v6_rule(rc, ip6_buf, plen) != 0) {
                        fprintf(stderr, "Error: Memory allocation failure while parsing IPv6 rules\n");
                        fclose(f);
                        return -1;
                    }
                }
                token = strtok_r(NULL, " ,\t\r\n", &saveptr);
            }
        }
    }

    fclose(f);

    if (section != 0) {
        fprintf(stderr, "Error: Unexpected EOF while parsing element block (missing closing '}')\n");
        return -1;
    }

    return 0;
}

static int do_stop(const char *pin_dir, const struct lan_ifaces *cli_lan_ifaces) {
    if (!pin_dir) pin_dir = DEFAULT_PIN_DIR;
    printf("[*] Stopping eBPF router and cleaning up pinned objects at %s...\n", pin_dir);

    /* 1. Detach TC ingress from all LAN interfaces (both saved and CLI specified) */
    struct lan_ifaces saved_list = {0};
    load_lan_ifaces(pin_dir, &saved_list);
    for (int i = 0; i < saved_list.count; i++) {
        tc_detach_interface(saved_list.names[i]);
    }
    if (cli_lan_ifaces) {
        for (int i = 0; i < cli_lan_ifaces->count; i++) {
            tc_detach_interface(cli_lan_ifaces->names[i]);
        }
    }
    char lan_path[512];
    snprintf(lan_path, sizeof(lan_path), "%s/%s", pin_dir, LAN_IFACES_FILENAME);
    unlink(lan_path);

    /* 2. Unpin TC ingress program */
    remove_pinned(pin_dir, TC_PROG_FILENAME);

    /* 3. Unpin cgroup links and maps */
    remove_pinned(pin_dir, "link_connect4");
    remove_pinned(pin_dir, "link_sendmsg4");
    remove_pinned(pin_dir, "link_connect6");
    remove_pinned(pin_dir, "link_sendmsg6");

    remove_pinned(pin_dir, "wg_endpoint_map");
    remove_pinned(pin_dir, "bypass_v4_map");
    remove_pinned(pin_dir, "bypass_v6_map");
    remove_pinned(pin_dir, "router_config_map");

    if (access(pin_dir, F_OK) == 0) {
        if (rmdir(pin_dir) != 0 && errno != ENOENT) {
            fprintf(stderr, "Warning: failed to remove directory '%s': %s\n", pin_dir, strerror(errno));
        }
    }
    printf("[✔] Successfully stopped and unpinned.\n");
    return 0;
}

static int apply_nft_rules(const char *rule_file, const char *wg_endpoint_str, const char *fwmark_override_str, const char *pin_dir) {
    struct rule_collector rc = {0};

    if (parse_rule_file(rule_file, &rc) != 0) {
        free_rule_collector(&rc);
        return -1;
    }

    if (fwmark_override_str) {
        if (parse_fwmark(fwmark_override_str, &rc.fwmark) != 0) {
            fprintf(stderr, "Error: Invalid or zero --fwmark override '%s'. A non-zero FWMARK is strictly required.\n", fwmark_override_str);
            free_rule_collector(&rc);
            return -1;
        }
    }

    const char *target_ep = (wg_endpoint_str && strlen(wg_endpoint_str) > 0) ? wg_endpoint_str : (rc.has_endpoint ? rc.endpoint : NULL);
    struct wg_endpoint ep;
    bool has_valid_ep = false;
    if (target_ep && strlen(target_ep) > 0) {
        if (parse_endpoint(target_ep, &ep) != 0) {
            fprintf(stderr, "Error: Invalid WireGuard endpoint '%s'\n", target_ep);
            free_rule_collector(&rc);
            return -1;
        }
        has_valid_ep = true;
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
        if (cfg_fd >= 0) close(cfg_fd);
        if (ep_fd >= 0) close(ep_fd);
        if (v4_fd >= 0) close(v4_fd);
        if (v6_fd >= 0) close(v6_fd);
        free_rule_collector(&rc);
        return -1;
    }

    clear_lpm_map(v4_fd);
    clear_lpm_map(v6_fd);

    int v4_loaded = 0;
    for (size_t i = 0; i < rc.v4_count; i++) {
        uint8_t val = 1;
        if (bpf_map_update_elem(v4_fd, &rc.v4_keys[i], &val, BPF_ANY) == 0) {
            v4_loaded++;
        }
    }

    int v6_loaded = 0;
    for (size_t i = 0; i < rc.v6_count; i++) {
        uint8_t val = 1;
        if (bpf_map_update_elem(v6_fd, &rc.v6_keys[i], &val, BPF_ANY) == 0) {
            v6_loaded++;
        }
    }

    /* 1. Update Config Map */
    uint32_t zero = 0;
    struct router_config cfg = {
        .fwmark = rc.fwmark,
        .enabled = 1,
    };
    bpf_map_update_elem(cfg_fd, &zero, &cfg, BPF_ANY);
    printf("  -> Configured FWMARK: 0x%x (%u)\n", rc.fwmark, rc.fwmark);

    /* 2. Update WireGuard Endpoint */
    if (has_valid_ep) {
        bpf_map_update_elem(ep_fd, &zero, &ep, BPF_ANY);
        printf("  -> WireGuard Endpoint (Anti-loopback): %s\n", target_ep);
    } else {
        memset(&ep, 0, sizeof(ep));
        bpf_map_update_elem(ep_fd, &zero, &ep, BPF_ANY);
        printf("  -> WireGuard Endpoint: Disabled\n");
    }

    printf("  -> Loaded %d IPv4 CIDR rules into bypass_v4_map (including decomposed ranges)\n", v4_loaded);
    printf("  -> Loaded %d IPv6 CIDR rules into bypass_v6_map\n", v6_loaded);
    printf("[✔] Successfully applied all routing rules!\n");

    close(cfg_fd);
    close(ep_fd);
    close(v4_fd);
    close(v6_fd);
    free_rule_collector(&rc);
    return 0;
}

static int do_start(const char *cgroup_path, const char *rule_file, const char *wg_endpoint, const char *fwmark, const char *pin_dir, const struct lan_ifaces *lan_list) {
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

    int err = ensure_dir(pin_dir);
    if (err != 0) {
        fprintf(stderr, "Error: Failed to create bpffs dir %s: %s\n", pin_dir, strerror(-err));
        close(cgroup_fd);
        return 1;
    }

    /* Clean up any leftover pinned objects and TC filters from previous runs */
    do_stop(pin_dir, lan_list);

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

    err = local_router_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Error: Failed to load BPF skeleton: %d (%s)\n", err, strerror(-err));
        close(cgroup_fd);
        local_router_bpf__destroy(skel);
        return 1;
    }

    err = bpf_object__pin_maps(skel->obj, pin_dir);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Error: Failed to pin maps: %d\n", err);
        goto cleanup_rollback;
    }

    /* Pin TC ingress program to allow dynamic add-if / del-if later */
    char prog_path[512];
    snprintf(prog_path, sizeof(prog_path), "%s/%s", pin_dir, TC_PROG_FILENAME);
    unlink(prog_path);
    err = bpf_program__pin(skel->progs.tc_router_ingress, prog_path);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Error: Failed to pin TC ingress program: %d\n", err);
        goto cleanup_rollback;
    }

    char link_path[512];
    skel->links.sock_connect4 = bpf_program__attach_cgroup(skel->progs.sock_connect4, cgroup_fd);
    if (!skel->links.sock_connect4) {
        fprintf(stderr, "Error: Failed to attach sock_connect4\n");
        err = -errno;
        goto cleanup_rollback;
    }
    snprintf(link_path, sizeof(link_path), "%s/link_connect4", pin_dir);
    err = bpf_link__pin(skel->links.sock_connect4, link_path);
    if (err) {
        fprintf(stderr, "Error: Failed to pin sock_connect4: %d\n", err);
        goto cleanup_rollback;
    }

    skel->links.sock_sendmsg4 = bpf_program__attach_cgroup(skel->progs.sock_sendmsg4, cgroup_fd);
    if (!skel->links.sock_sendmsg4) {
        fprintf(stderr, "Error: Failed to attach sock_sendmsg4\n");
        err = -errno;
        goto cleanup_rollback;
    }
    snprintf(link_path, sizeof(link_path), "%s/link_sendmsg4", pin_dir);
    err = bpf_link__pin(skel->links.sock_sendmsg4, link_path);
    if (err) {
        fprintf(stderr, "Error: Failed to pin sock_sendmsg4: %d\n", err);
        goto cleanup_rollback;
    }

    skel->links.sock_connect6 = bpf_program__attach_cgroup(skel->progs.sock_connect6, cgroup_fd);
    if (!skel->links.sock_connect6) {
        fprintf(stderr, "Error: Failed to attach sock_connect6\n");
        err = -errno;
        goto cleanup_rollback;
    }
    snprintf(link_path, sizeof(link_path), "%s/link_connect6", pin_dir);
    err = bpf_link__pin(skel->links.sock_connect6, link_path);
    if (err) {
        fprintf(stderr, "Error: Failed to pin sock_connect6: %d\n", err);
        goto cleanup_rollback;
    }

    skel->links.sock_sendmsg6 = bpf_program__attach_cgroup(skel->progs.sock_sendmsg6, cgroup_fd);
    if (!skel->links.sock_sendmsg6) {
        fprintf(stderr, "Error: Failed to attach sock_sendmsg6\n");
        err = -errno;
        goto cleanup_rollback;
    }
    snprintf(link_path, sizeof(link_path), "%s/link_sendmsg6", pin_dir);
    err = bpf_link__pin(skel->links.sock_sendmsg6, link_path);
    if (err) {
        fprintf(stderr, "Error: Failed to pin sock_sendmsg6: %d\n", err);
        goto cleanup_rollback;
    }

    printf("[+] Successfully loaded and attached eBPF programs to cgroup '%s'!\n", cgroup_path);

    /* Attach TC ingress on specified LAN interfaces */
    int tc_attached_count = 0;
    if (lan_list && lan_list->count > 0) {
        int tc_prog_fd = bpf_program__fd(skel->progs.tc_router_ingress);
        for (int i = 0; i < lan_list->count; i++) {
            if (tc_attach_interface(tc_prog_fd, lan_list->names[i]) != 0) {
                err = -1;
                goto cleanup_rollback;
            }
            tc_attached_count++;
        }
        save_lan_ifaces(pin_dir, lan_list);
        printf("[+] Attached TC ingress filter to %d LAN interface(s) for forwarded traffic!\n", tc_attached_count);
    }

    /* Apply rules */
    err = apply_nft_rules(rule_file, wg_endpoint, fwmark, pin_dir);
    if (err) {
        fprintf(stderr, "Error: Failed to apply routing rules from '%s'\n", rule_file);
        goto cleanup_rollback;
    }

    close(cgroup_fd);
    local_router_bpf__destroy(skel);
    return 0;

cleanup_rollback:
    fprintf(stderr, "[!] Start failed; rolling back and cleaning up pinned objects at %s...\n", pin_dir);
    do_stop(pin_dir, lan_list);
    close(cgroup_fd);
    local_router_bpf__destroy(skel);
    return 1;
}

static int do_add_if(const char *if_str, const char *pin_dir) {
    if (!pin_dir) pin_dir = DEFAULT_PIN_DIR;
    char prog_path[512];
    snprintf(prog_path, sizeof(prog_path), "%s/%s", pin_dir, TC_PROG_FILENAME);
    int prog_fd = bpf_obj_get(prog_path);
    if (prog_fd < 0) {
        fprintf(stderr, "Error: Router is not running or TC ingress program not found at %s. Is the router loaded?\n",
                prog_path);
        return 1;
    }

    struct lan_ifaces cur_list = {0};
    load_lan_ifaces(pin_dir, &cur_list);

    struct lan_ifaces to_add = {0};
    add_lan_iface(&to_add, if_str);

    if (to_add.count == 0) {
        fprintf(stderr, "Error: No valid interface names specified.\n");
        close(prog_fd);
        return 1;
    }

    int success_count = 0;
    for (int i = 0; i < to_add.count; i++) {
        if (tc_attach_interface(prog_fd, to_add.names[i]) == 0) {
            add_lan_iface(&cur_list, to_add.names[i]);
            success_count++;
        }
    }

    close(prog_fd);
    save_lan_ifaces(pin_dir, &cur_list);

    if (success_count > 0) {
        printf("[✔] Successfully attached TC filter to and saved %d LAN interface(s)!\n", success_count);
        return 0;
    }
    return 1;
}

static int do_del_if(const char *if_str, const char *pin_dir) {
    if (!pin_dir) pin_dir = DEFAULT_PIN_DIR;

    struct lan_ifaces cur_list = {0};
    load_lan_ifaces(pin_dir, &cur_list);

    struct lan_ifaces to_del = {0};
    add_lan_iface(&to_del, if_str);

    if (to_del.count == 0) {
        fprintf(stderr, "Error: No valid interface names specified.\n");
        return 1;
    }

    for (int i = 0; i < to_del.count; i++) {
        tc_detach_interface(to_del.names[i]);
        remove_lan_iface(&cur_list, to_del.names[i]);
        printf("[-] Detached TC ingress filter from '%s'\n", to_del.names[i]);
    }

    save_lan_ifaces(pin_dir, &cur_list);
    printf("[✔] Successfully detached and removed %d LAN interface(s)!\n", to_del.count);
    return 0;
}

static int do_set_endpoint(const char *endpoint_str, const char *pin_dir) {
    if (!pin_dir) pin_dir = DEFAULT_PIN_DIR;

    struct wg_endpoint ep;
    if (parse_endpoint(endpoint_str, &ep) != 0) {
        return 1;
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/wg_endpoint_map", pin_dir);
    int ep_fd = bpf_obj_get(path);
    if (ep_fd < 0) {
        fprintf(stderr, "Error: Failed to open wg_endpoint_map at %s. Is the router loaded?\n", pin_dir);
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

    /* Show attached LAN interfaces and their live kernel state */
    struct lan_ifaces lan_list = {0};
    load_lan_ifaces(pin_dir, &lan_list);
    if (lan_list.count > 0) {
        printf("  LAN Interfaces (TC Ingress Forwarding):\n");
        for (int i = 0; i < lan_list.count; i++) {
            const char *name = lan_list.names[i];
            unsigned int ifidx = if_nametoindex(name);
            if (ifidx == 0) {
                printf("    - %-12s: [MISSING / DOWN] (Device not present in system)\n", name);
            } else if (is_tc_ingress_attached(name)) {
                printf("    - %-12s: [ACTIVE] (ifindex %u, TC ingress filter active)\n", name, ifidx);
            } else {
                printf("    - %-12s: [DETACHED / RECREATED] (ifindex %u, filter missing - run 'add-if %s' to reattach)\n",
                       name, ifidx, name);
            }
        }
    } else {
        printf("  LAN Interfaces (TC Ingress): None (Local-only mode)\n");
    }

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
                if (ep.family == AF_INET) {
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
    printf("Usage: %s <start|stop|reload|set-endpoint|add-if|del-if|status> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  start          Load eBPF, attach to cgroup and optional LAN interfaces, and apply rules\n");
    printf("                 Options: --cgroup-path <path>    (default: /sys/fs/cgroup)\n");
    printf("                          --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n");
    printf("                          --wg-endpoint <IP[:Port]>\n");
    printf("                          --rule-file <var.nft>   (required)\n");
    printf("                          --fwmark <mark>         (optional override)\n");
    printf("                          --lan-if <iface>        (optional LAN interfaces for TC ingress,\n");
    printf("                                                   can be repeated or comma-separated, e.g. eth1,eth2)\n\n");
    printf("  stop           Detach eBPF programs, TC ingress filters, and remove pinned objects\n");
    printf("                 Options: --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n");
    printf("                          --lan-if <iface>        (optional explicit LAN interfaces to detach)\n\n");
    printf("  reload         Hot-reload nftables rule file into BPF maps (no detach)\n");
    printf("                 Options: --rule-file <var.nft>   (required)\n");
    printf("                          --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n");
    printf("                          --wg-endpoint <IP[:Port]>\n");
    printf("                          --fwmark <mark>\n\n");
    printf("  set-endpoint   Dynamically update WireGuard endpoint (IP[:Port])\n");
    printf("                 Options: --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n");
    printf("                 Usage:   %s set-endpoint <IP[:Port]> [--pin-dir <path>]\n\n", prog);
    printf("  add-if         Dynamically attach TC ingress filter to LAN interface(s)\n");
    printf("                 Options: --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n");
    printf("                 Usage:   %s add-if <iface[,iface2]> [--pin-dir <path>]\n\n", prog);
    printf("  del-if         Dynamically detach TC ingress filter from LAN interface(s)\n");
    printf("                 Options: --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n");
    printf("                 Usage:   %s del-if <iface[,iface2]> [--pin-dir <path>]\n\n", prog);
    printf("  status         Show current eBPF router status, LAN interfaces, and map statistics\n");
    printf("                 Options: --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n");
}

#ifndef UNIT_TESTING
int main(int argc, char **argv) {
    libbpf_set_print(libbpf_print_fn);

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
        struct lan_ifaces lan_list = {0};

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
            } else if ((strcmp(argv[i], "--lan-if") == 0 || strcmp(argv[i], "--forward-if") == 0 ||
                        strcmp(argv[i], "--lan-interface") == 0) && i + 1 < argc) {
                add_lan_iface(&lan_list, argv[++i]);
            } else {
                fprintf(stderr, "Unknown argument '%s'\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        }
        return do_start(cgroup_path, rule_file, wg_endpoint, fwmark, pin_dir, &lan_list);
    } else if (strcmp(cmd, "stop") == 0 || strcmp(cmd, "unload") == 0) {
        struct lan_ifaces cli_lan = {0};
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--pin-dir") == 0 && i + 1 < argc) {
                pin_dir = argv[++i];
            } else if ((strcmp(argv[i], "--lan-if") == 0 || strcmp(argv[i], "--forward-if") == 0 ||
                        strcmp(argv[i], "--lan-interface") == 0) && i + 1 < argc) {
                add_lan_iface(&cli_lan, argv[++i]);
            } else {
                fprintf(stderr, "Unknown argument '%s'\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        }
        return do_stop(pin_dir, &cli_lan);
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
    } else if (strcmp(cmd, "add-if") == 0 || strcmp(cmd, "add-lan-if") == 0) {
        const char *if_str = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--pin-dir") == 0 && i + 1 < argc) {
                pin_dir = argv[++i];
            } else if (!if_str && argv[i][0] != '-') {
                if_str = argv[i];
            } else {
                fprintf(stderr, "Unknown argument '%s'\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        }
        if (!if_str) {
            fprintf(stderr, "Error: missing interface argument. Usage: %s add-if <iface[,iface2]> [--pin-dir <path>]\n", argv[0]);
            return 1;
        }
        return do_add_if(if_str, pin_dir);
    } else if (strcmp(cmd, "del-if") == 0 || strcmp(cmd, "del-lan-if") == 0 || strcmp(cmd, "remove-if") == 0) {
        const char *if_str = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--pin-dir") == 0 && i + 1 < argc) {
                pin_dir = argv[++i];
            } else if (!if_str && argv[i][0] != '-') {
                if_str = argv[i];
            } else {
                fprintf(stderr, "Unknown argument '%s'\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        }
        if (!if_str) {
            fprintf(stderr, "Error: missing interface argument. Usage: %s del-if <iface[,iface2]> [--pin-dir <path>]\n", argv[0]);
            return 1;
        }
        return do_del_if(if_str, pin_dir);
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
#endif
