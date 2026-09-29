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
#include <sys/wait.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/route.h>
#include <stdarg.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "router_common.h"
#include "local_router.skel.h"

#ifndef RTF_UP
#define RTF_UP 0x0001
#endif

static bool g_suppress_libbpf_log = false;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (g_suppress_libbpf_log)
        return 0;

    if (level == LIBBPF_DEBUG && !getenv("LIBBPF_DEBUG"))
        return 0;

    char buf[512];
    va_list args_copy;
    va_copy(args_copy, args);
    vsnprintf(buf, sizeof(buf), format, args_copy);
    va_end(args_copy);

    /* Suppress benign Netlink extack messages triggered during TC hook probing,
     * attachment, and detachment (e.g. non-existent hooks or non-matching filter priorities) */
    if (strstr(buf, "Exclusivity flag on, cannot modify") ||
        strstr(buf, "Parent Qdisc doesn't exists") ||
        strstr(buf, "Parent Qdisc doesn't exist") ||
        strstr(buf, "Filter with specified priority/protocol not found") ||
        strstr(buf, "No such file or directory")) {
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
    char *buf = strdup(arg);
    if (!buf) return;
    char *saveptr = NULL;
    char *tok = strtok_r(buf, " ,\t", &saveptr);
    while (tok) {
        char *name = trim(tok);
        if (*name) {
            char clean_name[IFNAMSIZ];
            strncpy(clean_name, name, sizeof(clean_name) - 1);
            clean_name[sizeof(clean_name) - 1] = '\0';

            bool exists = false;
            for (int i = 0; i < list->count; i++) {
                if (strcmp(list->names[i], clean_name) == 0) {
                    exists = true;
                    break;
                }
            }
            if (!exists) {
                if (list->count < MAX_LAN_IFACES) {
                    memcpy(list->names[list->count], clean_name, IFNAMSIZ);
                    list->names[list->count][IFNAMSIZ - 1] = '\0';
                    list->count++;
                } else {
                    fprintf(stderr, "Warning: Maximum number of LAN interfaces (%d) reached, skipping '%s'\n",
                            MAX_LAN_IFACES, clean_name);
                }
            }
        }
        tok = strtok_r(NULL, " ,\t", &saveptr);
    }
    free(buf);
}

static void remove_lan_iface(struct lan_ifaces *list, const char *arg) {
    if (!arg || !list) return;
    char *buf = strdup(arg);
    if (!buf) return;
    char *saveptr = NULL;
    char *tok = strtok_r(buf, " ,\t", &saveptr);
    while (tok) {
        char *name = trim(tok);
        if (*name) {
            char clean_name[IFNAMSIZ];
            strncpy(clean_name, name, sizeof(clean_name) - 1);
            clean_name[sizeof(clean_name) - 1] = '\0';

            for (int i = 0; i < list->count; i++) {
                if (strcmp(list->names[i], clean_name) == 0) {
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
    free(buf);
}

static inline bool has_ip6(const uint32_t ip6[4]) {
    return (ip6[0] | ip6[1] | ip6[2] | ip6[3]) != 0;
}

#define OIF_DEV_FILENAME "oif_dev.txt"

static void save_oif_dev(const char *pin_dir, const char *oif_dev) {
    if (!pin_dir) return;

    char path[512];
    /* 1. Primary: Save directly into pinned router_config_map (fully supported on bpffs) */
    snprintf(path, sizeof(path), "%s/router_config_map", pin_dir);
    int cfg_fd = bpf_obj_get(path);
    if (cfg_fd >= 0) {
        uint32_t zero = 0;
        struct router_config cfg = {0};
        if (bpf_map_lookup_elem(cfg_fd, &zero, &cfg) == 0) {
            if (oif_dev && oif_dev[0] != '\0') {
                strncpy(cfg.oif_name, oif_dev, sizeof(cfg.oif_name) - 1);
                cfg.oif_name[sizeof(cfg.oif_name) - 1] = '\0';
            } else {
                memset(cfg.oif_name, 0, sizeof(cfg.oif_name));
            }
            bpf_map_update_elem(cfg_fd, &zero, &cfg, BPF_ANY);
        }
        close(cfg_fd);

        /* Keep fallback file in sync so stale files never persist */
        snprintf(path, sizeof(path), "%s/%s", pin_dir, OIF_DEV_FILENAME);
        if (!oif_dev || oif_dev[0] == '\0') {
            unlink(path);
        } else {
            FILE *f = fopen(path, "w");
            if (f) {
                fprintf(f, "%s\n", oif_dev);
                fclose(f);
            }
        }
        return;
    }

    /* 2. Fallback for non-bpffs environments (e.g. unit tests in /tmp) */
    snprintf(path, sizeof(path), "%s/%s", pin_dir, OIF_DEV_FILENAME);
    if (!oif_dev || oif_dev[0] == '\0') {
        unlink(path);
        return;
    }
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "%s\n", oif_dev);
    fclose(f);
}

static int load_oif_dev(const char *pin_dir, char *oif_dev, size_t max_len) {
    if (!pin_dir || !oif_dev || max_len == 0) return -1;
    oif_dev[0] = '\0';

    /* 1. Primary: Query pinned router_config_map (fully supported on bpffs) */
    char path[512];
    snprintf(path, sizeof(path), "%s/router_config_map", pin_dir);
    int cfg_fd = bpf_obj_get(path);
    if (cfg_fd >= 0) {
        uint32_t zero = 0;
        struct router_config cfg = {0};
        if (bpf_map_lookup_elem(cfg_fd, &zero, &cfg) == 0) {
            if (cfg.oif_name[0] != '\0') {
                snprintf(oif_dev, max_len, "%s", cfg.oif_name);
                close(cfg_fd);
                return 0;
            }
            /* Fallback to IP match if oif_name is not populated (e.g. legacy map) */
            if (cfg.oif_src_ip4 || has_ip6(cfg.oif_src_ip6)) {
                struct ifaddrs *ifaddr, *ifa;
                if (getifaddrs(&ifaddr) == 0) {
                    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
                        if (!ifa->ifa_name || !ifa->ifa_addr) continue;
                        if (cfg.oif_src_ip4 && ifa->ifa_addr->sa_family == AF_INET) {
                            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
                            if (sin->sin_addr.s_addr == cfg.oif_src_ip4) {
                                snprintf(oif_dev, max_len, "%s", ifa->ifa_name);
                                freeifaddrs(ifaddr);
                                close(cfg_fd);
                                return 0;
                            }
                        }
                        if (has_ip6(cfg.oif_src_ip6) && ifa->ifa_addr->sa_family == AF_INET6) {
                            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                            if (memcmp(&sin6->sin6_addr, cfg.oif_src_ip6, 16) == 0) {
                                snprintf(oif_dev, max_len, "%s", ifa->ifa_name);
                                freeifaddrs(ifaddr);
                                close(cfg_fd);
                                return 0;
                            }
                        }
                    }
                    freeifaddrs(ifaddr);
                }
            }
        }
        close(cfg_fd);
        /* Authoritative map exists and is valid. If oif is not set, do NOT read stale files */
        return -1;
    }

    /* 2. Fallback for non-bpffs environments (e.g. unit tests in /tmp) */
    snprintf(path, sizeof(path), "%s/%s", pin_dir, OIF_DEV_FILENAME);
    FILE *f = fopen(path, "r");
    if (f) {
        char line[IFNAMSIZ + 16];
        if (fgets(line, sizeof(line), f)) {
            char *t = trim(line);
            if (*t) {
                snprintf(oif_dev, max_len, "%s", t);
                fclose(f);
                return 0;
            }
        }
        fclose(f);
    }

    return -1;
}

static bool is_interface_carrier_up(const char *ifname) {
    if (!ifname || !*ifname) return false;

    /* 1. Check operational carrier via sysfs if present */
    char carrier_path[256];
    snprintf(carrier_path, sizeof(carrier_path), "/sys/class/net/%s/carrier", ifname);
    FILE *f = fopen(carrier_path, "r");
    if (f) {
        char val[16];
        bool carrier_zero = false;
        if (fgets(val, sizeof(val), f)) {
            char *t = trim(val);
            if (strcmp(t, "0") == 0) {
                carrier_zero = true;
            }
        }
        fclose(f);
        if (carrier_zero) {
            return false;
        }
    }

    /* 2. Check flags via socket ioctl (SIOCGIFFLAGS) */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
        int ret = ioctl(sock, SIOCGIFFLAGS, &ifr);
        close(sock);
        if (ret == 0) {
            if (!(ifr.ifr_flags & IFF_UP) || !(ifr.ifr_flags & IFF_RUNNING)) {
                return false;
            }
            return true;
        }
    }

    /* 3. Fallback: getifaddrs */
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == 0) {
        bool found = false;
        bool ok = false;
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_name && strcmp(ifa->ifa_name, ifname) == 0) {
                found = true;
                if ((ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING)) {
                    ok = true;
                    break;
                }
            }
        }
        freeifaddrs(ifaddr);
        if (found) return ok;
    }

    return false;
}

static bool is_physical_interface(const char *ifname) {
    if (!ifname || !*ifname) return false;
    if (strcmp(ifname, "lo") == 0 || strncmp(ifname, "lo:", 3) == 0) return false;

    /* Exclude known virtual/pseudo interfaces and VLAN subinterfaces */
    if (strncmp(ifname, "wg", 2) == 0 ||
        strncmp(ifname, "tun", 3) == 0 ||
        strncmp(ifname, "tap", 3) == 0 ||
        strncmp(ifname, "docker", 6) == 0 ||
        strncmp(ifname, "br", 2) == 0 ||
        strncmp(ifname, "bridge", 6) == 0 ||
        strncmp(ifname, "virbr", 5) == 0 ||
        strncmp(ifname, "veth", 4) == 0 ||
        strncmp(ifname, "dummy", 5) == 0 ||
        strncmp(ifname, "sit", 3) == 0 ||
        strncmp(ifname, "ip6tnl", 6) == 0 ||
        strncmp(ifname, "bond", 4) == 0 ||
        strncmp(ifname, "gre", 3) == 0 ||
        strncmp(ifname, "vxlan", 5) == 0 ||
        strncmp(ifname, "ppp", 3) == 0 ||
        strncmp(ifname, "vlan", 4) == 0 ||
        strncmp(ifname, "macvlan", 7) == 0 ||
        strchr(ifname, '.') != NULL) {
        return false;
    }

    /* Check if /sys/class/net/<ifname>/device exists */
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/device", ifname);
    if (access(path, F_OK) == 0) return true;

    /* Common physical interface naming patterns */
    if (strncmp(ifname, "eth", 3) == 0 ||
        strncmp(ifname, "en", 2) == 0 ||
        strncmp(ifname, "wl", 2) == 0 ||
        strncmp(ifname, "ww", 2) == 0) {
        return true;
    }

    return false;
}

static int count_active_physical_interfaces(void) {
    struct if_nameindex *if_list = if_nameindex();
    if (!if_list) return 0;

    int count = 0;
    for (struct if_nameindex *i = if_list; i->if_index && i->if_name; ++i) {
        if (!is_physical_interface(i->if_name)) continue;
        if (is_interface_carrier_up(i->if_name)) {
            count++;
        }
    }
    if_freenameindex(if_list);
    return count;
}

static inline bool is_ipv4_default_route(uint32_t dest, uint32_t mask, uint32_t flags) {
    return (dest == 0 && mask == 0 && (flags & RTF_UP));
}

static inline bool is_ipv6_default_route(const char *d_ip, const char *d_len, uint32_t flags) {
    if (!d_ip || !d_len) return false;
    if (strcmp(d_len, "00") != 0) return false;
    if (strcmp(d_ip, "00000000000000000000000000000000") != 0) return false;
    if (!(flags & RTF_UP)) return false;
    return true;
}

static bool is_auto_interface_keyword(const char *name) {
    if (!name) return false;
    return (strcasecmp(name, "auto") == 0 ||
            strcasecmp(name, "default") == 0 ||
            strcasecmp(name, "primary") == 0);
}

#ifdef UNIT_TESTING
int (*g_mock_get_default_interface)(const char *exclude_oif, char *out_ifname, size_t max_len) = NULL;
#endif

static int get_default_interface(const char *exclude_oif, char *out_ifname, size_t max_len) {
#ifdef UNIT_TESTING
    if (g_mock_get_default_interface) {
        return g_mock_get_default_interface(exclude_oif, out_ifname, max_len);
    }
#endif
    if (!out_ifname || max_len == 0) return -1;
    out_ifname[0] = '\0';

    #define SHOULD_EXCLUDE(name) \
        (strcmp(name, "lo") == 0 || \
         (exclude_oif && strcmp(name, exclude_oif) == 0) || \
         strncmp(name, "wg", 2) == 0)

    /* 1. Try IPv4 default route via /proc/net/route */
    FILE *f = fopen("/proc/net/route", "r");
    if (f) {
        char line[256];
        char best_ifname[IFNAMSIZ] = {0};
        uint32_t lowest_metric = 0xFFFFFFFF;
        bool found = false;

        /* Skip header line */
        if (fgets(line, sizeof(line), f)) {
            while (fgets(line, sizeof(line), f)) {
                char iface[IFNAMSIZ];
                uint32_t dest, flags, metric, mask;
                if (sscanf(line, "%15s %x %*x %x %*x %*x %x %x", iface, &dest, &flags, &metric, &mask) == 5) {
                    if (is_ipv4_default_route(dest, mask, flags)) {
                        if (SHOULD_EXCLUDE(iface)) continue;
                        if (!is_interface_carrier_up(iface)) continue;
                        if (metric < lowest_metric || !found) {
                            lowest_metric = metric;
                            snprintf(best_ifname, sizeof(best_ifname), "%s", iface);
                            found = true;
                        }
                    }
                }
            }
        }
        fclose(f);
        if (found) {
            snprintf(out_ifname, max_len, "%s", best_ifname);
            return 0;
        }
    }

    /* 2. Try IPv6 default route via /proc/net/ipv6_route */
    f = fopen("/proc/net/ipv6_route", "r");
    if (f) {
        char line[512];
        char best_ifname[IFNAMSIZ] = {0};
        uint32_t lowest_metric = 0xFFFFFFFF;
        bool found = false;

        while (fgets(line, sizeof(line), f)) {
            char d_ip[33], d_len[3], s_ip[33], s_len[3], nh[33];
            uint32_t metric, refcnt, use, flags;
            char iface[IFNAMSIZ];

            int fields = sscanf(line, "%32s %2s %32s %2s %32s %x %x %x %x %15s",
                                d_ip, d_len, s_ip, s_len, nh, &metric, &refcnt, &use, &flags, iface);
            if (fields == 10) {
                if (is_ipv6_default_route(d_ip, d_len, flags)) {
                    if (SHOULD_EXCLUDE(iface)) continue;
                    if (!is_interface_carrier_up(iface)) continue;
                    if (metric < lowest_metric || !found) {
                        lowest_metric = metric;
                        snprintf(best_ifname, sizeof(best_ifname), "%s", iface);
                        found = true;
                    }
                }
            }
        }
        fclose(f);
        if (found) {
            snprintf(out_ifname, max_len, "%s", best_ifname);
            return 0;
        }
    }

    /* 3. Fallback: Active non-loopback UP & RUNNING interface with an IP (prefer physical interfaces) */
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == 0) {
        char fallback_candidate[IFNAMSIZ] = {0};
        bool found_candidate = false;

        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (!ifa->ifa_name || !ifa->ifa_addr) continue;
            if (SHOULD_EXCLUDE(ifa->ifa_name)) continue;
            if ((ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING)) {
                if (!is_interface_carrier_up(ifa->ifa_name)) continue;
                if (ifa->ifa_addr->sa_family == AF_INET || ifa->ifa_addr->sa_family == AF_INET6) {
                    if (is_physical_interface(ifa->ifa_name)) {
                        snprintf(out_ifname, max_len, "%s", ifa->ifa_name);
                        freeifaddrs(ifaddr);
                        return 0;
                    }
                    if (!found_candidate) {
                        snprintf(fallback_candidate, sizeof(fallback_candidate), "%s", ifa->ifa_name);
                        found_candidate = true;
                    }
                }
            }
        }
        freeifaddrs(ifaddr);
        if (found_candidate) {
            snprintf(out_ifname, max_len, "%s", fallback_candidate);
            return 0;
        }
    }

    #undef SHOULD_EXCLUDE
    return -1;
}

static int resolve_lan_ifaces(struct lan_ifaces *list, const char *exclude_oif) {
    if (!list) return 0;
    char def_if[IFNAMSIZ] = {0};
    bool def_resolved = false;
    bool resolution_failed = false;

    for (int i = 0; i < list->count; i++) {
        if (is_auto_interface_keyword(list->names[i])) {
            const char *original_keyword = list->names[i];
            if (!def_resolved) {
                if (get_default_interface(exclude_oif, def_if, sizeof(def_if)) != 0) {
                    fprintf(stderr, "Error: Could not auto-detect default network interface (no default route or active physical interface found)\n");
                    resolution_failed = true;
                    for (int j = i; j < list->count - 1; j++) {
                        memcpy(list->names[j], list->names[j + 1], IFNAMSIZ);
                    }
                    list->count--;
                    i--;
                    continue;
                }
                def_resolved = true;
                printf("[*] Auto-detected default interface for TC ingress: '%s'\n", def_if);

                int phys_count = count_active_physical_interfaces();
                bool ppp_uplink = (strncmp(def_if, "ppp", 3) == 0);
                if (phys_count > 1 || (ppp_uplink && phys_count >= 1)) {
                    fprintf(stderr, "Warning: Multi-interface host detected (%d active physical LAN/WAN interface(s)%s). "
                                    "'%s' resolved to WAN/default-route interface '%s'. "
                                    "In a multi-NIC router setup, using 'auto' attaches TC ingress to WAN instead of LAN. "
                                    "You should explicitly specify the LAN interface (e.g. '--iif eth1') to avoid routing inversion!\n",
                            phys_count, ppp_uplink ? " with PPP uplink" : "", original_keyword, def_if);
                }
            }
            snprintf(list->names[i], IFNAMSIZ, "%s", def_if);
        }
        if (exclude_oif && strcmp(list->names[i], exclude_oif) == 0) {
            fprintf(stderr, "Error: Inbound LAN interface '%s' cannot be identical to outbound interface (--oif)!\n", list->names[i]);
            return -1;
        }
    }

    /* Deduplicate interface names */
    for (int i = 0; i < list->count; i++) {
        for (int j = i + 1; j < list->count; j++) {
            if (strcmp(list->names[i], list->names[j]) == 0) {
                for (int k = j; k < list->count - 1; k++) {
                    memcpy(list->names[k], list->names[k + 1], IFNAMSIZ);
                }
                list->count--;
                j--;
            }
        }
    }

    if (resolution_failed && list->count == 0) {
        return -1;
    }
    return 0;
}

static int get_or_create_lan_map(const char *pin_dir) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", pin_dir, LAN_IFACES_FILENAME);
    int fd = bpf_obj_get(path);
    if (fd >= 0) {
        return fd;
    }
    /* Try older name "lan_ifaces" if exists */
    snprintf(path, sizeof(path), "%s/lan_ifaces", pin_dir);
    fd = bpf_obj_get(path);
    if (fd >= 0) {
        return fd;
    }
    /* If not found, create and pin it into bpffs */
    snprintf(path, sizeof(path), "%s/%s", pin_dir, LAN_IFACES_FILENAME);
    fd = bpf_map_create(BPF_MAP_TYPE_HASH, LAN_IFACES_FILENAME, IFNAMSIZ, sizeof(__u32), MAX_LAN_IFACES, NULL);
    if (fd < 0) {
        return -1;
    }
    int pin_err = bpf_obj_pin(fd, path);
    if (pin_err != 0) {
        /* If pinning fails (e.g. not a bpffs directory like /tmp in unit tests), fallback */
        close(fd);
        return -1;
    }
    return fd;
}

static void save_lan_ifaces(const char *pin_dir, const struct lan_ifaces *list) {
    int map_fd = get_or_create_lan_map(pin_dir);
    if (map_fd >= 0) {
        /* Collect all existing keys to delete */
        char keys_to_delete[MAX_LAN_IFACES][IFNAMSIZ];
        int del_count = 0;
        char prev_key[IFNAMSIZ] = {0};
        char next_key[IFNAMSIZ] = {0};
        char *lookup_key = NULL;
        while (bpf_map_get_next_key(map_fd, lookup_key, next_key) == 0 && del_count < MAX_LAN_IFACES) {
            memcpy(keys_to_delete[del_count++], next_key, IFNAMSIZ);
            memcpy(prev_key, next_key, IFNAMSIZ);
            lookup_key = prev_key;
        }
        for (int i = 0; i < del_count; i++) {
            bpf_map_delete_elem(map_fd, keys_to_delete[i]);
        }

        /* Insert current entries */
        if (list) {
            for (int i = 0; i < list->count; i++) {
                char k[IFNAMSIZ] = {0};
                strncpy(k, list->names[i], IFNAMSIZ - 1);
                __u32 ifidx = if_nametoindex(k);
                bpf_map_update_elem(map_fd, k, &ifidx, BPF_ANY);
            }
        }
        /* Keep fallback file in sync so stale files never persist */
        char path[512];
        snprintf(path, sizeof(path), "%s/%s.txt", pin_dir, LAN_IFACES_FILENAME);
        if (!list || list->count == 0) {
            unlink(path);
            snprintf(path, sizeof(path), "%s/lan_ifaces.txt", pin_dir);
            unlink(path);
        } else {
            FILE *f = fopen(path, "w");
            if (f) {
                for (int i = 0; i < list->count; i++) {
                    fprintf(f, "%s\n", list->names[i]);
                }
                fclose(f);
            }
        }
        close(map_fd);
        return;
    }

    /* Fallback for regular filesystem (e.g. unit tests in /tmp) */
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.txt", pin_dir, LAN_IFACES_FILENAME);
    if (!list || list->count == 0) {
        unlink(path);
        snprintf(path, sizeof(path), "%s/lan_ifaces.txt", pin_dir);
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
    int map_fd = bpf_obj_get(path);
    if (map_fd < 0) {
        snprintf(path, sizeof(path), "%s/lan_ifaces", pin_dir);
        map_fd = bpf_obj_get(path);
    }
    if (map_fd >= 0) {
        char prev_key[IFNAMSIZ] = {0};
        char next_key[IFNAMSIZ] = {0};
        char *lookup_key = NULL;
        while (bpf_map_get_next_key(map_fd, lookup_key, next_key) == 0 && list->count < MAX_LAN_IFACES) {
            snprintf(list->names[list->count], sizeof(list->names[list->count]), "%s", next_key);
            list->names[list->count][IFNAMSIZ - 1] = '\0';
            list->count++;
            memcpy(prev_key, next_key, IFNAMSIZ);
            lookup_key = prev_key;
        }
        close(map_fd);
        return;
    }

    /* Fallback for regular filesystem */
    snprintf(path, sizeof(path), "%s/%s.txt", pin_dir, LAN_IFACES_FILENAME);
    FILE *f = fopen(path, "r");
    if (!f) {
        snprintf(path, sizeof(path), "%s/lan_ifaces.txt", pin_dir);
        f = fopen(path, "r");
    }
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

static uint32_t get_pinned_tc_prog_id(const char *pin_dir) {
    if (!pin_dir) return 0;
    char prog_path[512];
    snprintf(prog_path, sizeof(prog_path), "%s/%s", pin_dir, TC_PROG_FILENAME);
    int prog_fd = bpf_obj_get(prog_path);
    if (prog_fd < 0) {
        return 0;
    }
    struct bpf_prog_info info = {0};
    __u32 len = sizeof(info);
    uint32_t prog_id = 0;
    if (bpf_obj_get_info_by_fd(prog_fd, &info, &len) == 0) {
        prog_id = info.id;
    }
    close(prog_fd);
    return prog_id;
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

    /* 2. Attach TC ingress filter with fixed handle=1 and priority=1 */
    struct bpf_tc_opts opts = {
        .sz = sizeof(opts),
        .prog_fd = prog_fd,
        .flags = BPF_TC_F_REPLACE,
        .handle = 1,
        .priority = 1,
    };
    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        /* Fallback: let kernel auto-allocate if fixed priority is rejected */
        opts.handle = 0;
        opts.priority = 0;
        err = bpf_tc_attach(&hook, &opts);
    }
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
    struct bpf_tc_opts opts = {
        .sz = sizeof(opts),
        .handle = 1,
        .priority = 1,
    };
    g_suppress_libbpf_log = true;
    bpf_tc_detach(&hook, &opts);
    opts.priority = 49152;
    bpf_tc_detach(&hook, &opts);
    opts.handle = 0;
    opts.priority = 0;
    bpf_tc_detach(&hook, &opts);
    /* Note: We intentionally do NOT call bpf_tc_hook_destroy(&hook) here,
     * to avoid collaterally removing other TC filters or qdisc configurations
     * (e.g. QoS, egress filters) sharing the interface's clsact qdisc. */
    g_suppress_libbpf_log = false;
    return 0;
}

static bool query_tc_filter(int ifindex, uint32_t handle, uint32_t priority, uint32_t expected_prog_id) {
    struct bpf_tc_hook hook = {
        .sz = sizeof(hook),
        .ifindex = ifindex,
        .attach_point = BPF_TC_INGRESS,
    };
    struct bpf_tc_opts opts = {
        .sz = sizeof(opts),
        .handle = handle,
        .priority = priority,
    };
    g_suppress_libbpf_log = true;
    int ret = bpf_tc_query(&hook, &opts);
    g_suppress_libbpf_log = false;
    if (ret == 0) {
        if (expected_prog_id > 0) {
            return opts.prog_id == expected_prog_id;
        }
        return false; /* Cannot verify prog_id with certainty; fall back to check_tc_filter_cmd for program name */
    }
    return false;
}

static bool check_tc_filter_cmd(const char *ifname, uint32_t expected_prog_id) {
    int pipefd[2];
#ifdef O_CLOEXEC
    if (pipe2(pipefd, O_CLOEXEC) != 0) return false;
#else
    if (pipe(pipefd) != 0) return false;
#endif

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return false;
    }

    if (pid == 0) {
        /* Child process: direct exec without shell to prevent command injection */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        int nullfd = open("/dev/null", O_WRONLY);
        if (nullfd >= 0) {
            dup2(nullfd, STDERR_FILENO);
            close(nullfd);
        }
        char *const argv[] = {"tc", "filter", "show", "dev", (char *)ifname, "ingress", NULL};
        execvp("tc", argv);
        _exit(127);
    }

    /* Parent process */
    close(pipefd[1]);
    FILE *fp = fdopen(pipefd[0], "r");
    bool found = false;
    if (fp) {
        char line[256];
        char id_str[32] = {0};
        if (expected_prog_id > 0) {
            snprintf(id_str, sizeof(id_str), "id %u", expected_prog_id);
        }
        while (fgets(line, sizeof(line), fp)) {
            if (expected_prog_id > 0) {
                if (strstr(line, id_str)) {
                    found = true;
                    break;
                }
            } else {
                if (strstr(line, "tc_router_ingress") || strstr(line, "local_router")) {
                    found = true;
                    break;
                }
            }
        }
        fclose(fp);
    } else {
        close(pipefd[0]);
    }
    int status;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR);
    return found;
}

static bool is_tc_ingress_attached_ext(const char *ifname, uint32_t expected_prog_id, bool allow_cmd_fallback) {
    if (!ifname || expected_prog_id == 0) {
        return false;
    }

    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        return false;
    }

    /* 1. Check fixed handle=1, priority=1 */
    if (query_tc_filter((int)ifindex, 1, 1, expected_prog_id)) return true;

    /* 2. Check kernel auto-allocated default priority 49152 (0xc000) */
    if (query_tc_filter((int)ifindex, 1, 49152, expected_prog_id)) return true;

    /* 3. Check variations of handle/priority */
    if (query_tc_filter((int)ifindex, 0, 1, expected_prog_id)) return true;
    if (query_tc_filter((int)ifindex, 0, 49152, expected_prog_id)) return true;
    if (query_tc_filter((int)ifindex, 1, 0, expected_prog_id)) return true;
    if (query_tc_filter((int)ifindex, 0, 0, expected_prog_id)) return true;

    /* 4. Robust fallback via direct tc command inspection without shell (never in passive scanning) */
    if (!allow_cmd_fallback) {
        return false;
    }
    return check_tc_filter_cmd(ifname, expected_prog_id);
}

static bool is_tc_ingress_attached(const char *ifname, uint32_t expected_prog_id) {
    return is_tc_ingress_attached_ext(ifname, expected_prog_id, true);
}

static int ensure_dir(const char *path) {
    if (!path || !*path) return -EINVAL;
    char tmp[512];
    size_t len = strnlen(path, sizeof(tmp));
    if (len >= sizeof(tmp)) return -ENAMETOOLONG;
    memcpy(tmp, path, len + 1);

    mode_t dir_mode = (strstr(path, "/sys/fs/bpf") != NULL) ? 0700 : 0755;

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, dir_mode) != 0) {
                if (errno != EEXIST)
                    return -errno;
                struct stat st;
                if (stat(tmp, &st) != 0 || !S_ISDIR(st.st_mode))
                    return -ENOTDIR;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, dir_mode) != 0) {
        if (errno != EEXIST)
            return -errno;
        struct stat st;
        if (stat(tmp, &st) != 0 || !S_ISDIR(st.st_mode))
            return -ENOTDIR;
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
        uint64_t max_size = start & (-((uint64_t)start));
        if (max_size == 0) max_size = 0x100000000ULL;

        uint64_t diff = (uint64_t)end - start + 1;
        while (max_size > diff) {
            max_size >>= 1;
        }

        uint32_t prefixlen = 32 - __builtin_ctzll(max_size);
        cb(htonl(start), prefixlen, arg);

        if (max_size > (uint64_t)end - start) break;
        start += (uint32_t)max_size;
    }
}

static int parse_port(const char *port_str, uint16_t *out_port) {
    if (!port_str) return -1;
    while (isspace((unsigned char)*port_str)) port_str++;
    if (*port_str == '\0' || *port_str < '0' || *port_str > '9') return -1;

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
    if (*str == '\0' || *str == '-' || *str == '+') return -1;

    char *endptr = NULL;
    errno = 0;
    unsigned long long val = strtoull(str, &endptr, 0);
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
    if (!str || *str == '\0') return -1;
    if (strlen(str) >= 256) {
        fprintf(stderr, "Error: Endpoint string too long (max 255 chars)\n");
        return -1;
    }

    char buf[256];
    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *t = trim(buf);
    if (*t == '\0') return -1;

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

    bool oom;
};

static void v4_collect_cb(uint32_t net_be, uint32_t prefixlen, void *arg) {
    struct rule_collector *rc = (struct rule_collector *)arg;
    if (rc->oom) return;
    if (rc->v4_count >= rc->v4_cap) {
        size_t new_cap = rc->v4_cap ? rc->v4_cap * 2 : 64;
        struct ipv4_lpm_key *new_keys = realloc(rc->v4_keys, new_cap * sizeof(*new_keys));
        if (!new_keys) {
            rc->oom = true;
            return;
        }
        rc->v4_keys = new_keys;
        rc->v4_cap = new_cap;
    }
    rc->v4_keys[rc->v4_count].prefixlen = prefixlen;
    rc->v4_keys[rc->v4_count].data = net_be;
    rc->v4_count++;
}

static int add_v6_rule(struct rule_collector *rc, const uint8_t *ip6_bytes, uint32_t prefixlen) {
    if (rc->oom) return -1;
    if (rc->v6_count >= rc->v6_cap) {
        size_t new_cap = rc->v6_cap ? rc->v6_cap * 2 : 64;
        struct ipv6_lpm_key *new_keys = realloc(rc->v6_keys, new_cap * sizeof(*new_keys));
        if (!new_keys) {
            rc->oom = true;
            return -1;
        }
        rc->v6_keys = new_keys;
        rc->v6_cap = new_cap;
    }
    rc->v6_keys[rc->v6_count].prefixlen = prefixlen;
    memcpy(rc->v6_keys[rc->v6_count].data, ip6_bytes, 16);
    rc->v6_count++;
    return 0;
}

static inline uint32_t normalize_v4_cidr(uint32_t net_be, uint32_t prefixlen) {
    if (prefixlen == 0) return 0;
    if (prefixlen >= 32) return net_be;
    uint32_t mask = htonl(~((1ULL << (32 - prefixlen)) - 1));
    return net_be & mask;
}

static inline void normalize_v6_cidr(uint8_t ip6_buf[16], uint32_t prefixlen) {
    if (prefixlen >= 128) return;
    uint32_t full_bytes = prefixlen / 8;
    uint32_t rem_bits = prefixlen % 8;
    if (full_bytes < 16) {
        if (rem_bits > 0) {
            uint8_t mask = (uint8_t)(0xFF << (8 - rem_bits));
            ip6_buf[full_bytes] &= mask;
            full_bytes++;
        }
        for (uint32_t b = full_bytes; b < 16; b++) {
            ip6_buf[b] = 0;
        }
    }
}

static int cmp_v4_key(const void *a, const void *b) {
    const struct ipv4_lpm_key *ka = a;
    const struct ipv4_lpm_key *kb = b;
    if (ka->prefixlen != kb->prefixlen)
        return ka->prefixlen < kb->prefixlen ? -1 : 1;
    uint32_t da = ntohl(ka->data);
    uint32_t db = ntohl(kb->data);
    if (da != db)
        return da < db ? -1 : 1;
    return 0;
}

static int cmp_v6_key(const void *a, const void *b) {
    const struct ipv6_lpm_key *ka = a;
    const struct ipv6_lpm_key *kb = b;
    if (ka->prefixlen != kb->prefixlen)
        return ka->prefixlen < kb->prefixlen ? -1 : 1;
    return memcmp(ka->data, kb->data, 16);
}

static size_t deduplicate_v4(struct ipv4_lpm_key *keys, size_t count) {
    if (count <= 1) return count;
    qsort(keys, count, sizeof(*keys), cmp_v4_key);
    size_t w = 1;
    for (size_t r = 1; r < count; r++) {
        if (keys[r].prefixlen != keys[w - 1].prefixlen || keys[r].data != keys[w - 1].data) {
            keys[w++] = keys[r];
        }
    }
    return w;
}

static size_t deduplicate_v6(struct ipv6_lpm_key *keys, size_t count) {
    if (count <= 1) return count;
    qsort(keys, count, sizeof(*keys), cmp_v6_key);
    size_t w = 1;
    for (size_t r = 1; r < count; r++) {
        if (keys[r].prefixlen != keys[w - 1].prefixlen || memcmp(keys[r].data, keys[w - 1].data, 16) != 0) {
            keys[w++] = keys[r];
        }
    }
    return w;
}

static void prune_lpm_v4_map(int map_fd, const struct ipv4_lpm_key *keys, size_t count) {
    struct ipv4_lpm_key cur_key = {0};
    struct ipv4_lpm_key next_key = {0};
    void *lookup_key = NULL;

    struct ipv4_lpm_key *to_delete = NULL;
    size_t del_count = 0;
    size_t del_cap = 0;

    while (bpf_map_get_next_key(map_fd, lookup_key, &next_key) == 0) {
        cur_key = next_key;
        lookup_key = &cur_key;

        if (count == 0 || bsearch(&next_key, keys, count, sizeof(*keys), cmp_v4_key) == NULL) {
            if (del_count >= del_cap) {
                size_t new_cap = del_cap ? del_cap * 2 : 128;
                struct ipv4_lpm_key *new_arr = realloc(to_delete, new_cap * sizeof(*new_arr));
                if (!new_arr) {
                    fprintf(stderr, "Warning: Memory allocation failure while pruning IPv4 map\n");
                    break;
                }
                to_delete = new_arr;
                del_cap = new_cap;
            }
            to_delete[del_count++] = next_key;
        }
    }

    for (size_t i = 0; i < del_count; i++) {
        bpf_map_delete_elem(map_fd, &to_delete[i]);
    }
    free(to_delete);
}

static void prune_lpm_v6_map(int map_fd, const struct ipv6_lpm_key *keys, size_t count) {
    struct ipv6_lpm_key cur_key = {0};
    struct ipv6_lpm_key next_key = {0};
    void *lookup_key = NULL;

    struct ipv6_lpm_key *to_delete = NULL;
    size_t del_count = 0;
    size_t del_cap = 0;

    while (bpf_map_get_next_key(map_fd, lookup_key, &next_key) == 0) {
        cur_key = next_key;
        lookup_key = &cur_key;

        if (count == 0 || bsearch(&next_key, keys, count, sizeof(*keys), cmp_v6_key) == NULL) {
            if (del_count >= del_cap) {
                size_t new_cap = del_cap ? del_cap * 2 : 128;
                struct ipv6_lpm_key *new_arr = realloc(to_delete, new_cap * sizeof(*new_arr));
                if (!new_arr) {
                    fprintf(stderr, "Warning: Memory allocation failure while pruning IPv6 map\n");
                    break;
                }
                to_delete = new_arr;
                del_cap = new_cap;
            }
            to_delete[del_count++] = next_key;
        }
    }

    for (size_t i = 0; i < del_count; i++) {
        bpf_map_delete_elem(map_fd, &to_delete[i]);
    }
    free(to_delete);
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
    char *line = NULL;
    size_t line_cap = 0;
    ssize_t nread;
    int line_num = 0;
    int section = 0; // 0=none, 1=v4, 2=v6
    int ret = 0;

    while ((nread = getline(&line, &line_cap, f)) != -1) {
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
                    ret = -1;
                    break;
                }
                char *v = trim(eq + 1);
                if (parse_fwmark(v, &rc->fwmark) != 0) {
                    fprintf(stderr, "Error [line %d]: Invalid or zero FWMARK value '%s'. A non-zero FWMARK is strictly required to prevent traffic leaks.\n", line_num, v);
                    ret = -1;
                    break;
                }
                rc->has_fwmark = true;
                continue;
            }

            if (match_keyword(t, "define WG_ENDPOINT")) {
                char *eq = strchr(t, '=');
                if (!eq) {
                    fprintf(stderr, "Error [line %d]: Malformed WG_ENDPOINT definition (missing '='): %s\n", line_num, t);
                    ret = -1;
                    break;
                }
                char *v = trim(eq + 1);
                if (*v == '"' || *v == '\'') {
                    char q = *v++;
                    char *end = v + strlen(v) - 1;
                    if (end >= v && *end == q) *end = '\0';
                }
                v = trim(v);
                if (*v == '\0') {
                    rc->endpoint[0] = '\0';
                    rc->has_endpoint = false;
                    continue;
                }
                struct wg_endpoint tmp_ep;
                if (parse_endpoint(v, &tmp_ep) != 0) {
                    fprintf(stderr, "Error [line %d]: Invalid WG_ENDPOINT '%s'\n", line_num, v);
                    ret = -1;
                    break;
                }
                strncpy(rc->endpoint, v, sizeof(rc->endpoint) - 1);
                rc->endpoint[sizeof(rc->endpoint) - 1] = '\0';
                rc->has_endpoint = true;
                continue;
            }

            const char *blk_v4 = find_element_block(t, "IPV4_ELEMENTS");
            const char *blk_v6 = find_element_block(t, "IPV6_ELEMENTS");
            if (blk_v4) {
                const char *ob = strchr(blk_v4, '{');
                if (!ob) {
                    fprintf(stderr, "Error [line %d]: Missing '{' in IPV4_ELEMENTS definition\n", line_num);
                    ret = -1;
                    break;
                }
                section = 1;
                t = (char *)(ob + 1);
            } else if (blk_v6) {
                const char *ob = strchr(blk_v6, '{');
                if (!ob) {
                    fprintf(stderr, "Error [line %d]: Missing '{' in IPV6_ELEMENTS definition\n", line_num);
                    ret = -1;
                    break;
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

            if (cur_section == 1) {
                /* Normalize spaces around hyphens in IPv4 ranges, e.g. "1.0.1.0 - 1.0.3.255" -> "1.0.1.0-1.0.3.255" */
                char *src = t, *dst = t;
                while (*src) {
                    if (*src == '-') {
                        while (dst > t && isspace((unsigned char)*(dst - 1))) dst--;
                        *dst++ = '-';
                        src++;
                        while (isspace((unsigned char)*src)) src++;
                    } else {
                        *dst++ = *src++;
                    }
                }
                *dst = '\0';
            }

            char *saveptr = NULL;
            char *token = strtok_r(t, " ,\t\r\n", &saveptr);
            while (token) {
                if (cur_section == 1) { // IPv4
                    if (strchr(token, '-')) {
                        char s_ip[64] = {0}, e_ip[64] = {0};
                        char extra = '\0';
                        if (sscanf(token, "%63[^-]-%63[^ \t\r\n]%c", s_ip, e_ip, &extra) != 2) {
                            fprintf(stderr, "Error [line %d]: Malformed IPv4 range '%s'\n", line_num, token);
                            ret = -1;
                            break;
                        }
                        uint32_t s = 0, e = 0;
                        if (inet_pton(AF_INET, trim(s_ip), &s) != 1) {
                            fprintf(stderr, "Error [line %d]: Invalid start IP '%s' in range '%s'\n", line_num, s_ip, token);
                            ret = -1;
                            break;
                        }
                        if (inet_pton(AF_INET, trim(e_ip), &e) != 1) {
                            fprintf(stderr, "Error [line %d]: Invalid end IP '%s' in range '%s'\n", line_num, e_ip, token);
                            ret = -1;
                            break;
                        }
                        if (ntohl(s) > ntohl(e)) {
                            fprintf(stderr, "Error [line %d]: Inverted IPv4 range '%s' (start > end)\n", line_num, token);
                            ret = -1;
                            break;
                        }
                        range_to_cidrs(ntohl(s), ntohl(e), v4_collect_cb, rc);
                    } else if (strchr(token, '/')) {
                        char ip_str[64] = {0};
                        uint32_t plen = 32;
                        char extra = '\0';
                        if (sscanf(token, "%63[^/]/%u%c", ip_str, &plen, &extra) != 2) {
                            fprintf(stderr, "Error [line %d]: Malformed IPv4 CIDR '%s'\n", line_num, token);
                            ret = -1;
                            break;
                        }
                        if (plen > 32) {
                            fprintf(stderr, "Error [line %d]: Invalid IPv4 prefix length /%u in '%s'\n", line_num, plen, token);
                            ret = -1;
                            break;
                        }
                        uint32_t net = 0;
                        if (inet_pton(AF_INET, trim(ip_str), &net) != 1) {
                            fprintf(stderr, "Error [line %d]: Invalid IPv4 address '%s' in '%s'\n", line_num, ip_str, token);
                            ret = -1;
                            break;
                        }
                        v4_collect_cb(normalize_v4_cidr(net, plen), plen, rc);
                    } else {
                        uint32_t net = 0;
                        if (inet_pton(AF_INET, token, &net) != 1) {
                            fprintf(stderr, "Error [line %d]: Invalid IPv4 address '%s'\n", line_num, token);
                            ret = -1;
                            break;
                        }
                        v4_collect_cb(net, 32, rc);
                    }
                } else if (cur_section == 2) { // IPv6
                    char ip_str[64] = {0};
                    uint32_t plen = 128;
                    if (strchr(token, '/')) {
                        char extra = '\0';
                        if (sscanf(token, "%63[^/]/%u%c", ip_str, &plen, &extra) != 2) {
                            fprintf(stderr, "Error [line %d]: Malformed IPv6 CIDR '%s'\n", line_num, token);
                            ret = -1;
                            break;
                        }
                        if (plen > 128) {
                            fprintf(stderr, "Error [line %d]: Invalid IPv6 prefix length /%u in '%s'\n", line_num, plen, token);
                            ret = -1;
                            break;
                        }
                    } else {
                        strncpy(ip_str, token, sizeof(ip_str) - 1);
                        ip_str[sizeof(ip_str) - 1] = '\0';
                    }
                    uint8_t ip6_buf[16] = {0};
                    if (inet_pton(AF_INET6, trim(ip_str), ip6_buf) != 1) {
                        fprintf(stderr, "Error [line %d]: Invalid IPv6 address '%s'\n", line_num, ip_str);
                        ret = -1;
                        break;
                    }
                    normalize_v6_cidr(ip6_buf, plen);
                    if (add_v6_rule(rc, ip6_buf, plen) != 0) {
                        fprintf(stderr, "Error: Memory allocation failure while parsing IPv6 rules\n");
                        ret = -1;
                        break;
                    }
                }
                token = strtok_r(NULL, " ,\t\r\n", &saveptr);
            }
            if (ret != 0) break;
        }
    }

    free(line);
    fclose(f);

    if (ret != 0 || rc->oom || section != 0) {
        if (section != 0 && ret == 0) {
            fprintf(stderr, "Error: Unexpected EOF while parsing element block (missing closing '}')\n");
        } else if (rc->oom && ret == 0) {
            fprintf(stderr, "Error: Memory allocation failure while parsing rules\n");
        }
        free_rule_collector(rc);
        return -1;
    }

    return 0;
}

static int do_stop(const char *pin_dir, const struct lan_ifaces *cli_lan_ifaces) {
    if (!pin_dir) pin_dir = DEFAULT_PIN_DIR;
    printf("[*] Stopping eBPF router and cleaning up pinned objects at %s...\n", pin_dir);

    uint32_t our_prog_id = get_pinned_tc_prog_id(pin_dir);

    /* 1. Detach TC ingress from all LAN interfaces (both saved, CLI specified, and live discovered) */
    struct lan_ifaces to_detach = {0};
    load_lan_ifaces(pin_dir, &to_detach);
    if (cli_lan_ifaces) {
        for (int i = 0; i < cli_lan_ifaces->count; i++) {
            add_lan_iface(&to_detach, cli_lan_ifaces->names[i]);
        }
    }
    struct if_nameindex *if_list = if_nameindex();
    if (if_list) {
        for (struct if_nameindex *i = if_list; i->if_index && i->if_name; ++i) {
            if (is_tc_ingress_attached_ext(i->if_name, our_prog_id, false)) {
                add_lan_iface(&to_detach, i->if_name);
            }
        }
        if_freenameindex(if_list);
    }
    for (int i = 0; i < to_detach.count; i++) {
        tc_detach_interface(to_detach.names[i]);
    }
    remove_pinned(pin_dir, LAN_IFACES_FILENAME);
    remove_pinned(pin_dir, "lan_ifaces");
    char txt_path[512];
    snprintf(txt_path, sizeof(txt_path), "%s/%s.txt", pin_dir, LAN_IFACES_FILENAME);
    unlink(txt_path);
    snprintf(txt_path, sizeof(txt_path), "%s/lan_ifaces.txt", pin_dir);
    unlink(txt_path);
    snprintf(txt_path, sizeof(txt_path), "%s/%s", pin_dir, OIF_DEV_FILENAME);
    unlink(txt_path);

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
        if (strcmp(pin_dir, "/sys/fs/bpf") != 0 && strcmp(pin_dir, "/sys/fs") != 0 &&
            strcmp(pin_dir, "/sys") != 0 && strcmp(pin_dir, "/") != 0) {
            if (rmdir(pin_dir) != 0 && errno != ENOENT) {
                fprintf(stderr, "Warning: failed to remove directory '%s': %s\n", pin_dir, strerror(errno));
            }
        }
    }
    printf("[✔] Successfully stopped and unpinned.\n");
    return 0;
}

static int get_interface_ips(const char *ifname, uint32_t *ip4_be, uint32_t ip6_be[4]) {
    struct ifaddrs *ifaddr, *ifa;
    *ip4_be = 0;
    memset(ip6_be, 0, sizeof(uint32_t) * 4);

    if (getifaddrs(&ifaddr) == -1)
        return -1;

    bool found_usable_ip = false;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || strcmp(ifa->ifa_name, ifname) != 0)
            continue;

        bool is_loopback = (strcmp(ifname, "lo") == 0 || (ifa->ifa_flags & IFF_LOOPBACK));

        if (ifa->ifa_addr->sa_family == AF_INET && *ip4_be == 0) {
            struct sockaddr_in *p4 = (struct sockaddr_in *)ifa->ifa_addr;
            uint32_t ip = ntohl(p4->sin_addr.s_addr);
            /* Exclude loopback (127.0.0.0/8) unless querying loopback interface, and exclude link-local (169.254.0.0/16 APIPA) */
            if ((is_loopback || (ip >> 24) != 127) && (ip & 0xFFFF0000) != 0xA9FE0000) {
                *ip4_be = p4->sin_addr.s_addr;
                found_usable_ip = true;
            }
        } else if (ifa->ifa_addr->sa_family == AF_INET6 && !has_ip6(ip6_be)) {
            struct sockaddr_in6 *p6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            /* Exclude loopback (::1) unless querying loopback interface, and exclude link-local (fe80::/10) */
            if ((is_loopback || !IN6_IS_ADDR_LOOPBACK(&p6->sin6_addr)) && !IN6_IS_ADDR_LINKLOCAL(&p6->sin6_addr)) {
                memcpy(ip6_be, &p6->sin6_addr, sizeof(uint32_t) * 4);
                found_usable_ip = true;
            }
        }
    }

    freeifaddrs(ifaddr);
    return found_usable_ip ? 0 : -1;
}

static int apply_nft_rules(const char *rule_file, const char *wg_endpoint_str, const char *fwmark_override_str, const char *pin_dir, const char *oif_dev) {
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

    if (oif_dev && strlen(oif_dev) > 0) {
        struct lan_ifaces cur_lan = {0};
        load_lan_ifaces(pin_dir, &cur_lan);
        for (int i = 0; i < cur_lan.count; i++) {
            if (strcmp(cur_lan.names[i], oif_dev) == 0) {
                fprintf(stderr, "Error: Outbound interface '%s' cannot be identical to inbound LAN interface!\n", oif_dev);
                close(cfg_fd);
                close(ep_fd);
                close(v4_fd);
                close(v6_fd);
                free_rule_collector(&rc);
                return -1;
            }
        }
    }

    rc.v4_count = deduplicate_v4(rc.v4_keys, rc.v4_count);
    rc.v6_count = deduplicate_v6(rc.v6_keys, rc.v6_count);

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

    /* Prune stale entries from prior runs while avoiding zero-rule window */
    prune_lpm_v4_map(v4_fd, rc.v4_keys, rc.v4_count);
    prune_lpm_v6_map(v6_fd, rc.v6_keys, rc.v6_count);

    /* 1. Update Config Map */
    uint32_t zero = 0;
    struct router_config cfg = {0};

    /* Preserve existing oif settings on reload unless explicitly overridden */
    if (bpf_map_lookup_elem(cfg_fd, &zero, &cfg) != 0) {
        memset(&cfg, 0, sizeof(cfg));
    }

    cfg.fwmark = rc.fwmark;
    cfg.enabled = 1;

    if (oif_dev && strlen(oif_dev) > 0) {
        strncpy(cfg.oif_name, oif_dev, sizeof(cfg.oif_name) - 1);
        cfg.oif_name[sizeof(cfg.oif_name) - 1] = '\0';
        if (get_interface_ips(oif_dev, &cfg.oif_src_ip4, cfg.oif_src_ip6) == 0) {
            char buf4[INET_ADDRSTRLEN] = "none";
            char buf6[INET6_ADDRSTRLEN] = "none";
            if (cfg.oif_src_ip4)
                inet_ntop(AF_INET, &cfg.oif_src_ip4, buf4, sizeof(buf4));
            if (has_ip6(cfg.oif_src_ip6))
                inet_ntop(AF_INET6, cfg.oif_src_ip6, buf6, sizeof(buf6));
            printf("  -> Outbound Interface (oif: %s) Source IPs: IPv4=%s, IPv6=%s\n", oif_dev, buf4, buf6);
        } else {
            fprintf(stderr, "  [!] Warning: Outbound interface '%s' not found or has no valid IPv4/IPv6 assigned, skipping source IP binding.\n", oif_dev);
            cfg.oif_src_ip4 = 0;
            memset(cfg.oif_src_ip6, 0, sizeof(cfg.oif_src_ip6));
        }
        bpf_map_update_elem(cfg_fd, &zero, &cfg, BPF_ANY);
        save_oif_dev(pin_dir, oif_dev);
    } else if (cfg.oif_src_ip4 || has_ip6(cfg.oif_src_ip6) || cfg.oif_name[0] != '\0') {
        if (cfg.oif_name[0] != '\0') {
            /* Try re-probing interface IP in case interface acquired/changed IP (e.g. WireGuard handshake, DHCP) */
            uint32_t new_ip4 = 0;
            uint32_t new_ip6[4] = {0};
            if (get_interface_ips(cfg.oif_name, &new_ip4, new_ip6) == 0) {
                cfg.oif_src_ip4 = new_ip4;
                memcpy(cfg.oif_src_ip6, new_ip6, sizeof(cfg.oif_src_ip6));
            }
        }
        char buf4[INET_ADDRSTRLEN] = "none";
        char buf6[INET6_ADDRSTRLEN] = "none";
        if (cfg.oif_src_ip4)
            inet_ntop(AF_INET, &cfg.oif_src_ip4, buf4, sizeof(buf4));
        if (has_ip6(cfg.oif_src_ip6))
            inet_ntop(AF_INET6, cfg.oif_src_ip6, buf6, sizeof(buf6));
        if (cfg.oif_name[0] != '\0') {
            printf("  -> Preserving existing Outbound Interface (oif: %s) Source IPs: IPv4=%s, IPv6=%s\n", cfg.oif_name, buf4, buf6);
        } else {
            printf("  -> Preserving existing Outbound Interface Source IPs: IPv4=%s, IPv6=%s\n", buf4, buf6);
        }
        bpf_map_update_elem(cfg_fd, &zero, &cfg, BPF_ANY);
    } else {
        printf("  -> Outbound Interface (oif): None (UDP source IP injection disabled)\n");
        bpf_map_update_elem(cfg_fd, &zero, &cfg, BPF_ANY);
    }
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
    if (v4_loaded < (int)rc.v4_count) {
        fprintf(stderr, "Warning: %d of %zu IPv4 bypass rules could not be loaded into bypass_v4_map (map capacity reached?)\n",
                (int)rc.v4_count - v4_loaded, rc.v4_count);
    }
    printf("  -> Loaded %d IPv6 CIDR rules into bypass_v6_map\n", v6_loaded);
    if (v6_loaded < (int)rc.v6_count) {
        fprintf(stderr, "Warning: %d of %zu IPv6 bypass rules could not be loaded into bypass_v6_map (map capacity reached?)\n",
                (int)rc.v6_count - v6_loaded, rc.v6_count);
    }
    printf("[✔] Successfully applied all routing rules!\n");

    close(cfg_fd);
    close(ep_fd);
    close(v4_fd);
    close(v6_fd);
    free_rule_collector(&rc);
    return 0;
}

static int do_start(const char *cgroup_path, const char *rule_file, const char *wg_endpoint, const char *fwmark, const char *pin_dir, const struct lan_ifaces *lan_list, const char *oif_dev) {
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

    /* Re-ensure pin_dir exists because do_stop removes empty directories */
    err = ensure_dir(pin_dir);
    if (err != 0) {
        fprintf(stderr, "Error: Failed to recreate bpffs dir %s: %s\n", pin_dir, strerror(-err));
        close(cgroup_fd);
        return 1;
    }

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
    err = apply_nft_rules(rule_file, wg_endpoint, fwmark, pin_dir, oif_dev);
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

static int do_add_iif(const struct lan_ifaces *lan_list, const char *pin_dir) {
    if (!pin_dir) pin_dir = DEFAULT_PIN_DIR;
    char prog_path[512];
    snprintf(prog_path, sizeof(prog_path), "%s/%s", pin_dir, TC_PROG_FILENAME);
    int prog_fd = bpf_obj_get(prog_path);
    if (prog_fd < 0) {
        fprintf(stderr, "Error: Router is not running or TC ingress program not found at %s. Is the router loaded?\n",
                prog_path);
        return 1;
    }

    uint32_t our_prog_id = get_pinned_tc_prog_id(pin_dir);

    struct lan_ifaces cur_list = {0};
    load_lan_ifaces(pin_dir, &cur_list);

    /* Also discover any attached interface */
    struct if_nameindex *if_list = if_nameindex();
    if (if_list) {
        for (struct if_nameindex *i = if_list; i->if_index && i->if_name; ++i) {
            if (is_tc_ingress_attached_ext(i->if_name, our_prog_id, false)) {
                add_lan_iface(&cur_list, i->if_name);
            }
        }
        if_freenameindex(if_list);
    }

    struct lan_ifaces to_add = {0};
    if (lan_list) {
        for (int i = 0; i < lan_list->count; i++) {
            add_lan_iface(&to_add, lan_list->names[i]);
        }
    }

    char saved_oif[IFNAMSIZ] = {0};
    const char *exclude_oif = (load_oif_dev(pin_dir, saved_oif, sizeof(saved_oif)) == 0 && saved_oif[0] != '\0') ? saved_oif : NULL;

    if (resolve_lan_ifaces(&to_add, exclude_oif) != 0 || to_add.count == 0) {
        fprintf(stderr, "Error: No valid interface names specified or resolved.\n");
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

static int do_del_iif(const struct lan_ifaces *lan_list, const char *pin_dir) {
    if (!pin_dir) pin_dir = DEFAULT_PIN_DIR;

    uint32_t our_prog_id = get_pinned_tc_prog_id(pin_dir);

    struct lan_ifaces cur_list = {0};
    load_lan_ifaces(pin_dir, &cur_list);

    /* Also discover any attached interface */
    struct if_nameindex *if_list = if_nameindex();
    if (if_list) {
        for (struct if_nameindex *i = if_list; i->if_index && i->if_name; ++i) {
            if (is_tc_ingress_attached_ext(i->if_name, our_prog_id, false)) {
                add_lan_iface(&cur_list, i->if_name);
            }
        }
        if_freenameindex(if_list);
    }

    if (!lan_list || lan_list->count == 0) {
        fprintf(stderr, "Error: missing interface argument for del-iif. Specify interface name(s) or 'all'.\n");
        return 1;
    }

    for (int i = 0; i < lan_list->count; i++) {
        if (is_auto_interface_keyword(lan_list->names[i])) {
            fprintf(stderr, "Error: '%s' is not supported for del-iif to prevent accidentally detaching WAN. Specify explicit interface name(s) (e.g. 'del-iif eth1') or 'all'.\n", lan_list->names[i]);
            return 1;
        }
    }

    bool del_all = false;
    for (int i = 0; i < lan_list->count; i++) {
        if (strcasecmp(lan_list->names[i], "all") == 0) {
            del_all = true;
            break;
        }
    }

    if (del_all) {
        if (cur_list.count == 0) {
            printf("[-] No tracked or attached LAN interfaces found to detach.\n");
            return 0;
        }
        int detached = 0;
        for (int i = 0; i < cur_list.count; i++) {
            tc_detach_interface(cur_list.names[i]);
            printf("[-] Detached TC ingress filter from '%s'\n", cur_list.names[i]);
            detached++;
        }
        cur_list.count = 0;
        save_lan_ifaces(pin_dir, &cur_list);
        printf("[✔] Successfully detached and removed %d LAN interface(s)!\n", detached);
        return 0;
    }

    struct lan_ifaces to_del = {0};
    for (int i = 0; i < lan_list->count; i++) {
        add_lan_iface(&to_del, lan_list->names[i]);
    }

    int detached = 0;
    for (int i = 0; i < to_del.count; i++) {
        const char *name = to_del.names[i];
        bool was_tracked = false;
        for (int j = 0; j < cur_list.count; j++) {
            if (strcmp(cur_list.names[j], name) == 0) {
                was_tracked = true;
                break;
            }
        }
        bool was_attached = is_tc_ingress_attached(name, our_prog_id);
        if (!was_tracked && !was_attached) {
            printf("[-] Interface '%s' is not attached or tracked; skipping.\n", name);
            continue;
        }
        tc_detach_interface(name);
        remove_lan_iface(&cur_list, name);
        printf("[-] Detached TC ingress filter from '%s'\n", name);
        detached++;
    }

    save_lan_ifaces(pin_dir, &cur_list);
    if (detached > 0) {
        printf("[✔] Successfully detached and removed %d LAN interface(s)!\n", detached);
    } else {
        printf("[-] No specified interfaces were currently attached or tracked.\n");
    }
    return 0;
}

static int do_set_oif(const char *ifname, const char *pin_dir) {
    if (!pin_dir) pin_dir = DEFAULT_PIN_DIR;
    if (!ifname || strlen(ifname) == 0) {
        fprintf(stderr, "Error: missing interface name for set-oif. Usage: set-oif <iface>\n");
        return 1;
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/router_config_map", pin_dir);
    int cfg_fd = bpf_obj_get(path);
    if (cfg_fd < 0) {
        fprintf(stderr, "Error: Failed to open router_config_map at %s. Is the router loaded?\n", pin_dir);
        return 1;
    }

    uint32_t zero = 0;
    struct router_config cfg;
    if (bpf_map_lookup_elem(cfg_fd, &zero, &cfg) != 0) {
        fprintf(stderr, "Error: Failed to read router_config_map: %s\n", strerror(errno));
        close(cfg_fd);
        return 1;
    }

    struct lan_ifaces cur_lan = {0};
    load_lan_ifaces(pin_dir, &cur_lan);
    for (int i = 0; i < cur_lan.count; i++) {
        if (strcmp(cur_lan.names[i], ifname) == 0) {
            fprintf(stderr, "Error: Outbound interface '%s' cannot be identical to currently attached inbound LAN interface!\n", ifname);
            close(cfg_fd);
            return 1;
        }
    }

    if (get_interface_ips(ifname, &cfg.oif_src_ip4, cfg.oif_src_ip6) != 0) {
        fprintf(stderr, "  [!] Warning: Outbound interface '%s' not found or has no valid IPv4/IPv6 assigned, skipping source IP binding (fwmark-only mode active).\n", ifname);
        cfg.oif_src_ip4 = 0;
        memset(cfg.oif_src_ip6, 0, sizeof(cfg.oif_src_ip6));
    }

    strncpy(cfg.oif_name, ifname, sizeof(cfg.oif_name) - 1);
    cfg.oif_name[sizeof(cfg.oif_name) - 1] = '\0';

    if (bpf_map_update_elem(cfg_fd, &zero, &cfg, BPF_ANY) != 0) {
        fprintf(stderr, "Error: Failed to update router_config_map: %s\n", strerror(errno));
        close(cfg_fd);
        return 1;
    }
    close(cfg_fd);
    save_oif_dev(pin_dir, ifname);

    char buf4[INET_ADDRSTRLEN] = "none";
    char buf6[INET6_ADDRSTRLEN] = "none";
    if (cfg.oif_src_ip4)
        inet_ntop(AF_INET, &cfg.oif_src_ip4, buf4, sizeof(buf4));
    if (has_ip6(cfg.oif_src_ip6))
        inet_ntop(AF_INET6, cfg.oif_src_ip6, buf6, sizeof(buf6));

    printf("[✔] Outbound interface (oif) updated to '%s' (IPv4: %s, IPv6: %s)\n", ifname, buf4, buf6);
    return 0;
}

static int do_del_oif(const char *pin_dir) {
    if (!pin_dir) pin_dir = DEFAULT_PIN_DIR;

    char path[512];
    snprintf(path, sizeof(path), "%s/router_config_map", pin_dir);
    int cfg_fd = bpf_obj_get(path);
    if (cfg_fd < 0) {
        fprintf(stderr, "Error: Failed to open router_config_map at %s. Is the router loaded?\n", pin_dir);
        return 1;
    }

    uint32_t zero = 0;
    struct router_config cfg;
    if (bpf_map_lookup_elem(cfg_fd, &zero, &cfg) != 0) {
        fprintf(stderr, "Error: Failed to read router_config_map: %s\n", strerror(errno));
        close(cfg_fd);
        return 1;
    }

    cfg.oif_src_ip4 = 0;
    memset(cfg.oif_src_ip6, 0, sizeof(cfg.oif_src_ip6));
    memset(cfg.oif_name, 0, sizeof(cfg.oif_name));

    if (bpf_map_update_elem(cfg_fd, &zero, &cfg, BPF_ANY) != 0) {
        fprintf(stderr, "Error: Failed to update router_config_map: %s\n", strerror(errno));
        close(cfg_fd);
        return 1;
    }
    close(cfg_fd);
    save_oif_dev(pin_dir, NULL);

    printf("[✔] Outbound interface (oif) removed (UDP source IP injection disabled, fwmark-only mode active)\n");
    return 0;
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

    uint32_t zero = 0;
    struct wg_endpoint ep = {0};

    if (!endpoint_str || *endpoint_str == '\0' ||
        strcasecmp(endpoint_str, "none") == 0 ||
        strcasecmp(endpoint_str, "disable") == 0 ||
        strcasecmp(endpoint_str, "disabled") == 0 ||
        strcmp(endpoint_str, "\"\"") == 0 ||
        strcmp(endpoint_str, "''") == 0) {
        if (bpf_map_update_elem(ep_fd, &zero, &ep, BPF_ANY) != 0) {
            fprintf(stderr, "Error: Failed to update wg_endpoint_map: %s\n", strerror(errno));
            close(ep_fd);
            return 1;
        }
        close(ep_fd);
        printf("[✔] WireGuard anti-loopback endpoint disabled (removed).\n");
        return 0;
    }

    if (parse_endpoint(endpoint_str, &ep) != 0) {
        close(ep_fd);
        return 1;
    }

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

    uint32_t our_prog_id = get_pinned_tc_prog_id(pin_dir);

    /* Show attached LAN interfaces and their live kernel state */
    struct lan_ifaces lan_list = {0};
    load_lan_ifaces(pin_dir, &lan_list);

    /* Auto-discover interfaces on the system that have our TC ingress attached */
    struct if_nameindex *if_list = if_nameindex();
    if (if_list) {
        for (struct if_nameindex *i = if_list; i->if_index && i->if_name; ++i) {
            if (is_tc_ingress_attached_ext(i->if_name, our_prog_id, false)) {
                add_lan_iface(&lan_list, i->if_name);
            }
        }
        if_freenameindex(if_list);
    }

    if (lan_list.count > 0) {
        printf("  Inbound Interfaces (iif / TC Ingress Forwarding):\n");
        for (int i = 0; i < lan_list.count; i++) {
            const char *name = lan_list.names[i];
            unsigned int ifidx = if_nametoindex(name);
            if (ifidx == 0) {
                printf("    - %-12s: [MISSING / DOWN] (Device not present in system)\n", name);
            } else if (is_tc_ingress_attached(name, our_prog_id)) {
                printf("    - %-12s: [ACTIVE] (ifindex %u, TC ingress filter active)\n", name, ifidx);
            } else {
                printf("    - %-12s: [DETACHED / RECREATED] (ifindex %u, filter missing - run 'add-iif %s' to reattach)\n",
                       name, ifidx, name);
            }
        }
    } else {
        printf("  Inbound Interfaces (iif / TC Ingress): None (Local-only mode)\n");
    }

    char path[512];
    snprintf(path, sizeof(path), "%s/router_config_map", pin_dir);
    int cfg_fd = bpf_obj_get(path);
    if (cfg_fd >= 0) {
        uint32_t zero = 0;
        struct router_config cfg = {0}; /* Zero-init protects against cross-version stack garbage */
        if (bpf_map_lookup_elem(cfg_fd, &zero, &cfg) == 0) {
            printf("  Enabled: %s, FWMARK: 0x%x (%u)\n", cfg.enabled ? "true" : "false", cfg.fwmark, cfg.fwmark);
            if (cfg.oif_src_ip4 || has_ip6(cfg.oif_src_ip6) || cfg.oif_name[0] != '\0') {
                char buf4[INET_ADDRSTRLEN] = "none";
                char buf6[INET6_ADDRSTRLEN] = "none";
                if (cfg.oif_src_ip4)
                    inet_ntop(AF_INET, &cfg.oif_src_ip4, buf4, sizeof(buf4));
                if (has_ip6(cfg.oif_src_ip6))
                    inet_ntop(AF_INET6, cfg.oif_src_ip6, buf6, sizeof(buf6));
                if (cfg.oif_name[0] != '\0') {
                    printf("  UDP Injected Egress IPs (oif: %s): IPv4=%s, IPv6=%s\n", cfg.oif_name, buf4, buf6);
                } else {
                    printf("  UDP Injected Egress IPs (oif): IPv4=%s, IPv6=%s\n", buf4, buf6);
                }
            } else {
                printf("  UDP Injected Egress IPs (oif): Disabled (fwmark-only mode)\n");
            }
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
    printf("Usage: %s <start|stop|reload|set-endpoint|del-endpoint|set-oif|del-oif|add-iif|del-iif|status> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  start          Load eBPF, attach to cgroup and optional LAN interfaces, and apply rules\n");
    printf("                 Options: --cgroup-path <path>    (default: /sys/fs/cgroup)\n");
    printf("                          --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n");
    printf("                          --wg-endpoint <IP[:Port]>\n");
    printf("                          --rule-file <var.nft>   (required)\n");
    printf("                          --fwmark <mark>         (optional override)\n");
    printf("                          --oif <iface>           (optional outbound interface to bind UDP source IP, e.g. wg0)\n");
    printf("                          --iif <iface>           (optional inbound/LAN interfaces for TC ingress,\n");
    printf("                                                   can be 'auto'/'default'/'primary' to auto-detect default route interface,\n");
    printf("                                                   or repeated/comma-separated, e.g. --iif auto, --iif eth1,eth2; alias: --lan-if)\n\n");
    printf("  stop           Detach eBPF programs, TC ingress filters, and remove pinned objects\n");
    printf("                 Options: --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n");
    printf("                          --iif <iface>           (optional explicit inbound/LAN interfaces to detach;\n");
    printf("                                                   can be 'auto'/'default'/'primary'; alias: --lan-if)\n\n");
    printf("  reload         Hot-reload nftables rule file into BPF maps (no detach)\n");
    printf("                 Options: --rule-file <var.nft>   (required)\n");
    printf("                          --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n");
    printf("                          --wg-endpoint <IP[:Port]>\n");
    printf("                          --fwmark <mark>\n");
    printf("                          --oif <iface>           (optional outbound interface to bind UDP source IP)\n\n");
    printf("  set-endpoint   Dynamically update WireGuard endpoint (IP[:Port], or 'none' to disable)\n");
    printf("                 Options: --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n");
    printf("                 Usage:   %s set-endpoint <IP[:Port]|none> [--pin-dir <path>]\n\n", prog);
    printf("  del-endpoint   Dynamically remove WireGuard endpoint (disables anti-loopback bypass)\n");
    printf("                 Options: --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n");
    printf("                 Usage:   %s del-endpoint [--pin-dir <path>]\n\n", prog);
    printf("  set-oif        Dynamically set/update outbound interface (oif) and its source IP\n");
    printf("                 Options: --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n");
    printf("                 Usage:   %s set-oif <iface> [--pin-dir <path>]\n\n", prog);
    printf("  del-oif        Dynamically remove outbound interface (oif) and disable source IP injection\n");
    printf("                 Options: --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n");
    printf("                 Usage:   %s del-oif [--pin-dir <path>]\n\n", prog);
    printf("  add-iif        Dynamically attach TC ingress filter to inbound/LAN interface(s) (alias: add-if)\n");
    printf("                 Options: --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n");
    printf("                 Usage:   %s add-iif <iface[,iface2]|auto|default|primary> [--pin-dir <path>]\n\n", prog);
    printf("  del-iif        Dynamically detach TC ingress filter from inbound/LAN interface(s) (alias: del-if)\n");
    printf("                 Options: --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n");
    printf("                 Usage:   %s del-iif <iface[,iface2]|all> [--pin-dir <path>]\n\n", prog);
    printf("  status         Show current eBPF router status, LAN interfaces, and map statistics\n");
    printf("                 Options: --pin-dir <path>        (default: /sys/fs/bpf/wg_routing)\n");
    printf("                 Usage:   %s status [--pin-dir <path>]\n", prog);
}

int router_ctl_main(int argc, char **argv) {
    libbpf_set_print(libbpf_print_fn);

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];
    const char *pin_dir = DEFAULT_PIN_DIR;

    if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0 || strcmp(cmd, "help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    if (strcmp(cmd, "start") == 0 || strcmp(cmd, "load") == 0) {
        const char *cgroup_path = DEFAULT_CGROUP_PATH;
        const char *rule_file = NULL;
        const char *wg_endpoint = NULL;
        const char *fwmark = NULL;
        const char *oif_dev = NULL;
        struct lan_ifaces lan_list = {0};

        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--cgroup-path") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                cgroup_path = argv[++i];
            } else if (strcmp(argv[i], "--pin-dir") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                pin_dir = argv[++i];
            } else if (strcmp(argv[i], "--rule-file") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                rule_file = argv[++i];
            } else if (strcmp(argv[i], "--wg-endpoint") == 0 || strcmp(argv[i], "--endpoint") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                wg_endpoint = argv[++i];
            } else if (strcmp(argv[i], "--fwmark") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                fwmark = argv[++i];
            } else if (strcmp(argv[i], "--oif") == 0 || strcmp(argv[i], "--egress-dev") == 0 || strcmp(argv[i], "--wg-dev") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                oif_dev = argv[++i];
            } else if (strcmp(argv[i], "--iif") == 0 || strcmp(argv[i], "--lan-if") == 0 || strcmp(argv[i], "--forward-if") == 0 ||
                       strcmp(argv[i], "--lan-interface") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') {
                    fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]);
                    return 1;
                }
                add_lan_iface(&lan_list, argv[++i]);
            } else {
                fprintf(stderr, "Unknown argument '%s'\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        }
        if (resolve_lan_ifaces(&lan_list, oif_dev) != 0) {
            return 1;
        }
        return do_start(cgroup_path, rule_file, wg_endpoint, fwmark, pin_dir, &lan_list, oif_dev);
    } else if (strcmp(cmd, "stop") == 0 || strcmp(cmd, "unload") == 0) {
        struct lan_ifaces cli_lan = {0};
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--pin-dir") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                pin_dir = argv[++i];
            } else if (strcmp(argv[i], "--iif") == 0 || strcmp(argv[i], "--lan-if") == 0 || strcmp(argv[i], "--forward-if") == 0 ||
                       strcmp(argv[i], "--lan-interface") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') {
                    fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]);
                    return 1;
                }
                add_lan_iface(&cli_lan, argv[++i]);
            } else {
                fprintf(stderr, "Unknown argument '%s'\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        }
        if (cli_lan.count > 0) {
            if (resolve_lan_ifaces(&cli_lan, NULL) != 0 || cli_lan.count == 0) {
                fprintf(stderr, "Warning: Specified --iif interface could not be resolved; continuing cleanup.\n");
            }
        }
        return do_stop(pin_dir, &cli_lan);
    } else if (strcmp(cmd, "reload") == 0 || strcmp(cmd, "apply") == 0) {
        const char *rule_file = NULL;
        const char *wg_endpoint = NULL;
        const char *fwmark = NULL;
        const char *oif_dev = NULL;

        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--rule-file") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                rule_file = argv[++i];
            } else if (strcmp(argv[i], "--pin-dir") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                pin_dir = argv[++i];
            } else if (strcmp(argv[i], "--wg-endpoint") == 0 || strcmp(argv[i], "--endpoint") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                wg_endpoint = argv[++i];
            } else if (strcmp(argv[i], "--fwmark") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                fwmark = argv[++i];
            } else if (strcmp(argv[i], "--oif") == 0 || strcmp(argv[i], "--egress-dev") == 0 || strcmp(argv[i], "--wg-dev") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                oif_dev = argv[++i];
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
        return apply_nft_rules(rule_file, wg_endpoint, fwmark, pin_dir, oif_dev);
    } else if (strcmp(cmd, "set-endpoint") == 0) {
        const char *ep_str = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--pin-dir") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                pin_dir = argv[++i];
            } else if ((strcmp(argv[i], "--wg-endpoint") == 0 || strcmp(argv[i], "--endpoint") == 0)) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                ep_str = argv[++i];
            } else if (!ep_str && argv[i][0] != '-') {
                ep_str = argv[i];
            } else {
                fprintf(stderr, "Unknown argument '%s'\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        }
        if (!ep_str) {
            fprintf(stderr, "Error: missing endpoint argument. Usage: %s set-endpoint <IP[:Port]|none> [--pin-dir <path>]\n", argv[0]);
            return 1;
        }
        return do_set_endpoint(ep_str, pin_dir);
    } else if (strcmp(cmd, "del-endpoint") == 0 || strcmp(cmd, "unset-endpoint") == 0 || strcmp(cmd, "clear-endpoint") == 0) {
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--pin-dir") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                pin_dir = argv[++i];
            } else if (argv[i][0] != '-') {
                /* ignore */
            } else {
                fprintf(stderr, "Unknown argument '%s'\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        }
        return do_set_endpoint("none", pin_dir);
    } else if (strcmp(cmd, "set-oif") == 0 || strcmp(cmd, "add-oif") == 0) {
        const char *oif_name = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--pin-dir") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                pin_dir = argv[++i];
            } else if (strcmp(argv[i], "--oif") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                oif_name = argv[++i];
            } else if (!oif_name && argv[i][0] != '-') {
                oif_name = argv[i];
            } else {
                fprintf(stderr, "Unknown argument '%s'\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        }
        if (!oif_name) {
            fprintf(stderr, "Error: missing interface argument. Usage: %s set-oif <iface> [--pin-dir <path>]\n", argv[0]);
            return 1;
        }
        return do_set_oif(oif_name, pin_dir);
    } else if (strcmp(cmd, "del-oif") == 0 || strcmp(cmd, "unset-oif") == 0 || strcmp(cmd, "clear-oif") == 0) {
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--pin-dir") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                pin_dir = argv[++i];
            } else if (argv[i][0] != '-') {
                /* ignore */
            } else {
                fprintf(stderr, "Unknown argument '%s'\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        }
        return do_del_oif(pin_dir);
    } else if (strcmp(cmd, "add-iif") == 0 || strcmp(cmd, "add-if") == 0 ||
               strcmp(cmd, "set-iif") == 0 || strcmp(cmd, "add-lan-if") == 0) {
        struct lan_ifaces lan_list = {0};
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--pin-dir") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                pin_dir = argv[++i];
            } else if (strcmp(argv[i], "--iif") == 0 || strcmp(argv[i], "--lan-if") == 0 || strcmp(argv[i], "--if") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                add_lan_iface(&lan_list, argv[++i]);
            } else if (argv[i][0] != '-') {
                add_lan_iface(&lan_list, argv[i]);
            } else {
                fprintf(stderr, "Unknown argument '%s'\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        }
        if (lan_list.count == 0) {
            fprintf(stderr, "Error: missing interface argument for add-iif. Specify interface name(s) or 'auto'. Usage: %s add-iif <iface[,iface2]|auto> [--pin-dir <path>]\n", argv[0]);
            return 1;
        }
        return do_add_iif(&lan_list, pin_dir);
    } else if (strcmp(cmd, "del-iif") == 0 || strcmp(cmd, "del-if") == 0 ||
               strcmp(cmd, "unset-iif") == 0 || strcmp(cmd, "del-lan-if") == 0 || strcmp(cmd, "remove-if") == 0) {
        struct lan_ifaces lan_list = {0};
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--pin-dir") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                pin_dir = argv[++i];
            } else if (strcmp(argv[i], "--iif") == 0 || strcmp(argv[i], "--lan-if") == 0 || strcmp(argv[i], "--if") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
                add_lan_iface(&lan_list, argv[++i]);
            } else if (argv[i][0] != '-') {
                add_lan_iface(&lan_list, argv[i]);
            } else {
                fprintf(stderr, "Unknown argument '%s'\n", argv[i]);
                print_usage(argv[0]);
                return 1;
            }
        }
        if (lan_list.count == 0) {
            fprintf(stderr, "Error: missing interface argument for del-iif. Specify interface name(s) or 'all'. Usage: %s del-iif <iface[,iface2]|all> [--pin-dir <path>]\n", argv[0]);
            return 1;
        }
        return do_del_iif(&lan_list, pin_dir);
    } else if (strcmp(cmd, "status") == 0) {
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--pin-dir") == 0) {
                if (i + 1 >= argc || argv[i + 1][0] == '-') { fprintf(stderr, "Error: Option '%s' requires an argument\n", argv[i]); return 1; }
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

#ifndef UNIT_TESTING
int main(int argc, char **argv) {
    return router_ctl_main(argc, argv);
}
#endif
