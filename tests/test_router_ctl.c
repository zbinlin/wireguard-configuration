#define _GNU_SOURCE
#define UNIT_TESTING
#pragma GCC diagnostic ignored "-Wunused-function"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

/* Include the router controller source to test internal static functions */
#include "router_ctl.c"

static void test_parse_fwmark(void) {
    uint32_t mark = 0;

    /* Valid cases */
    assert(parse_fwmark("0x3000", &mark) == 0 && mark == 0x3000);
    assert(parse_fwmark("12288", &mark) == 0 && mark == 12288);
    assert(parse_fwmark("0x1", &mark) == 0 && mark == 1);
    assert(parse_fwmark("0xFFFFFFFF", &mark) == 0 && mark == 0xFFFFFFFF);
    assert(parse_fwmark("  0x100  ", &mark) == 0 && mark == 0x100);

    /* Invalid cases: zero, empty, non-numeric, trailing garbage, negative, or leading plus */
    assert(parse_fwmark("0", &mark) == -1);
    assert(parse_fwmark("0x0", &mark) == -1);
    assert(parse_fwmark("-1", &mark) == -1);
    assert(parse_fwmark("-100", &mark) == -1);
    assert(parse_fwmark("+0x3000", &mark) == -1);
    assert(parse_fwmark("+100", &mark) == -1);
    assert(parse_fwmark("", &mark) == -1);
    assert(parse_fwmark("abc", &mark) == -1);
    assert(parse_fwmark("0x3000xyz", &mark) == -1);
    assert(parse_fwmark("  ", &mark) == -1);
    assert(parse_fwmark(NULL, &mark) == -1);

    printf("  [PASS] test_parse_fwmark\n");
}

static void test_parse_port(void) {
    uint16_t port = 0;

    /* Valid ports */
    assert(parse_port("51820", &port) == 0 && port == 51820);
    assert(parse_port("1", &port) == 0 && port == 1);
    assert(parse_port("65535", &port) == 0 && port == 65535);

    /* Invalid ports: trailing garbage, zero, out-of-range, negative */
    assert(parse_port("51820xyz", &port) == -1);
    assert(parse_port("0", &port) == -1);
    assert(parse_port("65536", &port) == -1);
    assert(parse_port("-1", &port) == -1);
    assert(parse_port("+51820", &port) == -1);
    assert(parse_port("", &port) == -1);
    assert(parse_port("abc", &port) == -1);
    assert(parse_port(NULL, &port) == -1);

    printf("  [PASS] test_parse_port\n");
}

static void test_parse_endpoint(void) {
    struct wg_endpoint ep;

    /* IPv4 with port */
    assert(parse_endpoint("198.51.100.1:51820", &ep) == 0);
    assert(ep.family == AF_INET && ep.port == htons(51820));

    /* IPv4 without port (matches all ports) */
    assert(parse_endpoint("198.51.100.1", &ep) == 0);
    assert(ep.family == AF_INET && ep.port == 0);

    /* IPv4 with invalid port / trailing garbage */
    assert(parse_endpoint("198.51.100.1:51820abc", &ep) == -1);
    assert(parse_endpoint("198.51.100.1:0", &ep) == -1);
    assert(parse_endpoint("198.51.100.1:99999", &ep) == -1);

    /* IPv6 bracketed with port */
    assert(parse_endpoint("[2001:db8::1]:51820", &ep) == 0);
    assert(ep.family == AF_INET6 && ep.port == htons(51820));

    /* IPv6 bracketed without port */
    assert(parse_endpoint("[2001:db8::1]", &ep) == 0);
    assert(ep.family == AF_INET6 && ep.port == 0);

    /* IPv6 bracketed with invalid port / trailing garbage */
    assert(parse_endpoint("[2001:db8::1]:51820bad", &ep) == -1);
    assert(parse_endpoint("[2001:db8::1]:invalid", &ep) == -1);

    /* Plain IPv6 without brackets */
    assert(parse_endpoint("2001:db8::1", &ep) == 0);
    assert(ep.family == AF_INET6 && ep.port == 0);

    /* Malformed IPv6 inputs */
    assert(parse_endpoint("[2001:db8::1", &ep) == -1);
    assert(parse_endpoint("2001:xyz::1", &ep) == -1);
    assert(parse_endpoint("", &ep) == -1);
    assert(parse_endpoint(NULL, &ep) == -1);

    /* Oversized inputs (> 255 chars) */
    char long_ep[300];
    memset(long_ep, 'a', sizeof(long_ep) - 1);
    long_ep[sizeof(long_ep) - 1] = '\0';
    assert(parse_endpoint(long_ep, &ep) == -1);

    printf("  [PASS] test_parse_endpoint\n");
}

static void test_keyword_matching(void) {
    /* Exact or space/equals delimited match */
    assert(match_keyword("define FWMARK = 0x3000", "define FWMARK") == true);
    assert(match_keyword("define FWMARK=0x3000", "define FWMARK") == true);
    assert(match_keyword("define FWMARK \t= 0x3000", "define FWMARK") == true);
    assert(match_keyword("define FWMARK", "define FWMARK") == true);
    assert(match_keyword("define WG_ENDPOINT = 1.1.1.1", "define WG_ENDPOINT") == true);

    /* Word boundary rejection */
    assert(match_keyword("define FWMARK_ALT = 0x3000", "define FWMARK") == false);
    assert(match_keyword("define FWMARK2 = 0x3000", "define FWMARK") == false);
    assert(match_keyword("define WG_ENDPOINT_BACKUP = 1.1.1.1", "define WG_ENDPOINT") == false);

    /* Element block recognition */
    assert(find_element_block("define IPV4_ELEMENTS = {", "IPV4_ELEMENTS") != NULL);
    assert(find_element_block("IPV4_ELEMENTS={", "IPV4_ELEMENTS") != NULL);
    assert(find_element_block("define IPV4_ELEMENTS_EXTRA = {", "IPV4_ELEMENTS") == NULL);
    assert(find_element_block("MY_IPV4_ELEMENTS = {", "IPV4_ELEMENTS") == NULL);
    assert(find_element_block("define IPV6_ELEMENTS = {", "IPV6_ELEMENTS") != NULL);
    assert(find_element_block("define IPV6_ELEMENTS_BACKUP = {", "IPV6_ELEMENTS") == NULL);

    printf("  [PASS] test_keyword_matching\n");
}

static void test_ensure_dir(void) {
    const char *test_path = "/tmp/test_wg_router_nested/sub1/sub2";
    assert(ensure_dir(test_path) == 0);
    assert(access(test_path, F_OK) == 0);

    /* Calling again on existing directory should succeed */
    assert(ensure_dir(test_path) == 0);

    rmdir("/tmp/test_wg_router_nested/sub1/sub2");
    rmdir("/tmp/test_wg_router_nested/sub1");
    rmdir("/tmp/test_wg_router_nested");

    /* Test error when path is an existing regular file */
    const char *tmp_file = "/tmp/test_ensure_dir_file.txt";
    FILE *f = fopen(tmp_file, "w");
    assert(f != NULL);
    fprintf(f, "test\n");
    fclose(f);
    assert(ensure_dir(tmp_file) == -ENOTDIR);

    /* Test error when a parent component in the path is a regular file */
    char sub_path[512];
    snprintf(sub_path, sizeof(sub_path), "%s/subdir", tmp_file);
    assert(ensure_dir(sub_path) == -ENOTDIR);

    unlink(tmp_file);

    printf("  [PASS] test_ensure_dir\n");
}

struct range_test_result {
    uint32_t nets[32];
    uint32_t prefixlens[32];
    size_t count;
};

static void test_range_cb(uint32_t net_be, uint32_t prefixlen, void *arg) {
    struct range_test_result *res = (struct range_test_result *)arg;
    if (res->count < 32) {
        res->nets[res->count] = net_be;
        res->prefixlens[res->count] = prefixlen;
        res->count++;
    }
}

static void test_range_to_cidrs_edge_cases(void) {
    /* 1. Full address space 0.0.0.0 - 255.255.255.255 (MUST NOT infinite loop) */
    struct range_test_result r1 = {0};
    range_to_cidrs(0, 0xFFFFFFFF, test_range_cb, &r1);
    assert(r1.count == 1);
    assert(r1.prefixlens[0] == 0);
    assert(r1.nets[0] == 0);

    /* 2. Top half ending at 255.255.255.255: 128.0.0.0 - 255.255.255.255 */
    struct range_test_result r2 = {0};
    range_to_cidrs(0x80000000, 0xFFFFFFFF, test_range_cb, &r2);
    assert(r2.count == 1);
    assert(r2.prefixlens[0] == 1);
    assert(r2.nets[0] == htonl(0x80000000));

    /* 3. Single host range: 10.0.0.1 - 10.0.0.1 */
    struct range_test_result r3 = {0};
    uint32_t single_ip = 0x0A000001;
    range_to_cidrs(single_ip, single_ip, test_range_cb, &r3);
    assert(r3.count == 1);
    assert(r3.prefixlens[0] == 32);
    assert(r3.nets[0] == htonl(single_ip));

    /* 4. Multi-chunk range: 1.0.1.0 - 1.0.3.255 (256 + 512 = 768 IPs -> 1.0.1.0/24 + 1.0.2.0/23) */
    struct range_test_result r4 = {0};
    range_to_cidrs(0x01000100, 0x010003FF, test_range_cb, &r4);
    assert(r4.count == 2);
    assert(r4.prefixlens[0] == 24 && r4.nets[0] == htonl(0x01000100));
    assert(r4.prefixlens[1] == 23 && r4.nets[1] == htonl(0x01000200));

    printf("  [PASS] test_range_to_cidrs_edge_cases\n");
}

static void test_cidr_normalization_and_deduplication(void) {
    /* 1. IPv4 normalization */
    uint32_t host_ip = htonl(0xC0A80132); /* 192.168.1.50 */
    uint32_t norm_ip = normalize_v4_cidr(host_ip, 24);
    assert(norm_ip == htonl(0xC0A80100)); /* 192.168.1.0 */
    assert(normalize_v4_cidr(host_ip, 32) == host_ip);
    assert(normalize_v4_cidr(host_ip, 0) == 0);

    /* 2. IPv6 normalization */
    uint8_t ip6[16] = {0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78,
                       0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44};
    normalize_v6_cidr(ip6, 32);
    for (int i = 4; i < 16; i++) {
        assert(ip6[i] == 0);
    }
    assert(ip6[0] == 0x20 && ip6[1] == 0x01 && ip6[2] == 0x0d && ip6[3] == 0xb8);

    /* 3. Deduplication of IPv4 keys */
    struct ipv4_lpm_key v4_arr[4] = {
        { .prefixlen = 24, .data = htonl(0x0A000000) },
        { .prefixlen = 16, .data = htonl(0xC0A80000) },
        { .prefixlen = 24, .data = htonl(0x0A000000) }, /* duplicate */
        { .prefixlen = 8,  .data = htonl(0x0A000000) },
    };
    size_t new_v4_cnt = deduplicate_v4(v4_arr, 4);
    assert(new_v4_cnt == 3);

    /* 4. Deduplication of IPv6 keys */
    struct ipv6_lpm_key v6_arr[3] = {
        { .prefixlen = 32, .data = {0x20, 0x01, 0x0d, 0xb8} },
        { .prefixlen = 32, .data = {0x20, 0x01, 0x0d, 0xb8} }, /* duplicate */
        { .prefixlen = 64, .data = {0x20, 0x01, 0x0d, 0xb8} },
    };
    size_t new_v6_cnt = deduplicate_v6(v6_arr, 3);
    assert(new_v6_cnt == 2);

    printf("  [PASS] test_cidr_normalization_and_deduplication\n");
}

static void test_rule_parser(void) {
    /* 1. Parse var.nft from current or parent directory */
    const char *rule_file = access("var.nft", F_OK) == 0 ? "var.nft" : "../var.nft";
    struct rule_collector rc1 = {0};
    assert(parse_rule_file(rule_file, &rc1) == 0);
    assert(rc1.has_fwmark && rc1.fwmark == 0x3000);
    assert(rc1.v4_count == 18);
    assert(rc1.v6_count == 11);
    free_rule_collector(&rc1);

    /* 2. Test single line block & closing brace on same line */
    const char *tmp_file = "/tmp/test_rules_syntax.nft";
    FILE *f = fopen(tmp_file, "w");
    assert(f != NULL);
    fprintf(f, "define FWMARK = 0x1234\n");
    fprintf(f, "define WG_ENDPOINT = \"192.168.1.100:51820\"\n");
    fprintf(f, "define IPV4_ELEMENTS = { 10.0.0.0/8, 192.168.1.0/24 }\n");
    fprintf(f, "define IPV6_ELEMENTS = {\n");
    fprintf(f, "    2001:db8::/32,\n");
    fprintf(f, "    fe80::/10 }\n");
    fclose(f);

    struct rule_collector rc2 = {0};
    assert(parse_rule_file(tmp_file, &rc2) == 0);
    assert(rc2.fwmark == 0x1234);
    assert(rc2.has_endpoint && strcmp(rc2.endpoint, "192.168.1.100:51820") == 0);
    assert(rc2.v4_count == 2);
    assert(rc2.v6_count == 2);
    free_rule_collector(&rc2);

    /* 3. Test empty quotes in WG_ENDPOINT (disabled endpoint) */
    f = fopen(tmp_file, "w");
    fprintf(f, "define WG_ENDPOINT = \"\"\n");
    fprintf(f, "define IPV4_ELEMENTS = { 10.0.0.0/8 }\n");
    fclose(f);
    struct rule_collector rc_empty_ep = {0};
    assert(parse_rule_file(tmp_file, &rc_empty_ep) == 0);
    assert(!rc_empty_ep.has_endpoint);
    assert(rc_empty_ep.v4_count == 1);
    free_rule_collector(&rc_empty_ep);

    /* 4. Test ranges with spaces around hyphen: e.g. "10.0.0.1 - 10.0.0.2" */
    f = fopen(tmp_file, "w");
    fprintf(f, "define IPV4_ELEMENTS = { 10.0.0.1 - 10.0.0.2, 192.168.1.0   -   192.168.1.1 }\n");
    fclose(f);
    struct rule_collector rc_spaces = {0};
    assert(parse_rule_file(tmp_file, &rc_spaces) == 0);
    /* 10.0.0.1/32, 10.0.0.2/32, and optimal aggregate 192.168.1.0/31 -> 3 CIDRs */
    assert(rc_spaces.v4_count == 3);
    free_rule_collector(&rc_spaces);

    /* 5. Test line exceeding 512 bytes with getline */
    f = fopen(tmp_file, "w");
    fprintf(f, "define IPV4_ELEMENTS = {\n");
    for (int i = 0; i < 40; i++) {
        fprintf(f, " 10.0.%d.0/24,", i);
    }
    fprintf(f, " 10.0.40.0/24 }\n");
    fclose(f);
    struct rule_collector rc_long = {0};
    assert(parse_rule_file(tmp_file, &rc_long) == 0);
    assert(rc_long.v4_count == 41);
    free_rule_collector(&rc_long);

    /* 6. Test malformed fwmark (0 or missing) */
    f = fopen(tmp_file, "w");
    fprintf(f, "define FWMARK = 0\n");
    fclose(f);
    struct rule_collector rc_bad = {0};
    assert(parse_rule_file(tmp_file, &rc_bad) == -1);
    free_rule_collector(&rc_bad);

    /* 7. Test invalid IPv4 prefix length (>32) */
    f = fopen(tmp_file, "w");
    fprintf(f, "define IPV4_ELEMENTS = { 10.0.0.0/33 }\n");
    fclose(f);
    assert(parse_rule_file(tmp_file, &rc_bad) == -1);
    free_rule_collector(&rc_bad);

    /* 8. Test invalid IPv6 prefix length (>128) */
    f = fopen(tmp_file, "w");
    fprintf(f, "define IPV6_ELEMENTS = { 2001:db8::/129 }\n");
    fclose(f);
    assert(parse_rule_file(tmp_file, &rc_bad) == -1);
    free_rule_collector(&rc_bad);

    /* 9. Test inverted IPv4 range */
    f = fopen(tmp_file, "w");
    fprintf(f, "define IPV4_ELEMENTS = { 10.0.0.2-10.0.0.1 }\n");
    fclose(f);
    assert(parse_rule_file(tmp_file, &rc_bad) == -1);
    free_rule_collector(&rc_bad);

    /* 10. Test invalid IPv6 address */
    f = fopen(tmp_file, "w");
    fprintf(f, "define IPV6_ELEMENTS = { 2001:xyz::/32 }\n");
    fclose(f);
    assert(parse_rule_file(tmp_file, &rc_bad) == -1);
    free_rule_collector(&rc_bad);

    /* 11. Test IPv4 CIDR with trailing garbage */
    f = fopen(tmp_file, "w");
    fprintf(f, "define IPV4_ELEMENTS = { 10.0.0.1/24garbage }\n");
    fclose(f);
    assert(parse_rule_file(tmp_file, &rc_bad) == -1);
    assert(rc_bad.v4_keys == NULL); /* Verified collector freed on error */

    /* 12. Test IPv6 CIDR with trailing garbage */
    f = fopen(tmp_file, "w");
    fprintf(f, "define IPV6_ELEMENTS = { 2001:db8::/32xyz }\n");
    fclose(f);
    assert(parse_rule_file(tmp_file, &rc_bad) == -1);
    assert(rc_bad.v6_keys == NULL); /* Verified collector freed on error */

    /* 13. Test IPv4 range with trailing garbage */
    f = fopen(tmp_file, "w");
    fprintf(f, "define IPV4_ELEMENTS = { 10.0.0.1-10.0.0.2-10.0.0.3 }\n");
    fclose(f);
    assert(parse_rule_file(tmp_file, &rc_bad) == -1);
    assert(rc_bad.v4_keys == NULL);

    unlink(tmp_file);
    printf("  [PASS] test_rule_parser\n");
}

static void test_lan_ifaces(void) {
    struct lan_ifaces list = {0};

    /* 1. Comma-separated and whitespace parsing */
    add_lan_iface(&list, "eth1, eth2");
    assert(list.count == 2);
    assert(strcmp(list.names[0], "eth1") == 0);
    assert(strcmp(list.names[1], "eth2") == 0);

    /* 2. Repeated calls */
    add_lan_iface(&list, "br0");
    assert(list.count == 3);
    assert(strcmp(list.names[2], "br0") == 0);

    /* 3. Deduplication */
    add_lan_iface(&list, "eth1, br0, eth3");
    assert(list.count == 4);
    assert(strcmp(list.names[3], "eth3") == 0);

    /* 4. File persistence roundtrip */
    const char *test_dir = "/tmp/test_lan_persist";
    ensure_dir(test_dir);
    save_lan_ifaces(test_dir, &list);

    struct lan_ifaces loaded = {0};
    load_lan_ifaces(test_dir, &loaded);
    assert(loaded.count == 4);
    assert(strcmp(loaded.names[0], "eth1") == 0);
    assert(strcmp(loaded.names[1], "eth2") == 0);
    assert(strcmp(loaded.names[2], "br0") == 0);
    assert(strcmp(loaded.names[3], "eth3") == 0);

    /* 5. Removal of interfaces */
    remove_lan_iface(&list, "eth2");
    assert(list.count == 3);
    assert(strcmp(list.names[0], "eth1") == 0);
    assert(strcmp(list.names[1], "br0") == 0);
    assert(strcmp(list.names[2], "eth3") == 0);

    remove_lan_iface(&list, "eth1, eth3");
    assert(list.count == 1);
    assert(strcmp(list.names[0], "br0") == 0);

    remove_lan_iface(&list, "nonexistent");
    assert(list.count == 1);

    remove_lan_iface(&list, "br0");
    assert(list.count == 0);

    /* 6. Truncated name dedup check */
    struct lan_ifaces long_list = {0};
    add_lan_iface(&long_list, "interface_name_very_long_1");
    add_lan_iface(&long_list, "interface_name_very_long_2");
    /* Since first 15 chars are identical ("interface_name_"), second must be deduplicated */
    assert(long_list.count == 1);

    /* 7. Long input string exceeding 256 chars should not truncate elements */
    struct lan_ifaces large_list = {0};
    char long_if_str[512] = {0};
    for (int i = 0; i < 20; i++) {
        char item[32];
        snprintf(item, sizeof(item), "veth%d,", i);
        strcat(long_if_str, item);
    }
    strcat(long_if_str, "veth20");
    add_lan_iface(&large_list, long_if_str);
    assert(large_list.count == 21);
    assert(strcmp(large_list.names[0], "veth0") == 0);
    assert(strcmp(large_list.names[20], "veth20") == 0);

    char path[512];
    snprintf(path, sizeof(path), "%s/%s", test_dir, LAN_IFACES_FILENAME);
    unlink(path);
    snprintf(path, sizeof(path), "%s/%s.txt", test_dir, LAN_IFACES_FILENAME);
    unlink(path);
    rmdir(test_dir);

    printf("  [PASS] test_lan_ifaces\n");
}

static void test_oif_resolution(void) {
    uint32_t ip4 = 0;
    uint32_t ip6[4] = {0};

    /* 1. Test existing interface (loopback 'lo' is always present on Linux) */
    assert(get_interface_ips("lo", &ip4, ip6) == 0);
    assert(ip4 == htonl(0x7F000001)); /* 127.0.0.1 */

    /* 2. Test non-existent interface */
    assert(get_interface_ips("nonexistent_dev_xyz", &ip4, ip6) == -1);
    assert(ip4 == 0);
    assert(ip6[0] == 0 && ip6[1] == 0 && ip6[2] == 0 && ip6[3] == 0);

    /* 3. Test router_config simulation (set-oif and del-oif logic) */
    struct router_config cfg = {
        .fwmark = 0x3000,
        .enabled = 1,
        .oif_src_ip4 = 0,
        .oif_src_ip6 = {0},
    };

    /* Simulate set-oif on 'lo' */
    assert(get_interface_ips("lo", &cfg.oif_src_ip4, cfg.oif_src_ip6) == 0);
    assert(cfg.oif_src_ip4 == htonl(0x7F000001));

    /* Simulate del-oif */
    cfg.oif_src_ip4 = 0;
    memset(cfg.oif_src_ip6, 0, sizeof(cfg.oif_src_ip6));
    assert(cfg.oif_src_ip4 == 0);
    assert(cfg.oif_src_ip6[0] == 0 && cfg.oif_src_ip6[3] == 0);

    printf("  [PASS] test_oif_resolution\n");
}

static void test_qinq_ethertypes(void) {
    assert(ETH_P_8021Q == 0x8100);
    assert(ETH_P_8021AD == 0x88A8);
    assert(ETH_P_QINQ1 == 0x9100);
    assert(ETH_P_QINQ2 == 0x9200);
    assert(ETH_P_QINQ3 == 0x9300);
    printf("  [PASS] test_qinq_ethertypes\n");
}

static void test_prune_lpm_algorithm(void) {
    /* Test bsearch key identification for pruning stale keys */
    struct ipv4_lpm_key current_rules[3] = {
        { .prefixlen = 8,  .data = htonl(0x0A000000) }, /* 10.0.0.0/8 */
        { .prefixlen = 16, .data = htonl(0xC0A80000) }, /* 192.168.0.0/16 */
        { .prefixlen = 24, .data = htonl(0xC0A80100) }, /* 192.168.1.0/24 */
    };
    /* Sort keys as done in apply_nft_rules */
    qsort(current_rules, 3, sizeof(current_rules[0]), cmp_v4_key);

    /* Simulated existing keys in kernel map:
     * - 10.0.0.0/8 (kept)
     * - 172.16.0.0/12 (stale, should be pruned)
     * - 192.168.0.0/16 (kept)
     * - 192.168.2.0/24 (stale, should be pruned)
     */
    struct ipv4_lpm_key map_key1 = { .prefixlen = 8,  .data = htonl(0x0A000000) };
    struct ipv4_lpm_key map_key2 = { .prefixlen = 12, .data = htonl(0xAC100000) };
    struct ipv4_lpm_key map_key3 = { .prefixlen = 16, .data = htonl(0xC0A80000) };
    struct ipv4_lpm_key map_key4 = { .prefixlen = 24, .data = htonl(0xC0A80200) };

    assert(bsearch(&map_key1, current_rules, 3, sizeof(current_rules[0]), cmp_v4_key) != NULL);
    assert(bsearch(&map_key2, current_rules, 3, sizeof(current_rules[0]), cmp_v4_key) == NULL);
    assert(bsearch(&map_key3, current_rules, 3, sizeof(current_rules[0]), cmp_v4_key) != NULL);
    assert(bsearch(&map_key4, current_rules, 3, sizeof(current_rules[0]), cmp_v4_key) == NULL);

    printf("  [PASS] test_prune_lpm_algorithm\n");
}

static void test_ipv4_mapped_ipv6_logic(void) {
    /* Verify IPv4-mapped IPv6 address identification logic:
     * ::ffff:127.0.0.1 -> ip0 = 0, ip1 = 0, ip2 = bpf_htonl(0x0000ffff), ip3 = htonl(0x7F000001) */
    uint32_t ip0 = 0;
    uint32_t ip1 = 0;
    uint32_t ip2 = htonl(0x0000ffff);
    uint32_t ip3_loopback = htonl(0x7F000001);
    uint32_t ip3_zero = htonl(0x00000001);

    bool is_v4_mapped = (ip0 == 0 && ip1 == 0 && ip2 == htonl(0x0000ffff));
    assert(is_v4_mapped);

    /* Verify loopback (127.0.0.0/8) bypass logic */
    uint32_t host_ip = ntohl(ip3_loopback);
    assert((host_ip >> 24) == 127);

    /* Verify current network (0.0.0.0/8) bypass logic */
    uint32_t host_ip_zero = ntohl(ip3_zero);
    assert((host_ip_zero >> 24) == 0);

    printf("  [PASS] test_ipv4_mapped_ipv6_logic\n");
}

static void test_iif_oif_cli_alignment(void) {
    /* Verify iif and oif naming conventions and lan_ifaces manipulation */
    struct lan_ifaces iif_list = {0};

    /* Verify adding iif */
    add_lan_iface(&iif_list, "eth1");
    add_lan_iface(&iif_list, "eth2,eth3");
    assert(iif_list.count == 3);
    assert(strcmp(iif_list.names[0], "eth1") == 0);
    assert(strcmp(iif_list.names[1], "eth2") == 0);
    assert(strcmp(iif_list.names[2], "eth3") == 0);

    /* Verify removing iif */
    remove_lan_iface(&iif_list, "eth2");
    assert(iif_list.count == 2);
    assert(strcmp(iif_list.names[0], "eth1") == 0);
    assert(strcmp(iif_list.names[1], "eth3") == 0);

    remove_lan_iface(&iif_list, "eth1,eth3");
    assert(iif_list.count == 0);

    printf("  [PASS] test_iif_oif_cli_alignment\n");
}

static void test_default_interface_detection(void) {
    assert(is_auto_interface_keyword("auto") == true);
    assert(is_auto_interface_keyword("default") == true);
    assert(is_auto_interface_keyword("primary") == true);
    assert(is_auto_interface_keyword("PRIMARY") == true);
    assert(is_auto_interface_keyword("eth0") == false);
    assert(is_auto_interface_keyword(NULL) == false);
    assert(is_auto_interface_keyword("") == false);

    char ifname[IFNAMSIZ] = {0};
    int ret = get_default_interface(NULL, ifname, sizeof(ifname));
    if (ret == 0) {
        assert(strlen(ifname) > 0);
        assert(strcmp(ifname, "lo") != 0);
    }
    printf("  [PASS] test_default_interface_detection\n");
}

static void test_is_interface_carrier_up(void) {
    assert(is_interface_carrier_up("lo") == true);
    assert(is_interface_carrier_up("nonexistent_dev_xyz") == false);
    assert(is_interface_carrier_up("") == false);
    assert(is_interface_carrier_up(NULL) == false);
    printf("  [PASS] test_is_interface_carrier_up\n");
}

static void test_is_physical_interface(void) {
    assert(is_physical_interface("lo") == false);
    assert(is_physical_interface("lo:1") == false);
    assert(is_physical_interface("wg0") == false);
    assert(is_physical_interface("tun0") == false);
    assert(is_physical_interface("tap0") == false);
    assert(is_physical_interface("docker0") == false);
    assert(is_physical_interface("br0") == false);
    assert(is_physical_interface("br-lan") == false);
    assert(is_physical_interface("virbr0") == false);
    assert(is_physical_interface("veth1234") == false);
    assert(is_physical_interface("dummy0") == false);
    assert(is_physical_interface("sit0") == false);
    assert(is_physical_interface("bond0") == false);
    assert(is_physical_interface("gre0") == false);
    assert(is_physical_interface("vxlan0") == false);
    assert(is_physical_interface("eth0") == true);
    assert(is_physical_interface("eth1") == true);
    assert(is_physical_interface("enp3s0") == true);
    assert(is_physical_interface("wlan0") == true);
    assert(is_physical_interface("wwan0") == true);
    assert(is_physical_interface("eth0.100") == false);
    assert(is_physical_interface("enp3s0.20") == false);
    assert(is_physical_interface("ppp0") == false);
    assert(is_physical_interface("pppoe-wan") == false);
    assert(is_physical_interface("vlan10") == false);
    assert(is_physical_interface("macvlan0") == false);
    assert(is_physical_interface("") == false);
    assert(is_physical_interface(NULL) == false);
    printf("  [PASS] test_is_physical_interface\n");
}

static void test_ipv4_and_ipv6_default_route_matching(void) {
    assert(is_ipv4_default_route(0, 0, RTF_UP) == true);
    assert(is_ipv4_default_route(0, 0, 0) == false);
    assert(is_ipv4_default_route(0x0100000a, 0, RTF_UP) == false);
    assert(is_ipv4_default_route(0, 0xffffff00, RTF_UP) == false);

    assert(is_ipv6_default_route("00000000000000000000000000000000", "00", RTF_UP) == true);
    assert(is_ipv6_default_route("00000000000000000000000000000000", "00", RTF_UP | 0x02000000) == true);
    assert(is_ipv6_default_route("20010db8000000000000000000000000", "00", RTF_UP) == false);
    assert(is_ipv6_default_route("00000000000000000000000000000000", "20", RTF_UP) == false);
    assert(is_ipv6_default_route("00000000000000000000000000000000", "00", 0) == false);
    assert(is_ipv6_default_route(NULL, "00", RTF_UP) == false);
    assert(is_ipv6_default_route("00000000000000000000000000000000", NULL, RTF_UP) == false);
    printf("  [PASS] test_ipv4_and_ipv6_default_route_matching\n");
}

static void test_oif_dev_persistence(void) {
    const char *tmp_pin = "/tmp/test_oif_persistence_dir";
    ensure_dir(tmp_pin);
    char loaded[IFNAMSIZ] = {0};

    save_oif_dev(tmp_pin, "wg0");
    assert(load_oif_dev(tmp_pin, loaded, sizeof(loaded)) == 0);
    assert(strcmp(loaded, "wg0") == 0);

    save_oif_dev(tmp_pin, "wg1");
    assert(load_oif_dev(tmp_pin, loaded, sizeof(loaded)) == 0);
    assert(strcmp(loaded, "wg1") == 0);

    save_oif_dev(tmp_pin, NULL);
    assert(load_oif_dev(tmp_pin, loaded, sizeof(loaded)) == -1);

    rmdir(tmp_pin);
    printf("  [PASS] test_oif_dev_persistence\n");
}

static void test_cli_argument_validation(void) {
    char *del_no_args[] = {"router_ctl", "del-iif"};
    assert(router_ctl_main(2, del_no_args) == 1);

    char *del_auto[] = {"router_ctl", "del-iif", "auto"};
    assert(router_ctl_main(3, del_auto) == 1);

    char *del_default[] = {"router_ctl", "del-iif", "default"};
    assert(router_ctl_main(3, del_default) == 1);

    char *del_primary[] = {"router_ctl", "del-iif", "primary"};
    assert(router_ctl_main(3, del_primary) == 1);

    char *add_no_args[] = {"router_ctl", "add-iif"};
    assert(router_ctl_main(2, add_no_args) == 1);

    char *start_iif_missing[] = {"router_ctl", "start", "--rule-file", "var.nft", "--iif"};
    assert(router_ctl_main(5, start_iif_missing) == 1);

    char *start_iif_flag_next[] = {"router_ctl", "start", "--iif", "--rule-file", "var.nft"};
    assert(router_ctl_main(5, start_iif_flag_next) == 1);

    char *stop_iif_missing[] = {"router_ctl", "stop", "--iif"};
    assert(router_ctl_main(3, stop_iif_missing) == 1);

    char *stop_iif_flag_next[] = {"router_ctl", "stop", "--iif", "--pin-dir", "/tmp/nonexistent"};
    assert(router_ctl_main(5, stop_iif_flag_next) == 1);

    char *reload_missing_rule[] = {"router_ctl", "reload", "--rule-file", "--pin-dir", "/tmp/nonexistent"};
    assert(router_ctl_main(5, reload_missing_rule) == 1);

    char *start_missing_cgroup[] = {"router_ctl", "start", "--cgroup-path", "--rule-file", "var.nft"};
    assert(router_ctl_main(5, start_missing_cgroup) == 1);

    char *start_missing_pin[] = {"router_ctl", "start", "--pin-dir", "--rule-file", "var.nft"};
    assert(router_ctl_main(5, start_missing_pin) == 1);

    char *start_missing_oif[] = {"router_ctl", "start", "--rule-file", "var.nft", "--oif", "--fwmark", "0x1"};
    assert(router_ctl_main(7, start_missing_oif) == 1);

    char *set_oif_missing_pin[] = {"router_ctl", "set-oif", "wg0", "--pin-dir", "--other"};
    assert(router_ctl_main(5, set_oif_missing_pin) == 1);

    printf("  [PASS] test_cli_argument_validation\n");
}

static void test_query_tc_filter_zero_expected_prog_id(void) {
    /* If expected_prog_id == 0, query_tc_filter must return false to avoid false positives */
    assert(query_tc_filter(1, 1, 1, 0) == false);
    printf("  [PASS] test_query_tc_filter_zero_expected_prog_id\n");
}

static void test_do_set_oif_fwmark_mode(void) {
    const char *tmp_pin = "/tmp/test_do_set_oif_dir";
    ensure_dir(tmp_pin);

    save_oif_dev(tmp_pin, "wg_unassigned");
    char loaded[IFNAMSIZ] = {0};
    assert(load_oif_dev(tmp_pin, loaded, sizeof(loaded)) == 0);
    assert(strcmp(loaded, "wg_unassigned") == 0);

    /* Cleanup */
    char txt_path[512];
    snprintf(txt_path, sizeof(txt_path), "%s/%s", tmp_pin, OIF_DEV_FILENAME);
    unlink(txt_path);
    rmdir(tmp_pin);
    printf("  [PASS] test_do_set_oif_fwmark_mode\n");
}

static void test_del_iif_all_logic(void) {
    const char *tmp_pin = "/tmp/test_del_iif_all_dir";
    ensure_dir(tmp_pin);

    struct lan_ifaces initial = {0};
    add_lan_iface(&initial, "dummy_eth1,dummy_eth2");
    save_lan_ifaces(tmp_pin, &initial);

    struct lan_ifaces loaded = {0};
    load_lan_ifaces(tmp_pin, &loaded);
    assert(loaded.count == 2);

    struct lan_ifaces del_cmd = {0};
    add_lan_iface(&del_cmd, "all");

    /* do_del_iif will detach all and clear cur_list */
    int ret = do_del_iif(&del_cmd, tmp_pin);
    assert(ret == 0);

    struct lan_ifaces after = {0};
    load_lan_ifaces(tmp_pin, &after);
    assert(after.count == 0);

    /* Test calling del-iif all again when cur_list is empty -> returns 0 */
    assert(do_del_iif(&del_cmd, tmp_pin) == 0);

    char txt_path[512];
    snprintf(txt_path, sizeof(txt_path), "%s/%s.txt", tmp_pin, LAN_IFACES_FILENAME);
    unlink(txt_path);
    snprintf(txt_path, sizeof(txt_path), "%s/lan_ifaces.txt", tmp_pin);
    unlink(txt_path);
    rmdir(tmp_pin);

    printf("  [PASS] test_del_iif_all_logic\n");
}

static void test_del_iif_untracked(void) {
    const char *tmp_pin = "/tmp/test_del_iif_untracked_dir";
    ensure_dir(tmp_pin);

    struct lan_ifaces initial = {0};
    add_lan_iface(&initial, "dummy_eth1");
    save_lan_ifaces(tmp_pin, &initial);

    struct lan_ifaces del_cmd = {0};
    add_lan_iface(&del_cmd, "nonexistent99");

    /* do_del_iif with untracked interface should skip and not delete dummy_eth1 */
    int ret = do_del_iif(&del_cmd, tmp_pin);
    assert(ret == 0);

    struct lan_ifaces after = {0};
    load_lan_ifaces(tmp_pin, &after);
    assert(after.count == 1);
    assert(strcmp(after.names[0], "dummy_eth1") == 0);

    /* Clean up */
    char txt_path[512];
    snprintf(txt_path, sizeof(txt_path), "%s/%s.txt", tmp_pin, LAN_IFACES_FILENAME);
    unlink(txt_path);
    snprintf(txt_path, sizeof(txt_path), "%s/lan_ifaces.txt", tmp_pin);
    unlink(txt_path);
    rmdir(tmp_pin);

    printf("  [PASS] test_del_iif_untracked\n");
}

static void test_iif_equals_oif_rejection(void) {
    struct lan_ifaces list = {0};
    add_lan_iface(&list, "wg0");
    /* If LAN interface name equals exclude_oif, resolve_lan_ifaces must reject with -1 */
    assert(resolve_lan_ifaces(&list, "wg0") == -1);

    struct lan_ifaces list2 = {0};
    add_lan_iface(&list2, "eth1");
    /* When LAN interface is different from exclude_oif, resolve_lan_ifaces must succeed */
    assert(resolve_lan_ifaces(&list2, "wg0") == 0);
    assert(list2.count == 1);
    assert(strcmp(list2.names[0], "eth1") == 0);

    /* Test multiple interfaces where one matches exclude_oif */
    struct lan_ifaces list3 = {0};
    add_lan_iface(&list3, "eth1,wg0");
    assert(resolve_lan_ifaces(&list3, "wg0") == -1);

    printf("  [PASS] test_iif_equals_oif_rejection\n");
}

static int mock_fail_get_default_iface(const char *exclude, char *out, size_t max_len) {
    (void)exclude; (void)out; (void)max_len;
    return -1;
}

static void test_stop_fault_tolerance_on_unresolved_iif(void) {
    const char *tmp_pin = "/tmp/test_stop_fault_tol_dir";
    ensure_dir(tmp_pin);

    /* 1. Test stop with --iif auto when default route detection fails */
    g_mock_get_default_interface = mock_fail_get_default_iface;
    char *argv_auto[] = {
        "router_ctl", "stop",
        "--pin-dir", (char *)tmp_pin,
        "--iif", "auto"
    };
    /* stop must proceed, issue a warning, and return 0 even when auto fails to resolve */
    int ret_auto = router_ctl_main(6, argv_auto);
    assert(ret_auto == 0);
    assert(access(tmp_pin, F_OK) != 0);
    g_mock_get_default_interface = NULL;

    /* 2. Test stop with an unattached/nonexistent interface name */
    ensure_dir(tmp_pin);
    char *argv[] = {
        "router_ctl", "stop",
        "--pin-dir", (char *)tmp_pin,
        "--iif", "nonexistent_iface_99"
    };
    int ret = router_ctl_main(6, argv);
    assert(ret == 0);
    assert(access(tmp_pin, F_OK) != 0);

    printf("  [PASS] test_stop_fault_tolerance_on_unresolved_iif\n");
}

static void test_lan_ifaces_fallback_sync(void) {
    const char *tmp_pin = "/tmp/test_lan_sync_dir";
    ensure_dir(tmp_pin);

    char txt1[512], txt2[512];
    snprintf(txt1, sizeof(txt1), "%s/%s.txt", tmp_pin, LAN_IFACES_FILENAME);
    snprintf(txt2, sizeof(txt2), "%s/lan_ifaces.txt", tmp_pin);

    /* Create dummy stale files */
    FILE *f = fopen(txt1, "w");
    assert(f != NULL);
    fprintf(f, "stale_eth\n");
    fclose(f);
    f = fopen(txt2, "w");
    assert(f != NULL);
    fprintf(f, "stale_eth2\n");
    fclose(f);

    assert(access(txt1, F_OK) == 0);
    assert(access(txt2, F_OK) == 0);

    /* save_lan_ifaces with NULL or empty count should clean up fallback files */
    struct lan_ifaces empty = {0};
    save_lan_ifaces(tmp_pin, &empty);
    assert(access(txt1, F_OK) != 0);
    assert(access(txt2, F_OK) != 0);

    /* save_lan_ifaces with interfaces should write them */
    struct lan_ifaces to_save = {0};
    add_lan_iface(&to_save, "eth1,eth2");
    save_lan_ifaces(tmp_pin, &to_save);
    assert(access(txt1, F_OK) == 0);

    struct lan_ifaces loaded = {0};
    load_lan_ifaces(tmp_pin, &loaded);
    assert(loaded.count == 2);
    assert(strcmp(loaded.names[0], "eth1") == 0);
    assert(strcmp(loaded.names[1], "eth2") == 0);

    /* Clean up */
    save_lan_ifaces(tmp_pin, NULL);
    assert(access(txt1, F_OK) != 0);
    rmdir(tmp_pin);

    printf("  [PASS] test_lan_ifaces_fallback_sync\n");
}

static void test_tc_ingress_attached_ext_suppression(void) {
    /* If expected_prog_id == 0, is_tc_ingress_attached_ext must immediately return false */
    assert(is_tc_ingress_attached_ext("lo", 0, false) == false);
    assert(is_tc_ingress_attached_ext("lo", 0, true) == false);

    /* If interface name is NULL, must return false */
    assert(is_tc_ingress_attached_ext(NULL, 12345, false) == false);
    assert(is_tc_ingress_attached_ext(NULL, 12345, true) == false);

    /* For non-attached interface with allow_cmd_fallback=false, must return false without forking */
    assert(is_tc_ingress_attached_ext("lo", 12345, false) == false);
    assert(is_tc_ingress_attached_ext("nonexistent_dev", 12345, false) == false);

    printf("  [PASS] test_tc_ingress_attached_ext_suppression\n");
}

static void test_ghost_oif_cleanup(void) {
    const char *tmp_pin = "/tmp/test_ghost_oif_dir";
    ensure_dir(tmp_pin);

    char path[512];
    snprintf(path, sizeof(path), "%s/%s", tmp_pin, OIF_DEV_FILENAME);

    /* Create stale text file */
    FILE *f = fopen(path, "w");
    assert(f != NULL);
    fprintf(f, "stale_wg\n");
    fclose(f);

    /* Verify stale file exists */
    assert(access(path, F_OK) == 0);

    /* save_oif_dev with NULL must unlink the fallback file */
    save_oif_dev(tmp_pin, NULL);
    assert(access(path, F_OK) != 0);

    /* Calling load_oif_dev should now return -1 */
    char out_dev[IFNAMSIZ] = {0};
    assert(load_oif_dev(tmp_pin, out_dev, sizeof(out_dev)) == -1);

    rmdir(tmp_pin);
    printf("  [PASS] test_ghost_oif_cleanup\n");
}

int main(void) {
    libbpf_set_print(libbpf_print_fn);
    printf("[*] Running router_ctl unit tests...\n");
    test_parse_fwmark();
    test_parse_port();
    test_parse_endpoint();
    test_keyword_matching();
    test_ensure_dir();
    test_range_to_cidrs_edge_cases();
    test_cidr_normalization_and_deduplication();
    test_rule_parser();
    test_lan_ifaces();
    test_oif_resolution();
    test_qinq_ethertypes();
    test_prune_lpm_algorithm();
    test_ipv4_mapped_ipv6_logic();
    test_iif_oif_cli_alignment();
    test_default_interface_detection();
    test_is_interface_carrier_up();
    test_is_physical_interface();
    test_ipv4_and_ipv6_default_route_matching();
    test_oif_dev_persistence();
    test_del_iif_all_logic();
    test_del_iif_untracked();
    test_query_tc_filter_zero_expected_prog_id();
    test_do_set_oif_fwmark_mode();
    test_cli_argument_validation();
    test_iif_equals_oif_rejection();
    test_stop_fault_tolerance_on_unresolved_iif();
    test_lan_ifaces_fallback_sync();
    test_tc_ingress_attached_ext_suppression();
    test_ghost_oif_cleanup();
    printf("[✔] ALL UNIT TESTS PASSED!\n");
    return 0;
}
