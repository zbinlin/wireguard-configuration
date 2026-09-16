#define _GNU_SOURCE
#define UNIT_TESTING
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

    /* Invalid cases: zero, empty, non-numeric, or trailing garbage */
    assert(parse_fwmark("0", &mark) == -1);
    assert(parse_fwmark("0x0", &mark) == -1);
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

    printf("  [PASS] test_ensure_dir\n");
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

    /* 3. Test malformed fwmark (0 or missing) */
    f = fopen(tmp_file, "w");
    fprintf(f, "define FWMARK = 0\n");
    fclose(f);
    struct rule_collector rc_bad = {0};
    assert(parse_rule_file(tmp_file, &rc_bad) == -1);
    free_rule_collector(&rc_bad);

    /* 4. Test invalid IPv4 prefix length (>32) */
    f = fopen(tmp_file, "w");
    fprintf(f, "define IPV4_ELEMENTS = { 10.0.0.0/33 }\n");
    fclose(f);
    assert(parse_rule_file(tmp_file, &rc_bad) == -1);
    free_rule_collector(&rc_bad);

    /* 5. Test invalid IPv6 prefix length (>128) */
    f = fopen(tmp_file, "w");
    fprintf(f, "define IPV6_ELEMENTS = { 2001:db8::/129 }\n");
    fclose(f);
    assert(parse_rule_file(tmp_file, &rc_bad) == -1);
    free_rule_collector(&rc_bad);

    /* 6. Test inverted IPv4 range */
    f = fopen(tmp_file, "w");
    fprintf(f, "define IPV4_ELEMENTS = { 10.0.0.2-10.0.0.1 }\n");
    fclose(f);
    assert(parse_rule_file(tmp_file, &rc_bad) == -1);
    free_rule_collector(&rc_bad);

    /* 7. Test invalid IPv6 address */
    f = fopen(tmp_file, "w");
    fprintf(f, "define IPV6_ELEMENTS = { 2001:xyz::/32 }\n");
    fclose(f);
    assert(parse_rule_file(tmp_file, &rc_bad) == -1);
    free_rule_collector(&rc_bad);

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

    char path[512];
    snprintf(path, sizeof(path), "%s/%s", test_dir, LAN_IFACES_FILENAME);
    unlink(path);
    snprintf(path, sizeof(path), "%s/%s.txt", test_dir, LAN_IFACES_FILENAME);
    unlink(path);
    rmdir(test_dir);

    printf("  [PASS] test_lan_ifaces\n");
}

int main(void) {
    printf("[*] Running router_ctl unit tests...\n");
    test_parse_fwmark();
    test_parse_port();
    test_parse_endpoint();
    test_keyword_matching();
    test_ensure_dir();
    test_rule_parser();
    test_lan_ifaces();
    printf("[✔] ALL UNIT TESTS PASSED!\n");
    return 0;
}
