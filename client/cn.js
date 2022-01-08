#!/bin/env node

const https = require('https');
const { promisify } = require('util');
const readline = require('readline');

const DOWNLOAD_URI = 'https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest';
const PRIORITY = 1024;

async function fetch(uri) {
    return new Promise((resolve, reject) => {
        https.get(uri, resolve);
    });
}

async function parse(res) {
    const rl = new readline.createInterface({
        input: res,
    });
    return new Promise((resolve, reject) => {
        const result = [];
        rl.on('line', line => {
            if (/^#/.test(line)) {
                return;
            }
            const [_registry, cc, type, start, value, _date, _status] = line.split('|');
            if (cc !== 'CN') {
                return;
            }
            if (type === 'ipv4') {
                const address = start;
                const len = Math.log2(Number(value));
                if (Math.ceil(len) !== len) {
                    console.error(`!!!!WARNING!!!!: ${address}/${value} can't coverter to CIDR-style range.`);
                }
                const netmask = 32 - Math.ceil(len);
                result.push([address, netmask]);
            } else if (type === 'ipv6') {
                result.push([start, value]);
            }
        });
        rl.on('error', reject);
        rl.on('close', () => {
            result.sort((a, b) => Math.sign(b[1] - a[1]));
            resolve(result);
        });
    });
}

function output(ary) {
    console.log(`PRIORITY=$\{PRIORITY:-${PRIORITY}}`);

    const otherAddresses = [
        /** IPv4 **/

        '1.1.1.1', '1.0.0.1', /* Cloudflare DNS */
        '8.8.8.8', '8.8.4.4', /* Google DNS */
        '9.9.9.9', '149.112.112.112', /* Qua9 DNS */

        '0.0.0.0/8', /* Current network (From wiki) */
        '127.0.0.0/8', /* Loopback */
        '10.0.0.0/8', /* Private Internet Address */
        '100.64.0.0/10', /* Private Internet Address */
        '169.254.0.0/16', /* APIPA - Automatic Private IP Addressing */
        '172.16.0.0/12', /* Private Internet Address */
        '192.168.0.0/16', /* 192.168.0.0-192.168.255.255 */
        '198.18.0.0/15', /* Private network */
        '224.0.0.0/4', /* IP multicast */
        '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', /* Documentation */
        '192.88.99.0/24', /* 6to4 */
        '255.255.255.255/32',

        /** IPv6 **/
        '::/8', /* Loopback */
        'fc00::/7', /* Unique local addresses */
        'fe80::/10', /* Link-local addresses */
        'fec0::/10', /* Site-local addresses */
        'ff00::/8', /* Multicast addresses */
        '100::/64', /* Discard prefix */
        '2001:0000::/32', /* Teredo tunneling */
        '2001:0002::/48', /* Benchmarking, Documentation */
        '2001:0010::/28', /* ORCHID */
        '2001:0020::/28', /* ORCHIDv2 */
        '2001:db8::/32', /* Documentation */
        '2002::/16', /* 6to4 */
    ];
    for (const r of otherAddresses) {
        const type = r.indexOf(':') >= 0 ? '6' : '4';
        console.log(`ip -${type} rule add to ${r} priority $\{PRIORITY}`);
    }

    for (const [address, netmask] of ary) {
        const type = address.indexOf(':') >= 0 ? '6' : '4';
        console.log(`ip -${type} rule add to ${address}/${netmask} priority $\{PRIORITY}`);
    }
}

fetch(DOWNLOAD_URI).then(parse).then(output);
