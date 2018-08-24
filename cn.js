#!/bin/env node

const https = require('https');
const { promisify } = require('util');
const readline = require('readline');

const DOWNLOAD_URI = 'https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest';
const PRIORITY = 1024;

function ip2int(ip) {
    const ary = ip.split('.').map(Number);
    if (ary.length !== 4) {
        throw new Error(`${ip} is not valid IPv4`);
    }
    if (ary.some(num => Number.isNaN(num) || num < 0 || num >= 2 ** 8)) {
        throw new Error(`${ip} is not valid IPv4`);
    }
    return ary.reduce((result, num, idx, ary) => {
        return result | (num << (ary.length - idx - 1) * 8);
    }, 0) >>> 0;
}

function int2ip(num) {
    if (Number.isNaN(num)) {
        throw new Error(`${num} is not valid 32bit integer number`);
    }
    return [
        num >>> 3 * 8 & 0xFF,
        num >>> 2 * 8 & 0xFF,
        num >>> 1 * 8 & 0xFF,
        num >>> 0 * 8 & 0xFF,
    ].join('.');
}

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
            const [registry, cc, type, start, value, date, status] = line.split('|');
            if (cc !== 'CN' || type !== 'ipv4') {
                return;
            }
            const x = ip2int(start);
            const y = +value;
            result.push([x, y]);
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
        //'1.1.1.1', '1.0.0.1', /* Cloudflare DNS */
        //'8.8.8.8', '8.8.4.4', /* Google DNS */
        //'9.9.9.9', /* Qua9 DNS */

        '0.0.0.0/8', /* Current network (From wiki) */
        '10.0.0.0/8', /* Private Internet Address */
        '100.64.0.0/10', /* Private Internet Address */
        '169.254.0.0/16', /* APIPA - Automatic Private IP Addressing */
        '172.16.0.0/12', /* Private Internet Address */
        '192.168.0.0/17', /* 192.168.0.0-192.168.127.255, 192.168.128.0-192.168.255.255 用于 WireGuard 内网 */
        '198.18.0.0/15', /* Private network */
        '224.0.0.0/4', /* IP multicast */
        '255.255.255.255/32',
    ];
    for (const r of otherAddresses) {
        console.log(`ip rule add to ${r} priority $\{PRIORITY}`);
    }

    for (const [start, size] of ary) {
        const netmask = size.toString(2).length - 1;
        console.log(`ip rule add to ${int2ip(start)}/${32 - netmask} priority $\{PRIORITY}`);
    }
}

fetch(DOWNLOAD_URI).then(parse).then(output);
