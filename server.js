// ============================================================
//  PUZZLE #71 SCANNER v5 — PROXY ROTATION ENGINE
//  BTC ONLY | 50 KEYS/BATCH | 100 ADDR IN 1 REQUEST
//  AUTO PROXY ROTATION — NEW IP EVERY REQUEST
//  NO WAIT ON RATE LIMIT — JUST SWITCH IP & RETRY
//  FRESH PROXIES EVERY 60 SECONDS FROM 12+ SOURCES
// ============================================================

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const CryptoJS = require('crypto-js');
const elliptic = require('elliptic');
const fs = require('fs');
const crypto = require('crypto');
const nodeFetch = require('node-fetch');
const { HttpsProxyAgent } = require('https-proxy-agent');

const ec = new elliptic.ec('secp256k1');
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*', methods: ['GET','POST'] } });
const PORT = process.env.PORT || 3000;

// ============================================================
//  PUZZLE #71 RANGE: 2^66 to 2^67-1
// ============================================================
const RANGE_MIN = 1n << 66n;
const RANGE_MAX = (1n << 67n) - 1n;
const BATCH_SIZE = 50;
const generatedKeys = new Set();

// ============================================================
//  USER AGENT ROTATION
// ============================================================
const UAS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
];
function getUA() { return UAS[Math.floor(Math.random() * UAS.length)]; }
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ============================================================
//  CRYPTO UTILITIES
// ============================================================
function hexToBytes(hex) {
    if (hex.length % 2) hex = '0' + hex;
    const b = Buffer.alloc(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) b[i / 2] = parseInt(hex.substr(i, 2), 16);
    return b;
}
function bufToWA(buf) {
    const w = [];
    for (let i = 0; i < buf.length; i += 4) w.push(((buf[i]||0)<<24)|((buf[i+1]||0)<<16)|((buf[i+2]||0)<<8)|(buf[i+3]||0));
    return CryptoJS.lib.WordArray.create(w, buf.length);
}
function waToBuf(wa) {
    const w = wa.words, s = wa.sigBytes, u = Buffer.alloc(s);
    for (let i = 0; i < s; i++) u[i] = (w[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    return u;
}
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58Encode(bytes) {
    const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
    let n = 0n;
    for (let i = 0; i < buf.length; i++) n = n * 256n + BigInt(buf[i]);
    let s = '';
    while (n > 0n) { s = B58[Number(n % 58n)] + s; n = n / 58n; }
    for (let i = 0; i < buf.length && buf[i] === 0; i++) s = '1' + s;
    return s || '1';
}
function b58CheckEncode(ver, payload) {
    const p = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
    const f = Buffer.alloc(1 + p.length); f[0] = ver; p.copy(f, 1);
    const h1 = CryptoJS.SHA256(bufToWA(f)), h2 = CryptoJS.SHA256(h1), cs = waToBuf(h2).slice(0, 4);
    return b58Encode(Buffer.concat([f, cs]));
}
function hash160(pubHex) {
    const pb = hexToBytes(pubHex), s = CryptoJS.SHA256(bufToWA(pb)), r = CryptoJS.RIPEMD160(s);
    return waToBuf(r);
}

// ============================================================
//  KEY GENERATION (no repeat, Puzzle #71 range)
// ============================================================
function genUniquePrivKey() {
    const buf = new Uint8Array(9);
    let privHex, attempts = 0;
    do {
        crypto.randomFillSync(buf);
        let val = 0n;
        for (let i = 0; i < 9; i++) val = (val << 8n) | BigInt(buf[i]);
        val = (val & ((1n << 66n) - 1n)) + (1n << 66n);
        privHex = val.toString(16).padStart(64, '0');
        attempts++;
        if (attempts > 100000) { generatedKeys.clear(); console.log('[WARN] Key Set cleared at 100K'); attempts = 0; }
    } while (generatedKeys.has(privHex));
    generatedKeys.add(privHex);
    return privHex;
}
function genBatchKeys(count) {
    const keys = [];
    for (let i = 0; i < count; i++) keys.push(genUniquePrivKey());
    return keys;
}
function getPublicKeys(privHex) {
    const key = ec.keyFromPrivate(privHex, 'hex'), pub = key.getPublic();
    const x = pub.getX().toString('hex').padStart(64, '0'), y = pub.getY().toString('hex').padStart(64, '0');
    return { compressed: ((parseInt(y.substr(63, 1), 16) % 2 === 0) ? '02' : '03') + x, uncompressed: '04' + x + y };
}
function addrBTC(p) { return b58CheckEncode(0x00, hash160(p)); }
function deriveBTC(privHex) {
    const { compressed, uncompressed } = getPublicKeys(privHex);
    return { privkey_hex: privHex, comp_addr: addrBTC(compressed), uncomp_addr: addrBTC(uncompressed) };
}

// ============================================================
//  PROXY ROTATION SYSTEM
//  - Fetches proxies from 12+ free sources
//  - NEW IP on EVERY request (no wait, no rate limit worry)
//  - Auto-refreshes every 60 seconds
// ============================================================
const PROXY_SOURCES = [
    'https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt',
    'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt',
    'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt',
    'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
    'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
    'https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt',
    'https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt',
    'https://raw.githubusercontent.com/FLAVOR0000/proxy-list/main/http.txt',
    'https://raw.githubusercontent.com/mertguvencli/Proxy-List-World/main/data.txt',
    'https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt',
    'https://raw.githubusercontent.com/almroot/proxylist/master/list.txt',
    'https://raw.githubusercontent.com/opsxcz/proxy-list/master/http.txt',
    'https://www.proxy-list.download/api/v1/get?type=http&country=ALL',
    'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
];

let proxyPool = [];
let proxyIdx = 0;
let proxyCount = 0;

// Round-robin — every call gets a DIFFERENT proxy
function getNextProxy() {
    if (proxyPool.length === 0) return null;
    const p = proxyPool[proxyIdx % proxyPool.length];
    proxyIdx++;
    return p;
}

// Cache HttpsProxyAgent objects (avoid re-creating)
const agentCache = new Map();
function getProxyAgent(proxyUrl) {
    if (!proxyUrl) return undefined;
    let agent = agentCache.get(proxyUrl);
    if (!agent) {
        try {
            agent = new HttpsProxyAgent(proxyUrl);
            agentCache.set(proxyUrl, agent);
            if (agentCache.size > 600) {
                const keys = [...agentCache.keys()].slice(0, 150);
                keys.forEach(k => agentCache.delete(k));
            }
        } catch(e) { return undefined; }
    }
    return agent;
}

// Fetch proxies from ALL sources (parallel)
async function fetchProxies() {
    console.log('[PROXY] Fetching fresh proxies from ' + PROXY_SOURCES.length + ' sources...');
    const newProxies = new Set(proxyPool);

    const results = await Promise.allSettled(
        PROXY_SOURCES.map(function(src) {
            const ctrl = new AbortController();
            const tid = setTimeout(function() { ctrl.abort(); }, 8000);
            return nodeFetch(src, { signal: ctrl.signal })
                .then(function(r) { clearTimeout(tid); return r.ok ? r.text() : ''; })
                .catch(function() { clearTimeout(tid); return ''; });
        })
    );

    for (let i = 0; i < results.length; i++) {
        if (results[i].status !== 'fulfilled') continue;
        const text = results[i].value;
        if (!text) continue;
        const lines = text.split(/[\n\r]+/).map(function(l) { return l.trim(); }).filter(Boolean);
        for (let j = 0; j < lines.length; j++) {
            const line = lines[j];
            if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}$/.test(line)) {
                newProxies.add('http://' + line);
            }
        }
    }

    proxyPool = Array.from(newProxies).sort(function() { return Math.random() - 0.5; });
    proxyCount = proxyPool.length;
    proxyIdx = 0;
    console.log('[PROXY] Pool ready: ' + proxyCount + ' proxies loaded');
}

// Background refresher — runs forever, refreshes every 60 seconds
async function proxyRefresher() {
    while (true) {
        try { await fetchProxies(); } catch(e) { console.log('[PROXY] Refresh error:', e.message); }
        await sleep(60000); // 60 seconds
    }
}

// ============================================================
//  BATCH APIs — check 100 addresses in 1 request
// ============================================================
const BATCH_APIS = [
    { name: 'bc_balance', url: 'https://blockchain.info/balance?active=' },
    { name: 'bc_multi',   url: 'https://blockchain.info/multiaddr?active=' },
];

// ============================================================
//  INDIVIDUAL APIs — fallback (1 address per request)
// ============================================================
const INDIVIDUAL_APIS = [
    { t:'esplora', u:'https://blockstream.info/api/address/' },
    { t:'esplora', u:'https://btc1.trezor.io/api/address/' },
    { t:'esplora', u:'https://btc2.trezor.io/api/address/' },
    { t:'esplora', u:'https://btc3.trezor.io/api/address/' },
    { t:'esplora', u:'https://btc4.trezor.io/api/address/' },
    { t:'esplora', u:'https://btc5.trezor.io/api/address/' },
    { t:'esplora', u:'https://blockbook.blockstream.com/api/address/' },
    { t:'esplora', u:'https://blockbook8.blockstream.com/api/address/' },
    { t:'bc_raw', u:'https://blockchain.info/rawaddr/' },
    { t:'bc_q',   u:'https://blockchain.info/q/addressbalance/' },
    { t:'blockcypher', u:'https://api.blockcypher.com/v1/btc/main/addrs/' },
    { t:'chainso', u:'https://chain.so/api/v2/get_address_balance/BTC/' },
    { t:'sochain', u:'https://sochain.com/api/v2/get_address_balance/BTC/' },
    { t:'bitaps', u:'https://api.bitaps.com/btc/v1/blockchain/address/' },
    { t:'blockchair', u:'https://api.blockchair.com/bitcoin/dashboards/address/' },
    { t:'smartbit', u:'https://api.smartbit.com.au/v1/blockchain/address/' },
    { t:'btccom', u:'https://chain.api.btc.com/v3/address/' },
    { t:'insight', u:'https://insight.bitpay.com/api/addr/' },
    { t:'insight', u:'https://explorer.bitcoin.com/api/btc/addr/' },
    { t:'tokenview', u:'https://services.tokenview.io/vipapi/coin/btc/address/balance/' },
    { t:'coinspace', u:'https://api.coin.space/v1/btc/address/' },
    { t:'insight', u:'https://bitpay.com/api/addr/' },
    { t:'esplora', u:'https://api.btcscan.org/api/address/' },
    { t:'blockonomics', u:'https://www.blockonomics.co/api/balance/' },
    { t:'bitcoinchain', u:'https://bitcoinchain.com/api/address/' },
];

const TOTAL_APIS = BATCH_APIS.length + INDIVIDUAL_APIS.length;

// ============================================================
//  FETCH WITH PROXY — NEW IP EVERY REQUEST, NO WAIT
// ============================================================
let apiCallCount = 0;

async function fetchT(url, ms) {
    var proxy = getNextProxy();
    var agent = getProxyAgent(proxy);
    var ctrl = new AbortController();
    var tid = setTimeout(function() { ctrl.abort(); }, ms);
    var opts = { signal: ctrl.signal, headers: { 'User-Agent': getUA() } };
    if (agent) opts.agent = agent;
    try {
        var r = await nodeFetch(url, opts);
        clearTimeout(tid);
        return r;
    } catch(e) { clearTimeout(tid); throw e; }
}

// ============================================================
//  ZERO / ERR
// ============================================================
var ZERO = { received: 0, sent: 0, balance: 0, error: false };
var ERR  = { received: 0, sent: 0, balance: 0, error: true };

// ============================================================
//  BATCH CHECK — 100 addresses in 1 request
//  NO WAIT on rate limit — just switch IP and retry
// ============================================================
async function checkBatchAPI(addressList) {
    var addrStr = addressList.map(function(a) { return a.addr; }).join('|');

    for (var b = 0; b < BATCH_APIS.length; b++) {
        var batchApi = BATCH_APIS[b];
        var url = batchApi.url + addrStr;

        // Try up to 10 times — each time gets a NEW PROXY (new IP)
        for (var attempt = 0; attempt < 10; attempt++) {
            try {
                apiCallCount++;
                var r = await fetchT(url, 15000);

                if (r.status === 200) {
                    var d = await r.json();
                    if (d.error) continue; // switch IP, retry

                    var results = {};

                    if (batchApi.name === 'bc_balance') {
                        for (var i = 0; i < addressList.length; i++) {
                            var item = addressList[i];
                            var ad = d[item.addr];
                            if (ad) {
                                results[item.addr] = {
                                    received: (ad.total_received || 0) / 1e8,
                                    sent: (ad.total_sent || 0) / 1e8,
                                    balance: (ad.final_balance || 0) / 1e8,
                                    error: false
                                };
                            } else {
                                results[item.addr] = { received: 0, sent: 0, balance: 0, error: false };
                            }
                        }
                        return results;
                    }

                    if (batchApi.name === 'bc_multi') {
                        var addrMap = {};
                        if (d.addresses) {
                            for (var j = 0; j < d.addresses.length; j++) {
                                var a = d.addresses[j];
                                addrMap[a.address] = {
                                    received: (a.total_received || 0) / 1e8,
                                    sent: (a.total_sent || 0) / 1e8,
                                    balance: (a.final_balance || 0) / 1e8,
                                    error: false
                                };
                            }
                        }
                        for (var k = 0; k < addressList.length; k++) {
                            results[addressList[k].addr] = addrMap[addressList[k].addr] || { received: 0, sent: 0, balance: 0, error: false };
                        }
                        return results;
                    }
                }

                // 429 or other HTTP error — NO WAIT, next loop iteration = new proxy
                continue;

            } catch(e) {
                // Timeout, connection error — NO WAIT, new proxy next try
                continue;
            }
        }
    }
    return null;
}

// ============================================================
//  INDIVIDUAL API CHECKERS (fallback)
// ============================================================
async function callIndividualAPI(ep, addr) {
    apiCallCount++;

    if (ep.t === 'esplora') {
        var r = await fetchT(ep.u + addr, 5000);
        if (!r.ok) throw 0;
        var d = await r.json();
        var c = d.chain_stats || d.mempool_stats || {};
        var f = parseInt(c.funded_txo_sum) || 0, s = parseInt(c.spent_txo_sum) || 0;
        return { received: f/1e8, sent: s/1e8, balance: (f-s)/1e8, error: false };
    }
    if (ep.t === 'bc_raw') {
        var r2 = await fetchT(ep.u + addr, 5000);
        if (!r2.ok) throw 0;
        var d2 = await r2.json();
        return { received: (d2.total_received||0)/1e8, sent: (d2.total_sent||0)/1e8, balance: (d2.final_balance||0)/1e8, error: false };
    }
    if (ep.t === 'bc_q') {
        var r3 = await fetchT(ep.u + addr, 5000);
        if (!r3.ok) throw 0;
        var txt = await r3.text();
        var bal = parseInt(txt);
        if (isNaN(bal)) throw 0;
        return { received: 0, sent: 0, balance: bal/1e8, error: false };
    }
    if (ep.t === 'blockcypher') {
        var r4 = await fetchT(ep.u + addr + '/balance', 5000);
        if (!r4.ok) throw 0;
        var d4 = await r4.json();
        return { received: (d4.total_received||0)/1e8, sent: (d4.total_sent||0)/1e8, balance: (d4.final_balance||0)/1e8, error: false };
    }
    if (ep.t === 'chainso' || ep.t === 'sochain') {
        var r5 = await fetchT(ep.u + addr, 5000);
        if (!r5.ok) throw 0;
        var d5 = await r5.json();
        if (d5.status !== 'success') throw 0;
        return { received: 0, sent: 0, balance: (parseFloat(d5.data.confirmed_balance)||0)/1e8, error: false };
    }
    if (ep.t === 'bitaps') {
        var r6 = await fetchT(ep.u + addr, 5000);
        if (!r6.ok) throw 0;
        var d6 = await r6.json();
        return { received: (d6.received||0)/1e8, sent: (d6.sent||0)/1e8, balance: (d6.balance||0)/1e8, error: false };
    }
    if (ep.t === 'blockchair') {
        var r7 = await fetchT(ep.u + addr + '?limit=0', 5000);
        if (!r7.ok) throw 0;
        var d7 = await r7.json();
        var ad7 = d7.data && d7.data[addr];
        if (!ad7) throw 0;
        return { received: (ad7.address.received||0)/1e8, sent: (ad7.address.spent||0)/1e8, balance: (ad7.address.balance||0)/1e8, error: false };
    }
    if (ep.t === 'smartbit') {
        var r8 = await fetchT(ep.u + addr, 5000);
        if (!r8.ok) throw 0;
        var d8 = await r8.json();
        if (!d8.success) throw 0;
        return { received: (d8.address.total_received||0)/1e8, sent: (d8.address.total_sent||0)/1e8, balance: (d8.address.balance||0)/1e8, error: false };
    }
    if (ep.t === 'btccom') {
        var r9 = await fetchT(ep.u + addr, 5000);
        if (!r9.ok) throw 0;
        var d9 = await r9.json();
        if (d9.err_no !== 0) throw 0;
        return { received: (d9.data.total_receive||0)/1e8, sent: 0, balance: (d9.data.balance||0)/1e8, error: false };
    }
    if (ep.t === 'insight') {
        var r10 = await fetchT(ep.u + addr, 5000);
        if (!r10.ok) throw 0;
        var d10 = await r10.json();
        return { received: (d10.totalReceivedSat||0)/1e8, sent: (d10.totalSentSat||0)/1e8, balance: (d10.balanceSat||0)/1e8, error: false };
    }
    if (ep.t === 'tokenview') {
        var r11 = await fetchT(ep.u + addr, 5000);
        if (!r11.ok) throw 0;
        var d11 = await r11.json();
        if (d11.code !== 200) throw 0;
        return { received: 0, sent: 0, balance: (parseFloat(d11.result)||0)/1e8, error: false };
    }
    if (ep.t === 'coinspace') {
        var r12 = await fetchT(ep.u + addr, 5000);
        if (!r12.ok) throw 0;
        var d12 = await r12.json();
        return { received: (d12.received||0)/1e8, sent: (d12.sent||0)/1e8, balance: (d12.balance||0)/1e8, error: false };
    }
    if (ep.t === 'blockonomics') {
        var proxy = getNextProxy();
        var agent = getProxyAgent(proxy);
        var ctrl2 = new AbortController();
        var tid2 = setTimeout(function() { ctrl2.abort(); }, 5000);
        var opts2 = { method: 'POST', headers: { 'Content-Type': 'application/json', 'User-Agent': getUA() }, body: JSON.stringify({ addrs: addr }), signal: ctrl2.signal };
        if (agent) opts2.agent = agent;
        var r13 = await nodeFetch('https://www.blockonomics.co/api/balance', opts2);
        clearTimeout(tid2);
        if (!r13.ok) throw 0;
        var d13 = await r13.json();
        if (d13.response && d13.response.length > 0) {
            var a13 = d13.response[0];
            return { received: (a13.received||0)/1e8, sent: 0, balance: (a13.balance||0)/1e8, error: false };
        }
        throw 0;
    }
    if (ep.t === 'bitcoinchain') {
        var r14 = await fetchT(ep.u + addr, 5000);
        if (!r14.ok) throw 0;
        var d14 = await r14.json();
        return { received: (d14.total_received||0)/1e8, sent: (d14.total_sent||0)/1e8, balance: (d14.balance||0)/1e8, error: false };
    }
    throw 0;
}

// Check one address — try shuffled APIs, NO WAIT between retries
async function checkBalanceFallback(addr) {
    var apis = INDIVIDUAL_APIS.slice().sort(function() { return Math.random() - 0.5; });
    var maxTries = Math.min(6, apis.length);
    for (var i = 0; i < maxTries; i++) {
        try {
            var r = await callIndividualAPI(apis[i], addr);
            if (r && !r.error) return r;
        } catch(e) {}
        // NO sleep — fetchT automatically uses new proxy on next call
    }
    return { received: 0, sent: 0, balance: 0, error: true };
}

// ============================================================
//  PARALLEL LIMITER
// ============================================================
async function parallelLimit(tasks, limit) {
    var results = new Array(tasks.length);
    var idx = 0;
    async function runNext() {
        while (idx < tasks.length) {
            var i = idx++;
            try { results[i] = await tasks[i](); } catch(e) { results[i] = { received: 0, sent: 0, balance: 0, error: true }; }
        }
    }
    var workers = [];
    for (var w = 0; w < Math.min(limit, tasks.length); w++) workers.push(runNext());
    await Promise.all(workers);
    return results;
}

// ============================================================
//  STATE
// ============================================================
var state = {
    checkCount: 0, foundCount: 0, foundData: [],
    startTime: Date.now(), speedValue: 0, addrChecked: 0,
    batchHits: 0, fallbackHits: 0
};

function saveFound(entry) {
    try {
        fs.appendFileSync('found_wallets.txt',
            'PRIV KEY: ' + entry.privkey_hex + '\n' +
            'COIN: BTC\nTYPE: ' + entry.addrType + '\n' +
            'COMP: ' + entry.comp_addr + '\n' +
            'UNCOMP: ' + (entry.uncomp_addr || 'N/A') + '\n' +
            'R:' + entry.received.toFixed(8) + ' S:' + entry.sent.toFixed(8) + ' B:' + entry.balance.toFixed(8) + ' BTC\n' +
            'DATE: ' + new Date().toISOString() + '\n' +
            '='.repeat(60) + '\n\n'
        );
    } catch(e) {}
}

// ============================================================
//  PROCESS BATCH
// ============================================================
async function processBatch() {
    var keys = genBatchKeys(BATCH_SIZE);
    var wallets = keys.map(function(k) { return deriveBTC(k); });
    state.checkCount += BATCH_SIZE;

    var allAddrs = [];
    for (var i = 0; i < wallets.length; i++) {
        allAddrs.push({ addr: wallets[i].comp_addr, type: 'comp', idx: i });
        allAddrs.push({ addr: wallets[i].uncomp_addr, type: 'uncomp', idx: i });
    }

    // STEP 1: BATCH API (100 addresses in 1 request, auto proxy rotation)
    var addrResults = null;
    try {
        addrResults = await checkBatchAPI(allAddrs);
    } catch(e) {
        console.log('[BATCH] Exception:', e.message);
    }

    if (addrResults) {
        state.batchHits++;
    } else {
        // STEP 2: FALLBACK — individual checks (auto proxy rotation)
        state.fallbackHits++;
        var tasks = allAddrs.map(function(item) { return function() { return checkBalanceFallback(item.addr); }; });
        var results = await parallelLimit(tasks, 25);
        addrResults = {};
        for (var j = 0; j < allAddrs.length; j++) {
            addrResults[allAddrs[j].addr] = results[j] || { received: 0, sent: 0, balance: 0, error: true };
        }
    }

    state.addrChecked += allAddrs.length;

    // EMIT each wallet
    for (var m = 0; m < wallets.length; m++) {
        var w = wallets[m];
        var compR = addrResults[w.comp_addr] || { received: 0, sent: 0, balance: 0, error: true };
        var uncompR = addrResults[w.uncomp_addr] || { received: 0, sent: 0, balance: 0, error: true };

        io.emit('wallet', {
            privkey_hex: w.privkey_hex,
            comp_addr: w.comp_addr,
            uncomp_addr: w.uncomp_addr,
            comp: compR, uncomp: uncompR,
            checkCount: state.checkCount, foundCount: state.foundCount,
            apiCallCount: apiCallCount, addrChecked: state.addrChecked
        });

        if (!compR.error && ((compR.received||0) > 0 || (compR.sent||0) > 0 || (compR.balance||0) > 0)) {
            state.foundCount++;
            var entry = { idx: state.foundCount, privkey_hex: w.privkey_hex, comp_addr: w.comp_addr, uncomp_addr: w.uncomp_addr, coin: 'Bitcoin', coinSym: 'BTC', addrType: 'COMPRESSED', received: compR.received, sent: compR.sent, balance: compR.balance };
            state.foundData.push(entry); saveFound(entry); io.emit('found', entry);
            console.log('\x1b[32m[FOUND] #' + entry.idx + ' BTC COMP B:' + entry.balance.toFixed(8) + '\x1b[0m');
        }
        if (!uncompR.error && ((uncompR.received||0) > 0 || (uncompR.sent||0) > 0 || (uncompR.balance||0) > 0)) {
            state.foundCount++;
            var entry2 = { idx: state.foundCount, privkey_hex: w.privkey_hex, comp_addr: w.comp_addr, uncomp_addr: w.uncomp_addr, coin: 'Bitcoin', coinSym: 'BTC', addrType: 'UNCOMPRESSED', received: uncompR.received, sent: uncompR.sent, balance: uncompR.balance };
            state.foundData.push(entry2); saveFound(entry2); io.emit('found', entry2);
            console.log('\x1b[32m[FOUND] #' + entry2.idx + ' BTC UNCOMP B:' + entry2.balance.toFixed(8) + '\x1b[0m');
        }
    }
}

// ============================================================
//  WORKERS (3 parallel)
// ============================================================
async function worker(id) {
    console.log('[WORKER ' + id + '] Started');
    while (true) {
        try { await processBatch(); }
        catch(e) { console.error('[W' + id + ' ERR]', e.message); await sleep(300); }
    }
}

// ============================================================
//  SPEED COUNTER
// ============================================================
var lastSpeedCheck = 0, lastSpeedTime = Date.now();
setInterval(function() {
    var now = Date.now(), elapsed = (now - lastSpeedTime) / 1000;
    if (elapsed >= 1) {
        var speed = Math.round((state.checkCount - lastSpeedCheck) / elapsed);
        if (speed > 0) state.speedValue = speed;
        io.emit('speed', {
            speed: state.speedValue, checkCount: state.checkCount,
            foundCount: state.foundCount, apiCallCount: apiCallCount,
            addrChecked: state.addrChecked,
            batchHits: state.batchHits, fallbackHits: state.fallbackHits,
            proxyCount: proxyCount
        });
        lastSpeedTime = now; lastSpeedCheck = state.checkCount;
    }
}, 1000);

// ============================================================
//  SOCKET.IO
// ============================================================
io.on('connection', function(socket) {
    console.log('[VIEWER] ' + socket.id + ' (' + io.engine.clientsCount + ')');
    socket.emit('init', {
        checkCount: state.checkCount, foundCount: state.foundCount,
        apiCallCount: apiCallCount, speed: state.speedValue, addrChecked: state.addrChecked,
        foundData: state.foundData.slice(-50), totalApis: TOTAL_APIS,
        batchApis: BATCH_APIS.length, individualApis: INDIVIDUAL_APIS.length,
        proxyCount: proxyCount
    });
    socket.on('disconnect', function() {});
});

// ============================================================
//  START — Load proxies FIRST, then start workers
// ============================================================
app.use(express.static('public'));

async function boot() {
    console.log('============================================');
    console.log('  PUZZLE #71 SCANNER v5 — PROXY ENGINE');
    console.log('  BTC ONLY | 50 Keys/Batch | 100 Addr/Req');
    console.log('  Batch APIs: ' + BATCH_APIS.length + ' | Individual: ' + INDIVIDUAL_APIS.length);
    console.log('  Total APIs: ' + TOTAL_APIS);
    console.log('  PROXY ROTATION: New IP every request');
    console.log('  NO WAIT on rate limit — instant IP switch');
    console.log('============================================');

    // Load proxies first (non-blocking for workers)
    fetchProxies().then(function() {
        console.log('[BOOT] Proxies loaded, scanner fully active');
    }).catch(function() {});
    proxyRefresher();

    io.emit('log', { msg: '<span style="color:#f97316;font-weight:900;font-size:14px">PUZZLE #71 SCANNER v5 — PROXY ROTATION ENGINE</span>' });
    io.emit('log', { msg: '<span style="color:#22c55e;font-weight:700">Mode: BATCH + AUTO PROXY ROTATION (New IP every request)</span>' });
    io.emit('log', { msg: '<span style="color:#60a5fa">Batch APIs: ' + BATCH_APIS.length + ' | Fallback APIs: ' + INDIVIDUAL_APIS.length + ' | Total: ' + TOTAL_APIS + '</span>' });
    io.emit('log', { msg: '<span style="color:#22d3ee">Primary: blockchain.info/balance + multiaddr (100 addr in 1 call)</span>' });
    io.emit('log', { msg: '<span style="color:#a78bfa">Proxy Sources: ' + PROXY_SOURCES.length + ' | Refresh: Every 60 seconds</span>' });
    io.emit('log', { msg: '<span style="color:#f472b6">NO WAIT on 429 — instant IP switch & retry</span>' });
    io.emit('log', { msg: '' });

    worker(1); worker(2); worker(3);
}

server.listen(PORT, boot);