// ============================================================
//  PUZZLE #71 SCANNER v4 — BATCH API ENGINE
//  BTC ONLY | 50 KEYS/BATCH | 100 ADDR IN 1 REQUEST
//  PRIMARY: blockchain.info/balance + multiaddr (BATCH)
//  FALLBACK: 36 Individual APIs (mempool, trezor, blockcypher...)
//  Like Python script: 100 addresses in 1 API call
// ============================================================

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const CryptoJS = require('crypto-js');
const elliptic = require('elliptic');
const fs = require('fs');
const crypto = require('crypto');

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
//  USER AGENT ROTATION (like Python fake_useragent)
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
function bytesToHex(bytes) { return Array.from(bytes, b => ('0' + b.toString(16)).slice(-2)).join(''); }
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
//  BATCH APIs — check 100 addresses in 1 request (like Python)
// ============================================================
const BATCH_APIS = [
    { name: 'bc_balance',  url: 'https://blockchain.info/balance?active=' },
    { name: 'bc_multi',    url: 'https://blockchain.info/multiaddr?active=' },
];

// ============================================================
//  INDIVIDUAL APIs — fallback (1 address per request)
// ============================================================
const INDIVIDUAL_APIS = [
    // === ESPLORA / MEMPOOL (fast, same format) ===
    { t:'esplora', u:'https://mempool.space/api/address/' },
    { t:'esplora', u:'https://blockstream.info/api/address/' },
    { t:'esplora', u:'https://mempool.emzy.de/api/address/' },
    { t:'esplora', u:'https://mempool.fmt.cash/api/address/' },
    { t:'esplora', u:'https://mempool.ninja/api/address/' },
    { t:'esplora', u:'https://btc1.trezor.io/api/address/' },
    { t:'esplora', u:'https://btc2.trezor.io/api/address/' },
    { t:'esplora', u:'https://btc3.trezor.io/api/address/' },
    { t:'esplora', u:'https://btc4.trezor.io/api/address/' },
    { t:'esplora', u:'https://btc5.trezor.io/api/address/' },
    { t:'esplora', u:'https://mempool.btc.petertodd.org/api/address/' },
    { t:'esplora', u:'https://mempool.bitcoin.pt/api/address/' },
    { t:'esplora', u:'https://mempool.nostr.zone/api/address/' },
    { t:'esplora', u:'https://mempool.donatebtc.io/api/address/' },
    { t:'esplora', u:'https://blockbook.blockstream.com/api/address/' },
    { t:'esplora', u:'https://blockbook8.blockstream.com/api/address/' },
    { t:'esplora', u:'https://mempool.ccd.le/api/address/' },
    { t:'esplora', u:'https://mempool.lunar.btc/api/address/' },
    // === BLOCKCHAIN.INFO (individual) ===
    { t:'bc_raw', u:'https://blockchain.info/rawaddr/' },
    { t:'bc_q',   u:'https://blockchain.info/q/addressbalance/' },
    // === BLOCKCYPHER ===
    { t:'blockcypher', u:'https://api.blockcypher.com/v1/btc/main/addrs/' },
    // === CHAIN.SO / SOCHAIN ===
    { t:'chainso', u:'https://chain.so/api/v2/get_address_balance/BTC/' },
    { t:'sochain', u:'https://sochain.com/api/v2/get_address_balance/BTC/' },
    // === BITAPS ===
    { t:'bitaps', u:'https://api.bitaps.com/btc/v1/blockchain/address/' },
    // === BLOCKCHAIR ===
    { t:'blockchair', u:'https://api.blockchair.com/bitcoin/dashboards/address/' },
    // === SMARTBIT ===
    { t:'smartbit', u:'https://api.smartbit.com.au/v1/blockchain/address/' },
    // === BTC.COM ===
    { t:'btccom', u:'https://chain.api.btc.com/v3/address/' },
    // === INSIGHT ===
    { t:'insight', u:'https://insight.bitpay.com/api/addr/' },
    { t:'insight', u:'https://explorer.bitcoin.com/api/btc/addr/' },
    // === TOKENVIEW ===
    { t:'tokenview', u:'https://services.tokenview.io/vipapi/coin/btc/address/balance/' },
    // === COINSPACE ===
    { t:'coinspace', u:'https://api.coin.space/v1/btc/address/' },
    // === BITPAY ===
    { t:'insight', u:'https://bitpay.com/api/addr/' },
    // === BTCSCAN ===
    { t:'esplora', u:'https://api.btcscan.org/api/address/' },
    // === BLOCKONOMICS ===
    { t:'blockonomics', u:'https://www.blockonomics.co/api/balance/' },
    // === BITCOINCHAIN ===
    { t:'bitcoinchain', u:'https://bitcoinchain.com/api/address/' },
];

const TOTAL_APIS = BATCH_APIS.length + INDIVIDUAL_APIS.length;

// ============================================================
//  NATIVE FETCH WITH ABORTCONTROLLER TIMEOUT
// ============================================================
let apiCallCount = 0;

async function fetchT(url, ms) {
    const ctrl = new AbortController();
    const tid = setTimeout(() => ctrl.abort(), ms);
    try {
        const r = await fetch(url, { signal: ctrl.signal, headers: { 'User-Agent': getUA() } });
        clearTimeout(tid);
        return r;
    } catch(e) { clearTimeout(tid); throw e; }
}

// ============================================================
//  ZERO / ERR constants
// ============================================================
const ZERO = { received: 0, sent: 0, balance: 0, error: false };
const ERR  = { received: 0, sent: 0, balance: 0, error: true };

// ============================================================
//  BATCH CHECK — blockchain.info (100 addresses in 1 request)
//  This is the SAME approach as the Python script
// ============================================================
async function checkBatchAPI(addressList) {
    // addressList: [{addr, type, idx}, ...]
    const addrStr = addressList.map(a => a.addr).join('|');

    for (const batchApi of BATCH_APIS) {
        const url = batchApi.url + addrStr;

        for (let attempt = 0; attempt < 3; attempt++) {
            try {
                apiCallCount++;
                const r = await fetchT(url, 20000);

                if (r.status === 200) {
                    const d = await r.json();
                    if (d.error) { console.log('[BATCH] API error:', d.error); await sleep(2000); continue; }

                    const results = {};

                    if (batchApi.name === 'bc_balance') {
                        // Response: { "addr1": {final_balance, total_received, total_sent}, ... }
                        // Always returns ALL addresses (even zero balance)
                        for (const item of addressList) {
                            const ad = d[item.addr];
                            if (ad) {
                                results[item.addr] = {
                                    received: (ad.total_received || 0) / 1e8,
                                    sent: (ad.total_sent || 0) / 1e8,
                                    balance: (ad.final_balance || 0) / 1e8,
                                    error: false
                                };
                            } else {
                                // Missing = never used = zero
                                results[item.addr] = { ...ZERO };
                            }
                        }
                        console.log('[BATCH] bc_balance OK — ' + addressList.length + ' addrs');
                        return results;
                    }

                    if (batchApi.name === 'bc_multi') {
                        // Response: { addresses: [{address, final_balance, ...}, ...] }
                        // May NOT include addresses with zero activity
                        const addrMap = {};
                        if (d.addresses) {
                            for (const a of d.addresses) {
                                addrMap[a.address] = {
                                    received: (a.total_received || 0) / 1e8,
                                    sent: (a.total_sent || 0) / 1e8,
                                    balance: (a.final_balance || 0) / 1e8,
                                    error: false
                                };
                            }
                        }
                        for (const item of addressList) {
                            results[item.addr] = addrMap[item.addr] || { ...ZERO };
                        }
                        console.log('[BATCH] bc_multi OK — ' + (d.addresses ? d.addresses.length : 0) + ' active addrs');
                        return results;
                    }
                }

                if (r.status === 429) {
                    console.log('[BATCH] Rate limited (' + batchApi.name + '), waiting 10s...');
                    await sleep(10000);
                    continue;
                }
                if (r.status === 403) {
                    console.log('[BATCH] 403 Forbidden (' + batchApi.name + '), waiting 3s...');
                    await sleep(3000);
                    continue;
                }

                // Other HTTP error
                console.log('[BATCH] HTTP ' + r.status + ' (' + batchApi.name + ')');
                await sleep(3000);
                continue;

            } catch(e) {
                if (e.name === 'AbortError') {
                    console.log('[BATCH] Timeout (' + batchApi.name + ')');
                    await sleep(2000);
                } else {
                    console.log('[BATCH] Error (' + batchApi.name + '): ' + e.message);
                    await sleep(1000);
                }
                continue;
            }
        }
    }

    return null; // All batch APIs failed after all retries
}

// ============================================================
//  INDIVIDUAL API CHECKERS (fallback — 1 address per request)
// ============================================================
async function callIndividualAPI(ep, addr) {
    apiCallCount++;

    if (ep.t === 'esplora') {
        const r = await fetchT(ep.u + addr, 5000);
        if (!r.ok) throw 0;
        const d = await r.json();
        const c = d.chain_stats || d.mempool_stats || {};
        const f = parseInt(c.funded_txo_sum) || 0, s = parseInt(c.spent_txo_sum) || 0;
        return { received: f/1e8, sent: s/1e8, balance: (f-s)/1e8, error: false };
    }

    if (ep.t === 'bc_raw') {
        const r = await fetchT(ep.u + addr, 5000);
        if (!r.ok) throw 0;
        const d = await r.json();
        return { received: (d.total_received||0)/1e8, sent: (d.total_sent||0)/1e8, balance: (d.final_balance||0)/1e8, error: false };
    }

    if (ep.t === 'bc_q') {
        // Returns plain text number (satoshis)
        const r = await fetchT(ep.u + addr, 5000);
        if (!r.ok) throw 0;
        const txt = await r.text();
        const bal = parseInt(txt);
        if (isNaN(bal)) throw 0;
        return { received: 0, sent: 0, balance: bal/1e8, error: false };
    }

    if (ep.t === 'blockcypher') {
        const r = await fetchT(ep.u + addr + '/balance', 5000);
        if (!r.ok) throw 0;
        const d = await r.json();
        return { received: (d.total_received||0)/1e8, sent: (d.total_sent||0)/1e8, balance: (d.final_balance||0)/1e8, error: false };
    }

    if (ep.t === 'chainso' || ep.t === 'sochain') {
        const r = await fetchT(ep.u + addr, 5000);
        if (!r.ok) throw 0;
        const d = await r.json();
        if (d.status !== 'success') throw 0;
        return { received: 0, sent: 0, balance: (parseFloat(d.data.confirmed_balance)||0)/1e8, error: false };
    }

    if (ep.t === 'bitaps') {
        const r = await fetchT(ep.u + addr, 5000);
        if (!r.ok) throw 0;
        const d = await r.json();
        return { received: (d.received||0)/1e8, sent: (d.sent||0)/1e8, balance: (d.balance||0)/1e8, error: false };
    }

    if (ep.t === 'blockchair') {
        const r = await fetchT(ep.u + addr + '?limit=0', 5000);
        if (!r.ok) throw 0;
        const d = await r.json();
        const ad = d.data && d.data[addr];
        if (!ad) throw 0;
        return { received: (ad.address.received||0)/1e8, sent: (ad.address.spent||0)/1e8, balance: (ad.address.balance||0)/1e8, error: false };
    }

    if (ep.t === 'smartbit') {
        const r = await fetchT(ep.u + addr, 5000);
        if (!r.ok) throw 0;
        const d = await r.json();
        if (!d.success) throw 0;
        return { received: (d.address.total_received||0)/1e8, sent: (d.address.total_sent||0)/1e8, balance: (d.address.balance||0)/1e8, error: false };
    }

    if (ep.t === 'btccom') {
        const r = await fetchT(ep.u + addr, 5000);
        if (!r.ok) throw 0;
        const d = await r.json();
        if (d.err_no !== 0) throw 0;
        return { received: (d.data.total_receive||0)/1e8, sent: 0, balance: (d.data.balance||0)/1e8, error: false };
    }

    if (ep.t === 'insight') {
        const r = await fetchT(ep.u + addr, 5000);
        if (!r.ok) throw 0;
        const d = await r.json();
        return { received: (d.totalReceivedSat||0)/1e8, sent: (d.totalSentSat||0)/1e8, balance: (d.balanceSat||0)/1e8, error: false };
    }

    if (ep.t === 'tokenview') {
        const r = await fetchT(ep.u + addr, 5000);
        if (!r.ok) throw 0;
        const d = await r.json();
        if (d.code !== 200) throw 0;
        return { received: 0, sent: 0, balance: (parseFloat(d.result)||0)/1e8, error: false };
    }

    if (ep.t === 'coinspace') {
        const r = await fetchT(ep.u + addr, 5000);
        if (!r.ok) throw 0;
        const d = await r.json();
        return { received: (d.received||0)/1e8, sent: (d.sent||0)/1e8, balance: (d.balance||0)/1e8, error: false };
    }

    if (ep.t === 'blockonomics') {
        // blockonomics expects POST with address list
        const r = await fetch(ep.u, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'User-Agent': getUA() },
            body: JSON.stringify({ addrs: addr }),
            signal: AbortSignal.timeout(5000)
        });
        if (!r.ok) throw 0;
        const d = await r.json();
        if (d.response && d.response.length > 0) {
            const a = d.response[0];
            return { received: (a.received||0)/1e8, sent: 0, balance: (a.balance||0)/1e8, error: false };
        }
        throw 0;
    }

    if (ep.t === 'bitcoinchain') {
        const r = await fetchT(ep.u + addr, 5000);
        if (!r.ok) throw 0;
        const d = await r.json();
        return { received: (d.total_received||0)/1e8, sent: (d.total_sent||0)/1e8, balance: (d.balance||0)/1e8, error: false };
    }

    // Unknown type — try generic JSON parse
    throw 0;
}

// Check one address by trying shuffled individual APIs
async function checkBalanceFallback(addr) {
    const apis = [...INDIVIDUAL_APIS].sort(() => Math.random() - 0.5);
    const maxTries = Math.min(5, apis.length);
    for (let i = 0; i < maxTries; i++) {
        try {
            const r = await callIndividualAPI(apis[i], addr);
            if (r && !r.error) return r;
        } catch(e) {}
        if (i < maxTries - 1) await sleep(150);
    }
    return { ...ERR };
}

// ============================================================
//  PARALLEL LIMITER
// ============================================================
async function parallelLimit(tasks, limit) {
    const results = new Array(tasks.length);
    let idx = 0;
    async function runNext() {
        while (idx < tasks.length) {
            const i = idx++;
            try { results[i] = await tasks[i](); } catch(e) { results[i] = { ...ERR }; }
        }
    }
    const workers = Array.from({length: Math.min(limit, tasks.length)}, () => runNext());
    await Promise.all(workers);
    return results;
}

// ============================================================
//  STATE
// ============================================================
const state = {
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
//  PROCESS BATCH: 50 keys → 100 addresses → 1 batch API call
// ============================================================
async function processBatch() {
    const keys = genBatchKeys(BATCH_SIZE);
    const wallets = keys.map(k => deriveBTC(k));
    state.checkCount += BATCH_SIZE;

    // Build 100 address list (50 comp + 50 uncomp)
    const allAddrs = [];
    for (let i = 0; i < wallets.length; i++) {
        allAddrs.push({ addr: wallets[i].comp_addr, type: 'comp', idx: i });
        allAddrs.push({ addr: wallets[i].uncomp_addr, type: 'uncomp', idx: i });
    }

    // === STEP 1: BATCH API (100 addresses in 1 request — like Python) ===
    let addrResults = null;
    try {
        addrResults = await checkBatchAPI(allAddrs);
    } catch(e) {
        console.log('[BATCH] Exception:', e.message);
    }

    if (addrResults) {
        state.batchHits++;
    } else {
        // === STEP 2: FALLBACK — Individual API checks ===
        state.fallbackHits++;
        console.log('[FALLBACK] Batch failed, checking ' + allAddrs.length + ' addrs individually...');

        const tasks = allAddrs.map(item => () => checkBalanceFallback(item.addr));
        const results = await parallelLimit(tasks, 25);

        addrResults = {};
        for (let i = 0; i < allAddrs.length; i++) {
            addrResults[allAddrs[i].addr] = results[i] || { ...ERR };
        }
    }

    state.addrChecked += allAddrs.length;

    // === EMIT each wallet real-time ===
    for (let i = 0; i < wallets.length; i++) {
        const w = wallets[i];
        const compR = addrResults[w.comp_addr] || { ...ERR };
        const uncompR = addrResults[w.uncomp_addr] || { ...ERR };

        io.emit('wallet', {
            privkey_hex: w.privkey_hex,
            comp_addr: w.comp_addr,
            uncomp_addr: w.uncomp_addr,
            comp: compR,
            uncomp: uncompR,
            checkCount: state.checkCount,
            foundCount: state.foundCount,
            apiCallCount,
            addrChecked: state.addrChecked
        });

        // Check compressed
        if (!compR.error && ((compR.received||0) > 0 || (compR.sent||0) > 0 || (compR.balance||0) > 0)) {
            state.foundCount++;
            const entry = {
                idx: state.foundCount, privkey_hex: w.privkey_hex,
                comp_addr: w.comp_addr, uncomp_addr: w.uncomp_addr,
                coin: 'Bitcoin', coinSym: 'BTC', addrType: 'COMPRESSED',
                received: compR.received, sent: compR.sent, balance: compR.balance
            };
            state.foundData.push(entry); saveFound(entry); io.emit('found', entry);
            console.log('\x1b[32m[FOUND] #' + entry.idx + ' BTC COMP B:' + entry.balance.toFixed(8) + '\x1b[0m');
        }

        // Check uncompressed
        if (!uncompR.error && ((uncompR.received||0) > 0 || (uncompR.sent||0) > 0 || (uncompR.balance||0) > 0)) {
            state.foundCount++;
            const entry = {
                idx: state.foundCount, privkey_hex: w.privkey_hex,
                comp_addr: w.comp_addr, uncomp_addr: w.uncomp_addr,
                coin: 'Bitcoin', coinSym: 'BTC', addrType: 'UNCOMPRESSED',
                received: uncompR.received, sent: uncompR.sent, balance: uncompR.balance
            };
            state.foundData.push(entry); saveFound(entry); io.emit('found', entry);
            console.log('\x1b[32m[FOUND] #' + entry.idx + ' BTC UNCOMP B:' + entry.balance.toFixed(8) + '\x1b[0m');
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
        catch(e) { console.error('[W' + id + ' ERR]', e.message); await sleep(500); }
    }
}

// ============================================================
//  SPEED COUNTER (every 1 sec)
// ============================================================
let lastSpeedCheck = 0, lastSpeedTime = Date.now();
setInterval(function() {
    const now = Date.now(), elapsed = (now - lastSpeedTime) / 1000;
    if (elapsed >= 1) {
        const speed = Math.round((state.checkCount - lastSpeedCheck) / elapsed);
        if (speed > 0) state.speedValue = speed;
        io.emit('speed', {
            speed: state.speedValue, checkCount: state.checkCount,
            foundCount: state.foundCount, apiCallCount,
            addrChecked: state.addrChecked,
            batchHits: state.batchHits, fallbackHits: state.fallbackHits
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
        apiCallCount, speed: state.speedValue, addrChecked: state.addrChecked,
        foundData: state.foundData.slice(-50), totalApis: TOTAL_APIS,
        batchApis: BATCH_APIS.length, individualApis: INDIVIDUAL_APIS.length
    });
    socket.on('disconnect', function() {});
});

// ============================================================
//  START
// ============================================================
app.use(express.static('public'));
server.listen(PORT, function() {
    console.log('============================================');
    console.log('  PUZZLE #71 SCANNER v4 — BATCH ENGINE');
    console.log('  BTC ONLY | 50 Keys/Batch | 100 Addr/Req');
    console.log('  Batch APIs: ' + BATCH_APIS.length + ' | Individual: ' + INDIVIDUAL_APIS.length);
    console.log('  Total APIs: ' + TOTAL_APIS);
    console.log('  PRIMARY: blockchain.info/balance (100 addr in 1 call)');
    console.log('  FALLBACK: mempool + trezor + blockcypher + 30 more');
    console.log('============================================');
    io.emit('log', { msg: '<span style="color:#f97316;font-weight:900;font-size:14px">PUZZLE #71 SCANNER v4 — BATCH ENGINE</span>' });
    io.emit('log', { msg: '<span style="color:#22c55e;font-weight:700">Mode: BATCH (100 addresses in 1 API call — like Python)</span>' });
    io.emit('log', { msg: '<span style="color:#60a5fa">Batch APIs: ' + BATCH_APIS.length + ' | Fallback APIs: ' + INDIVIDUAL_APIS.length + ' | Total: ' + TOTAL_APIS + '</span>' });
    io.emit('log', { msg: '<span style="color:#22d3ee">Primary: blockchain.info/balance + multiaddr</span>' });
    io.emit('log', { msg: '<span style="color:#a78bfa">Fallback: mempool.space + blockstream + trezor + 30 more</span>' });
    io.emit('log', { msg: '' });
    worker(1); worker(2); worker(3);
});