// ============================================================
//  PUZZLE #71 SCANNER v9 — ZERO DELAY ENGINE
//  BTC ONLY | 2 KEYS/BATCH | 4 ADDR/REQ
//  INSTANT: Generate → Check → Emit → Next (NO delay)
//  DIRECT first → Proxy only on 429
//  Proxy VERIFIED before use
//  NO RETRY — one shot per API, fast failover
//  D = REAL viewer count
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

const RANGE_MIN = 1n << 66n;
const RANGE_MAX = (1n << 67n) - 1n;
const BATCH_SIZE = 2; // 2 keys = 4 addresses per request
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
];
function getUA() { return UAS[Math.floor(Math.random() * UAS.length)]; }

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
        if (attempts > 100000) { generatedKeys.clear(); attempts = 0; }
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
//  PROXY SYSTEM — VERIFY BEFORE USE
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
let verifiedPool = [];
let proxyIdx = 0;
let proxyCount = 0;
let verifiedCount = 0;
let useProxy = false;

function getNextProxy() {
    if (verifiedPool.length === 0) return null;
    const p = verifiedPool[proxyIdx % verifiedPool.length];
    proxyIdx++;
    return p;
}

const agentCache = new Map();
function getProxyAgent(proxyUrl) {
    if (!proxyUrl) return undefined;
    let agent = agentCache.get(proxyUrl);
    if (!agent) {
        try {
            agent = new HttpsProxyAgent(proxyUrl);
            agentCache.set(proxyUrl, agent);
            if (agentCache.size > 300) {
                const keys = [...agentCache.keys()].slice(0, 50);
                keys.forEach(k => agentCache.delete(k));
            }
        } catch(e) { return undefined; }
    }
    return agent;
}

// Fetch proxy lists from sources
async function fetchProxyLists() {
    console.log('[PROXY] Fetching from ' + PROXY_SOURCES.length + ' sources...');
    const newProxies = new Set();
    const results = await Promise.allSettled(
        PROXY_SOURCES.map(function(src) {
            const ctrl = new AbortController();
            const tid = setTimeout(function() { ctrl.abort(); }, 5000);
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
            if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}$/.test(lines[j])) {
                newProxies.add('http://' + lines[j]);
            }
        }
    }
    proxyPool = Array.from(newProxies).sort(function() { return Math.random() - 0.5; });
    proxyCount = proxyPool.length;
    console.log('[PROXY] Raw: ' + proxyCount);
}

// VERIFY proxies — test against blockchain.info, keep only REAL ones
async function verifyProxies() {
    if (proxyPool.length === 0) return;
    console.log('[VERIFY] Testing proxies against blockchain.info...');
    var testUrl = 'https://blockchain.info/q/getblockcount';
    var working = [];
    var tested = 0;
    var batchSize = 80;
    var maxTest = 600;

    for (var i = 0; i < proxyPool.length && tested < maxTest; i += batchSize) {
        var batch = proxyPool.slice(i, Math.min(i + batchSize, proxyPool.length));
        var checks = batch.map(function(proxyUrl) {
            tested++;
            var ctrl = new AbortController();
            var tid = setTimeout(function() { ctrl.abort(); }, 3000);
            try {
                var agent = new HttpsProxyAgent(proxyUrl);
                return nodeFetch(testUrl, { signal: ctrl.signal, agent: agent, timeout: 3000 })
                    .then(function(r) { clearTimeout(tid); return r.ok ? proxyUrl : null; })
                    .catch(function() { clearTimeout(tid); return null; });
            } catch(e) { clearTimeout(tid); return Promise.resolve(null); }
        });
        var results = await Promise.allSettled(checks);
        for (var j = 0; j < results.length; j++) {
            if (results[j].status === 'fulfilled' && results[j].value) {
                working.push(results[j].value);
            }
        }
    }

    verifiedPool = working.sort(function() { return Math.random() - 0.5; });
    verifiedCount = verifiedPool.length;
    proxyIdx = 0;
    console.log('[VERIFY] REAL proxies: ' + verifiedCount + ' / ' + tested + ' tested');
}

// Background proxy manager: fetch + verify every 90 seconds
async function proxyManager() {
    while (true) {
        try {
            await fetchProxyLists();
            await verifyProxies();
            // If we found good proxies, keep using direct until 429
            if (verifiedCount > 0) useProxy = false;
        } catch(e) { console.log('[PROXY] Error:', e.message); }
        await new Promise(r => setTimeout(r, 90000));
    }
}

// ============================================================
//  REAL BATCH APIs — blockchain.info ONLY (confirmed real)
// ============================================================
const BATCH_APIS = [
    { name: 'bc_balance', url: 'https://blockchain.info/balance?active=' },
    { name: 'bc_multi',   url: 'https://blockchain.info/multiaddr?active=' },
];

// ============================================================
//  INSTANT FETCH — 3s timeout, NO retry
// ============================================================
let apiCallCount = 0;
let directHits = 0;
let proxyHits = 0;

async function instantFetch(url, proxyUrl) {
    var ctrl = new AbortController();
    var tid = setTimeout(function() { ctrl.abort(); }, 3000); // 3s timeout — FAST
    var opts = { signal: ctrl.signal, headers: { 'User-Agent': getUA() } };

    if (proxyUrl) {
        var agent = getProxyAgent(proxyUrl);
        if (agent) opts.agent = agent;
    }

    try {
        var r = await nodeFetch(url, opts);
        clearTimeout(tid);
        return r;
    } catch(e) {
        clearTimeout(tid);
        return null; // Fail fast, return null
    }
}

// ============================================================
//  BATCH CHECK — ONE SHOT per API, NO RETRY, ZERO DELAY
// ============================================================
async function checkBatch(addressList) {
    var addrStr = addressList.map(function(a) { return a.addr; }).join('|');

    for (var b = 0; b < BATCH_APIS.length; b++) {
        var api = BATCH_APIS[b];
        var url = api.url + addrStr;

        // Step 1: Try DIRECT (fastest — no proxy)
        apiCallCount++;
        var r = await instantFetch(url, null);

        if (r && r.status === 429) {
            // Rate limited — switch to proxy mode
            useProxy = true;
            var proxy = getNextProxy();
            if (proxy) {
                apiCallCount++;
                r = await instantFetch(url, proxy);
                if (r && r.status === 429) {
                    // Try another proxy
                    proxy = getNextProxy();
                    if (proxy) {
                        apiCallCount++;
                        r = await instantFetch(url, proxy);
                    }
                }
            }
            if (!r || r.status !== 200) continue;
        }

        if (r && r.status === 200) {
            if (!useProxy) directHits++; else proxyHits++;

            var d;
            try { d = await r.json(); } catch(e) { continue; }
            if (d.error) continue;

            var results = {};

            if (api.name === 'bc_balance') {
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

            if (api.name === 'bc_multi') {
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
    }
    return null;
}

// ============================================================
//  STATE
// ============================================================
var state = {
    checkCount: 0, foundCount: 0, foundData: [],
    startTime: Date.now(), speedValue: 0, addrChecked: 0,
    batchHits: 0, batchMiss: 0
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
//  PROCESS BATCH — INSTANT (no delay, no retry)
// ============================================================
async function processBatch() {
    // Step 1: Generate keys (instant — microseconds)
    var keys = genBatchKeys(BATCH_SIZE);
    var wallets = keys.map(function(k) { return deriveBTC(k); });
    state.checkCount += BATCH_SIZE;

    // Step 2: Build address list (instant)
    var allAddrs = [];
    for (var i = 0; i < wallets.length; i++) {
        allAddrs.push({ addr: wallets[i].comp_addr, type: 'comp', idx: i });
        allAddrs.push({ addr: wallets[i].uncomp_addr, type: 'uncomp', idx: i });
    }

    // Step 3: Check balance (one shot, 3s max)
    var addrResults = null;
    try {
        addrResults = await checkBatch(allAddrs);
    } catch(e) {}

    if (addrResults) {
        state.batchHits++;
    } else {
        state.batchMiss++;
    }

    var results = addrResults || {};
    state.addrChecked += allAddrs.length;

    // Step 4: Emit results (instant)
    for (var m = 0; m < wallets.length; m++) {
        var w = wallets[m];
        var compR = results[w.comp_addr] || { received: 0, sent: 0, balance: 0, error: !addrResults };
        var uncompR = results[w.uncomp_addr] || { received: 0, sent: 0, balance: 0, error: !addrResults };

        io.emit('wallet', {
            privkey_hex: w.privkey_hex,
            comp_addr: w.comp_addr,
            uncomp_addr: w.uncomp_addr,
            comp: compR, uncomp: uncompR,
            checkCount: state.checkCount, foundCount: state.foundCount,
            apiCallCount: apiCallCount, addrChecked: state.addrChecked
        });

        // Check FOUND (R>0 OR S>0 OR B>0)
        if (!compR.error && ((compR.received||0) > 0 || (compR.sent||0) > 0 || (compR.balance||0) > 0)) {
            state.foundCount++;
            var entry = { idx: state.foundCount, privkey_hex: w.privkey_hex, comp_addr: w.comp_addr, uncomp_addr: w.uncomp_addr, coin: 'Bitcoin', coinSym: 'BTC', addrType: 'COMPRESSED', received: compR.received, sent: compR.sent, balance: compR.balance };
            state.foundData.push(entry); saveFound(entry); io.emit('found', entry);
            console.log('\x1b[32m[FOUND] #' + entry.idx + ' BTC COMP R:'+entry.received.toFixed(8)+' S:'+entry.sent.toFixed(8)+' B:'+entry.balance.toFixed(8)+'\x1b[0m');
        }
        if (!uncompR.error && ((uncompR.received||0) > 0 || (uncompR.sent||0) > 0 || (uncompR.balance||0) > 0)) {
            state.foundCount++;
            var entry2 = { idx: state.foundCount, privkey_hex: w.privkey_hex, comp_addr: w.comp_addr, uncomp_addr: w.uncomp_addr, coin: 'Bitcoin', coinSym: 'BTC', addrType: 'UNCOMPRESSED', received: uncompR.received, sent: uncompR.sent, balance: uncompR.balance };
            state.foundData.push(entry2); saveFound(entry2); io.emit('found', entry2);
            console.log('\x1b[32m[FOUND] #' + entry2.idx + ' BTC UNCOMP R:'+entry2.received.toFixed(8)+' S:'+entry2.sent.toFixed(8)+' B:'+entry2.balance.toFixed(8)+'\x1b[0m');
        }
    }
}

// ============================================================
//  WORKERS — 3 parallel, ZERO DELAY loop
// ============================================================
async function worker(id) {
    console.log('[WORKER ' + id + '] Started — ZERO DELAY');
    while (true) {
        try {
            await processBatch();
            // NO sleep, NO delay — immediately next batch
        }
        catch(e) { console.error('[W' + id + ' ERR]', e.message); }
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
        var realViewers = io.engine.clientsCount;
        io.emit('speed', {
            speed: state.speedValue, checkCount: state.checkCount,
            foundCount: state.foundCount, apiCallCount: apiCallCount,
            addrChecked: state.addrChecked,
            batchHits: state.batchHits, batchMiss: state.batchMiss,
            proxyCount: verifiedCount, rawProxies: proxyCount,
            directHits: directHits, proxyHits: proxyHits,
            viewers: realViewers
        });
        lastSpeedTime = now; lastSpeedCheck = state.checkCount;
    }
}, 1000);

// ============================================================
//  SOCKET.IO
// ============================================================
io.on('connection', function(socket) {
    var realViewers = io.engine.clientsCount;
    console.log('[VIEWER] ' + socket.id + ' (total: ' + realViewers + ')');
    socket.emit('init', {
        checkCount: state.checkCount, foundCount: state.foundCount,
        apiCallCount: apiCallCount, speed: state.speedValue, addrChecked: state.addrChecked,
        foundData: state.foundData.slice(-50), totalApis: BATCH_APIS.length,
        proxyCount: verifiedCount, viewers: realViewers
    });
    socket.on('disconnect', function() {});
});

// ============================================================
//  START
// ============================================================
app.use(express.static('public'));

async function boot() {
    console.log('============================================');
    console.log('  PUZZLE #71 SCANNER v9 — ZERO DELAY');
    console.log('  BTC ONLY | 2 Keys/Batch | 4 Addr/Req');
    console.log('  Generate → Check → Emit → NEXT (instant)');
    console.log('  3s timeout | NO retry | DIRECT first');
    console.log('  Proxy VERIFY — only real working proxies');
    console.log('  D = REAL viewer count');
    console.log('============================================');

    // Start proxy manager in background
    proxyManager();

    io.emit('log', { msg: '<span style="color:#f97316;font-weight:900;font-size:14px">PUZZLE #71 SCANNER v9 — ZERO DELAY ENGINE</span>' });
    io.emit('log', { msg: '<span style="color:#22c55e;font-weight:700">Generate → Check → Emit → NEXT (instant, no delay)</span>' });
    io.emit('log', { msg: '<span style="color:#60a5fa">2 keys = 4 addresses per API call</span>' });
    io.emit('log', { msg: '<span style="color:#a78bfa">3s timeout | NO retry | DIRECT first</span>' });
    io.emit('log', { msg: '<span style="color:#f472b6">Proxy VERIFY: Only real working proxies used</span>' });
    io.emit('log', { msg: '<span style="color:#facc15">FOUND = Any R>0 OR S>0 OR B>0 → Instant Save</span>' });
    io.emit('log', { msg: '<span style="color:#64748b">D = Real live viewer count</span>' });
    io.emit('log', { msg: '' });

    // Start workers immediately
    worker(1); worker(2); worker(3);
}

server.listen(PORT, boot);