// ============================================================
//  PUZZLE #71 SCANNER v7 — REAL API ONLY ENGINE
//  BTC ONLY | 10 KEYS/BATCH | 20 ADDR/SEC
//  ONLY blockchain.info BATCH API (CONFIRMED REAL)
//  NO FAKE APIs — NO RPC — NO MEMPOOL
//  PROXY ROTATION — NEW IP EVERY REQUEST
//  FOUND = ANY NON-ZERO IN R/S/B → INSTANT SAVE
//  D = REAL VIEWER COUNT
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
const BATCH_SIZE = 10; // 10 keys = 20 addresses per batch (20 addr/sec)
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
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
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

function getNextProxy() {
    if (proxyPool.length === 0) return null;
    const p = proxyPool[proxyIdx % proxyPool.length];
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
            if (agentCache.size > 800) {
                const keys = [...agentCache.keys()].slice(0, 200);
                keys.forEach(k => agentCache.delete(k));
            }
        } catch(e) { return undefined; }
    }
    return agent;
}

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
    console.log('[PROXY] Pool ready: ' + proxyCount + ' proxies');
}

async function proxyRefresher() {
    while (true) {
        try { await fetchProxies(); } catch(e) { console.log('[PROXY] Refresh error:', e.message); }
        await sleep(60000);
    }
}

// ============================================================
//  REAL BATCH APIs ONLY — blockchain.info (CONFIRMED REAL)
//  These show correct balance (50.00001641 BTC vs fake 0.00001641)
//  NO mempool, NO blockstream, NO fake APIs, NO RPC
// ============================================================
const BATCH_APIS = [
    { name: 'bc_balance', url: 'https://blockchain.info/balance?active=' },
    { name: 'bc_multi',   url: 'https://blockchain.info/multiaddr?active=' },
];

const TOTAL_APIS = BATCH_APIS.length;

// ============================================================
//  FETCH WITH PROXY — NEW IP EVERY REQUEST
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
//  BATCH CHECK — blockchain.info REAL API
//  20 addresses in 1 request, auto retry on error with new IP
// ============================================================
async function checkBatchAPI(addressList) {
    var addrStr = addressList.map(function(a) { return a.addr; }).join('|');

    for (var b = 0; b < BATCH_APIS.length; b++) {
        var batchApi = BATCH_APIS[b];
        var url = batchApi.url + addrStr;

        // Try up to 5 times — each time NEW PROXY (new IP)
        for (var attempt = 0; attempt < 5; attempt++) {
            try {
                apiCallCount++;
                var r = await fetchT(url, 15000);

                if (r.status === 200) {
                    var d = await r.json();
                    if (d.error) continue;

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

                // 429 or error — switch IP (next loop = new proxy)
                continue;

            } catch(e) {
                // Timeout/connection error — switch proxy, retry
                continue;
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
//  PROCESS BATCH — Generate → Check → Display ONLY after response
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

    // CHECK via blockchain.info REAL batch API
    var addrResults = null;
    try {
        addrResults = await checkBatchAPI(allAddrs);
    } catch(e) {
        console.log('[BATCH] Exception:', e.message);
    }

    if (addrResults) {
        state.batchHits++;
    } else {
        state.batchMiss++;
    }

    // Build default zero results if batch failed
    var results = addrResults || {};
    state.addrChecked += allAddrs.length;

    // EMIT each wallet — ONLY after API response
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

        // FOUND: ANY non-zero in R, S, or B → instant save + dashboard
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
//  WORKERS (3 parallel — each does 20 addr/sec with proxy)
// ============================================================
async function worker(id) {
    console.log('[WORKER ' + id + '] Started');
    while (true) {
        try { await processBatch(); }
        catch(e) { console.error('[W' + id + ' ERR]', e.message); await sleep(100); }
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
        // REAL viewer count — no fake, no obfuscation
        var realViewers = io.engine.clientsCount;
        io.emit('speed', {
            speed: state.speedValue, checkCount: state.checkCount,
            foundCount: state.foundCount, apiCallCount: apiCallCount,
            addrChecked: state.addrChecked,
            batchHits: state.batchHits, batchMiss: state.batchMiss,
            proxyCount: proxyCount, viewers: realViewers
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
        foundData: state.foundData.slice(-50), totalApis: TOTAL_APIS,
        proxyCount: proxyCount, viewers: realViewers
    });
    socket.on('disconnect', function() {});
});

// ============================================================
//  START
// ============================================================
app.use(express.static('public'));

async function boot() {
    console.log('============================================');
    console.log('  PUZZLE #71 SCANNER v7 — REAL API ONLY');
    console.log('  BTC ONLY | 10 Keys/Batch | 20 Addr/Sec');
    console.log('  Real APIs: ' + TOTAL_APIS + ' (blockchain.info ONLY)');
    console.log('  NO fake APIs | NO RPC | NO mempool');
    console.log('  PROXY ROTATION: New IP every request');
    console.log('  D = REAL viewer count');
    console.log('============================================');

    fetchProxies().then(function() {
        console.log('[BOOT] Proxies loaded, scanner active');
    }).catch(function() {});
    proxyRefresher();

    io.emit('log', { msg: '<span style="color:#f97316;font-weight:900;font-size:14px">PUZZLE #71 SCANNER v7 — REAL API ONLY</span>' });
    io.emit('log', { msg: '<span style="color:#22c55e;font-weight:700">ONLY blockchain.info Batch API (Confirmed Real Balance)</span>' });
    io.emit('log', { msg: '<span style="color:#ef4444;font-weight:700">NO fake APIs | NO mempool | NO blockstream | NO RPC</span>' });
    io.emit('log', { msg: '<span style="color:#60a5fa">Batch: 10 keys = 20 addresses per request</span>' });
    io.emit('log', { msg: '<span style="color:#a78bfa">Proxy Sources: ' + PROXY_SOURCES.length + ' | Refresh: Every 60 seconds</span>' });
    io.emit('log', { msg: '<span style="color:#f472b6">429/Error = instant IP switch & retry (no wait)</span>' });
    io.emit('log', { msg: '<span style="color:#facc15">FOUND = Any R>0 OR S>0 OR B>0 → Instant Save</span>' });
    io.emit('log', { msg: '<span style="color:#64748b">D = Real live viewer count (no fake)</span>' });
    io.emit('log', { msg: '' });

    worker(1); worker(2); worker(3);
}

server.listen(PORT, boot);