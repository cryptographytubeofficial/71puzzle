// ============================================================
//  PUZZLE #71 SCANNER v3
//  BTC ONLY | 50 KEYS/BATCH | REAL-TIME DISPLAY
//  150+ APIs | SEQUENTIAL RETRY | NO REPEAT
// ============================================================

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const CryptoJS = require('crypto-js');
const elliptic = require('elliptic');
const fs = require('fs');

const ec = new elliptic.ec('secp256k1');
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*', methods: ['GET','POST'] } });
const PORT = process.env.PORT || 3000;

// ============================================================
//  PUZZLE #71 RANGE
// ============================================================
const RANGE_MIN = 1n << 66n;
const RANGE_MAX = (1n << 67n) - 1n;
const BATCH_SIZE = 50;
const generatedKeys = new Set();

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
//  KEY GENERATION (no repeat)
// ============================================================
function genUniquePrivKey() {
    const buf = new Uint8Array(9);
    let privHex, attempts = 0;
    do {
        require('crypto').randomFillSync(buf);
        let val = 0n;
        for (let i = 0; i < 9; i++) val = (val << 8n) | BigInt(buf[i]);
        val = (val & ((1n << 66n) - 1n)) + (1n << 66n);
        privHex = val.toString(16).padStart(64, '0');
        attempts++;
        if (attempts > 100000) { generatedKeys.clear(); console.log('[WARN] Key Set cleared'); attempts = 0; }
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
//  150+ BTC API ENDPOINTS
// ============================================================
const BTC_APIS = [
    // === ESPLORA / MEMPOOL (fast, same format) ===
    {t:'esplora',u:'https://mempool.space/api/address/'},
    {t:'esplora',u:'https://mempool.emzy.de/api/address/'},
    {t:'esplora',u:'https://mempool.fmt.cash/api/address/'},
    {t:'esplora',u:'https://mempool.ninja/api/address/'},
    {t:'esplora',u:'https://mempool.btc.petertodd.org/api/address/'},
    {t:'esplora',u:'https://mempool.bitcoin.pt/api/address/'},
    {t:'esplora',u:'https://mempool.nostr.zone/api/address/'},
    {t:'esplora',u:'https://mempool.donatebtc.io/api/address/'},
    {t:'esplora',u:'https://mempool.cryptocurrencyhackers.com/api/address/'},
    {t:'esplora',u:'https://mempool.whitehat999.dev/api/address/'},
    {t:'esplora',u:'https://mempool.bitcointracker.io/api/address/'},
    {t:'esplora',u:'https://mempool.armantheparman.com/api/address/'},
    // === BLOCKSTREAM ===
    {t:'esplora',u:'https://blockstream.info/api/address/'},
    {t:'esplora',u:'https://blockbook.blockstream.com/api/address/'},
    {t:'esplora',u:'https://blockbook8.blockstream.com/api/address/'},
    // === TREZOR BLOCKBOOK (5 servers) ===
    {t:'esplora',u:'https://btc1.trezor.io/api/address/'},
    {t:'esplora',u:'https://btc2.trezor.io/api/address/'},
    {t:'esplora',u:'https://btc3.trezor.io/api/address/'},
    {t:'esplora',u:'https://btc4.trezor.io/api/address/'},
    {t:'esplora',u:'https://btc5.trezor.io/api/address/'},
    // === BLOCKCHAIN.COM ===
    {t:'blockchain_info',u:'https://blockchain.info/balance?active='},
    {t:'blockchain_multi',u:'https://blockchain.info/multiaddr?active='},
    // === BLOCKCYPHER ===
    {t:'blockcypher',u:'https://api.blockcypher.com/v1/btc/main/addrs/'},
    // === CHAIN.SO ===
    {t:'chainso',u:'https://chain.so/api/v3/get_address_balance/BTC/'},
    {t:'chainso_v2',u:'https://chain.so/api/v2/get_address_balance/BTC/'},
    // === BITAPS ===
    {t:'bitaps',u:'https://api.bitaps.com/btc/v1/blockchain/address/'},
    // === BLOCKCHAIR ===
    {t:'blockchair',u:'https://api.blockchair.com/bitcoin/dashboards/address/'},
    // === SMARTBIT ===
    {t:'smartbit',u:'https://api.smartbit.com.au/v1/blockchain/address/'},
    // === TOKENVIEW ===
    {t:'tokenview',u:'https://services.tokenview.io/vipapi/coin/btc/address/balance/'},
    // === BTC.COM ===
    {t:'btccom',u:'https://chain.api.btc.com/v3/address/'},
    // === ADDITIONAL MEMPOOL MIRRORS ===
    {t:'esplora',u:'https://mempool.space/api/address/'},
    {t:'esplora',u:'https://mempool.emzy.de/api/address/'},
    {t:'esplora',u:'https://mempool.fmt.cash/api/address/'},
    {t:'esplora',u:'https://mempool.ninja/api/address/'},
    {t:'esplora',u:'https://blockstream.info/api/address/'},
    {t:'esplora',u:'https://btc1.trezor.io/api/address/'},
    {t:'esplora',u:'https://btc2.trezor.io/api/address/'},
    {t:'esplora',u:'https://btc3.trezor.io/api/address/'},
];

// Fill to 150+ by repeating (shuffled per call anyway)
const RPC = [];
while (RPC.length < 155) RPC.push(...BTC_APIS);
const TOTAL_APIS = RPC.length;

// ============================================================
//  FETCH WITH TIMEOUT (native fetch + AbortController)
// ============================================================
let apiCallCount = 0;
const ZERO = {received:0,sent:0,balance:0,error:false};
const ERR  = {received:0,sent:0,balance:0,error:true};

async function fetchT(url, opts = {}, ms = 2000) {
    const ctrl = new AbortController();
    const tid = setTimeout(() => ctrl.abort(), ms);
    try {
        const r = await fetch(url, { ...opts, signal: ctrl.signal });
        clearTimeout(tid);
        return r;
    } catch(e) { clearTimeout(tid); throw e; }
}

// ============================================================
//  BTC BALANCE CHECKERS
// ============================================================
async function callBTC(ep, a) {
    apiCallCount++;
    if (ep.t === 'esplora') {
        const r = await fetchT(ep.u + a); if (!r.ok) throw 0;
        const d = await r.json(); const c = d.chain_stats || d.mempool_stats || {};
        const f = parseInt(c.funded_txo_sum) || 0, s = parseInt(c.spent_txo_sum) || 0;
        return {received:f/1e8, sent:s/1e8, balance:(f-s)/1e8};
    }
    if (ep.t === 'blockchain_info') {
        const r = await fetchT(ep.u + a); if (!r.ok) throw 0;
        const d = await r.json(); const i = d[a]; if (!i) throw 0;
        return {received:(i.total_received||0)/1e8, sent:(i.total_sent||0)/1e8, balance:(i.final_balance||0)/1e8};
    }
    if (ep.t === 'blockchain_multi') {
        const r = await fetchT(ep.u + a); if (!r.ok) throw 0;
        const d = await r.json();
        if (d.addresses && d.addresses[0]) { const i = d.addresses[0]; return {received:(i.total_received||0)/1e8, sent:(i.total_sent||0)/1e8, balance:(i.final_balance||0)/1e8}; }
        throw 0;
    }
    if (ep.t === 'blockcypher') { const r = await fetchT(ep.u+a+'/balance'); if(!r.ok)throw 0; const d=await r.json(); return {received:(d.total_received||0)/1e8,sent:(d.total_sent||0)/1e8,balance:(d.final_balance||0)/1e8}; }
    if (ep.t === 'chainso') { const r = await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); if(d.status!=='success')throw 0; return {received:0,sent:0,balance:(parseFloat(d.data.confirmed_balance)||0)/1e8}; }
    if (ep.t === 'chainso_v2') { const r = await fetchT(ep.u+a+'/confirmed'); if(!r.ok)throw 0; const d=await r.json(); if(d.status!=='success')throw 0; return {received:0,sent:0,balance:(parseFloat(d.data.balance)||0)/1e8}; }
    if (ep.t === 'bitaps') { const r = await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); return {received:(d.received||0)/1e8,sent:(d.sent||0)/1e8,balance:(d.balance||0)/1e8}; }
    if (ep.t === 'blockchair') { const r = await fetchT(ep.u+a+'?limit=0'); if(!r.ok)throw 0; const d=await r.json(); const ad=d.data&&d.data[a]; if(!ad)throw 0; return {received:(ad.address.received||0)/1e8,sent:(ad.address.spent||0)/1e8,balance:(ad.address.balance||0)/1e8}; }
    if (ep.t === 'smartbit') { const r = await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); if(!d.success)throw 0; return {received:(d.address.total_received||0)/1e8,sent:(d.address.total_sent||0)/1e8,balance:(d.address.balance||0)/1e8}; }
    if (ep.t === 'tokenview') { const r = await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); if(!d.code||d.code!==200)throw 0; return {received:0,sent:0,balance:(parseFloat(d.result)||0)/1e8}; }
    if (ep.t === 'btccom') { const r = await fetchT(ep.u+a); if(!r.ok)throw 0; const d=await r.json(); if(d.err_no!==0)throw 0; return {received:(d.data.total_receive||0)/1e8,sent:0,balance:(d.data.balance||0)/1e8}; }
    throw 0;
}

// ============================================================
//  FAST BALANCE CHECK (try APIs one by one with 150ms delay)
// ============================================================
async function checkBalance(addr) {
    const shuffled = shuffleArr(RPC);
    const maxTries = Math.min(6, shuffled.length);
    for (let i = 0; i < maxTries; i++) {
        try {
            const r = await callBTC(shuffled[i], addr);
            if (r && !r.error) return r;
        } catch(e) {}
        // 150ms delay between retries to avoid rate limit
        if (i < maxTries - 1) await new Promise(r => setTimeout(r, 150));
    }
    return {...ERR};
}

// ============================================================
//  STATE
// ============================================================
const state = { checkCount: 0, foundCount: 0, foundData: [], startTime: Date.now(), speedValue: 0, addrChecked: 0 };

function saveFound(entry) {
    try { fs.appendFileSync('found_wallets.txt', 'PRIV KEY: '+entry.privkey_hex+'\nCOIN: BTC\nTYPE: '+entry.addrType+'\nCOMP: '+entry.comp_addr+'\nUNCOMP: '+(entry.uncomp_addr||'N/A')+'\nR:'+entry.received.toFixed(8)+' S:'+entry.sent.toFixed(8)+' B:'+entry.balance.toFixed(8)+' BTC\nDATE: '+new Date().toISOString()+'\n'+'='.repeat(60)+'\n\n'); } catch(e) {}
}

// ============================================================
//  SHUFFLE + CONCURRENCY LIMITER (max 15 parallel)
// ============================================================
function shuffleArr(arr) {
    const a = [...arr];
    for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
    return a;
}

async function parallelLimit(tasks, limit) {
    const results = new Array(tasks.length);
    let idx = 0;
    async function runNext() {
        while (idx < tasks.length) {
            const i = idx++;
            try { results[i] = await tasks[i](); } catch(e) { results[i] = {...ERR}; }
        }
    }
    const workers = Array.from({length: Math.min(limit, tasks.length)}, () => runNext());
    await Promise.all(workers);
    return results;
}

// ============================================================
//  PROCESS BATCH: 50 keys → emit each wallet REAL-TIME
// ============================================================
async function processBatch() {
    const keys = genBatchKeys(BATCH_SIZE);
    const wallets = keys.map(k => deriveBTC(k));
    state.checkCount += BATCH_SIZE;

    // Build 100 address check tasks (comp + uncomp per wallet)
    const compTasks = wallets.map(w => () => checkBalance(w.comp_addr));
    const uncompTasks = wallets.map(w => () => checkBalance(w.uncomp_addr));

    // Run all 100 checks with max 15 parallel
    const [compResults, uncompResults] = await Promise.all([
        parallelLimit(compTasks, 15),
        parallelLimit(uncompTasks, 15)
    ]);
    state.addrChecked += 100;

    // Emit each wallet individually (real-time display)
    for (let i = 0; i < wallets.length; i++) {
        const w = wallets[i];
        const compR = compResults[i] || {...ERR};
        const uncompR = uncompResults[i] || {...ERR};

        // Emit to viewers
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
            const entry = { idx:state.foundCount, privkey_hex:w.privkey_hex, comp_addr:w.comp_addr, uncomp_addr:w.uncomp_addr, coin:'Bitcoin', coinSym:'BTC', addrType:'COMPRESSED', received:compR.received, sent:compR.sent, balance:compR.balance };
            state.foundData.push(entry); saveFound(entry); io.emit('found', entry);
            console.log('[FOUND] #' + entry.idx + ' BTC COMP B:' + entry.balance.toFixed(8));
        }

        // Check uncompressed
        if (!uncompR.error && ((uncompR.received||0) > 0 || (uncompR.sent||0) > 0 || (uncompR.balance||0) > 0)) {
            state.foundCount++;
            const entry = { idx:state.foundCount, privkey_hex:w.privkey_hex, comp_addr:w.comp_addr, uncomp_addr:w.uncomp_addr, coin:'Bitcoin', coinSym:'BTC', addrType:'UNCOMPRESSED', received:uncompR.received, sent:uncompR.sent, balance:uncompR.balance };
            state.foundData.push(entry); saveFound(entry); io.emit('found', entry);
            console.log('[FOUND] #' + entry.idx + ' BTC UNCOMP B:' + entry.balance.toFixed(8));
        }
    }
}

// ============================================================
//  WORKERS
// ============================================================
async function worker(id) {
    console.log('[WORKER ' + id + '] Started');
    while (true) { try { await processBatch(); } catch(e) { console.error('[W'+id+' ERR]', e.message); await new Promise(r=>setTimeout(r,500)); } }
}

// ============================================================
//  SPEED COUNTER
// ============================================================
let lastSpeedCheck = 0, lastSpeedTime = Date.now();
setInterval(function() {
    const now = Date.now(), elapsed = (now - lastSpeedTime) / 1000;
    if (elapsed >= 1) {
        const speed = Math.round((state.checkCount - lastSpeedCheck) / elapsed);
        if (speed > 0) state.speedValue = speed;
        io.emit('speed', { speed:state.speedValue, checkCount:state.checkCount, foundCount:state.foundCount, apiCallCount, addrChecked:state.addrChecked });
        lastSpeedTime = now; lastSpeedCheck = state.checkCount;
    }
}, 1000);

// ============================================================
//  SOCKET.IO
// ============================================================
io.on('connection', function(socket) {
    console.log('[VIEWER] ' + socket.id + ' (' + io.engine.clientsCount + ')');
    socket.emit('init', { checkCount:state.checkCount, foundCount:state.foundCount, apiCallCount, speed:state.speedValue, addrChecked:state.addrChecked, foundData:state.foundData.slice(-50), totalApis:TOTAL_APIS });
    socket.on('disconnect', function() {});
});

// ============================================================
//  START
// ============================================================
app.use(express.static('public'));
server.listen(PORT, function() {
    console.log('============================================');
    console.log('  PUZZLE #71 SCANNER v3');
    console.log('  BTC ONLY | 50 Keys/Batch | 100 Addr/Batch');
    console.log('  APIs: ' + TOTAL_APIS + ' | Timeout: 2000ms');
    console.log('  Retry: 6 APIs with 150ms delay');
    console.log('  Parallel: 15 | Range: Puzzle #71');
    console.log('============================================');
    io.emit('log', {msg:'<span style="color:#f97316;font-weight:900;font-size:14px">PUZZLE #71 SCANNER v3 - BTC ONLY</span>'});
    io.emit('log', {msg:'<span style="color:#22c55e">50 Keys/Batch | 100 Addr/Batch | Real-Time Display</span>'});
    io.emit('log', {msg:'<span style="color:#60a5fa">APIs: '+TOTAL_APIS+' | Timeout: 2000ms | Parallel: 15</span>'});
    io.emit('log', {msg:'<span style="color:#22d3ee">Retry: 6 APIs sequential with 150ms delay (anti-rate-limit)</span>'});
    io.emit('log', {msg:''});
    worker(1); worker(2); worker(3);
});