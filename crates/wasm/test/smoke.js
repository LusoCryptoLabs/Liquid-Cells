// Node smoke test for the Liquid Cells WASM SDK. Proves the SAME stf runs in WebAssembly: sign a
// transfer, cross-check the sha256 swap hashlock against node's own crypto, run the keccak SMT
// reconstruct, and round-trip an HTLC lock -> claim. Run: node test/smoke.js  (after build.sh).
const assert = require('assert');
const crypto = require('crypto');
const m = require('../pkg-node/liquid_cells_wasm.js');

const POOL = '0x' + '11'.repeat(32);
const SECRET = '0x' + '00'.repeat(31) + '07';
const hexOf = (s) => '0x' + Buffer.from(s).toString('hex');

// 1. identity. NB: u64 params/returns (chain_id, expiry, timeout, nonce) cross as JS BigInt.
const a = new m.WasmAccount(POOL, 0x434b42n, SECRET);
assert.strictEqual(a.key().length, 66, 'key is 32 bytes hex');
assert.strictEqual(a.pubkey().length, 68, 'pubkey is 33 bytes hex');
assert.strictEqual(a.ckb_lock_args().length, 42, 'lock args 20 bytes hex');
assert.strictEqual(Number(a.nonce()), 0);
console.log('account key   :', a.key());
console.log('ckb lock args :', a.ckb_lock_args());

// 2. signed transfer, nonce advances
const t = JSON.parse(a.transfer('0x' + '22'.repeat(32), '1000', '10', 100n));
assert.strictEqual(t.type, 'transfer');
assert.strictEqual(t.amount, '1000');
assert.strictEqual(t.nonce, 0);
assert.strictEqual(t.sig.length, 130, 'sig is 64 bytes hex');
assert.strictEqual(Number(a.nonce()), 1, 'nonce advanced after signing');
console.log('transfer sig  :', t.sig.slice(0, 26) + '...');

// 3. swap hashlock H = sha256(secret) matches node's crypto exactly (the cross-impl check)
const H = '0x' + crypto.createHash('sha256').update(Buffer.from('liquid-cells')).digest('hex');
const Hwasm = m.swap_hashlock_sha256(hexOf('liquid-cells'));
assert.strictEqual(Hwasm, H, `sha256 mismatch: ${Hwasm} != ${H}`);
console.log('sha256 hashlock matches node crypto:', Hwasm === H);

// 4. the keccak SMT reconstruct runs in wasm (empty history -> the empty-tree root, 32 bytes)
const root = m.reconstruct_root('[]');
assert.strictEqual(root.length, 66, 'reconstruct returns a 32-byte root');
console.log('empty-tree root:', root);

// 5. HTLC lock -> ref -> claim round-trips through the same byte layouts
const locked = JSON.parse(a.htlc_lock('0x' + '33'.repeat(32), '5000', '1', Hwasm, 50n));
assert.strictEqual(locked.type, 'htlc_lock');
const claim = JSON.parse(m.htlc_claim(JSON.stringify(locked.htlc_ref), hexOf('liquid-cells')));
assert.strictEqual(claim.type, 'htlc_claim');
assert.strictEqual(claim.preimage, hexOf('liquid-cells'));

console.log('\nWASM SDK smoke test PASSED');
