// End-to-end: the BROWSER SDK signs a payment and submits it to the LIVE sequencer service over
// HTTP, exactly as a web app would. Proves the whole stack composes: WASM-signed intent -> HTTP ->
// sequencer -> sealed checkpoint -> trustless DA reconstruct, all through the SAME stf.
//
// Run: start the service in WSL (lc-sequencer-service --port 8910), then on the host:
//   node crates/sequencer-service/demo/wasm-e2e.js
const m = require('../../wasm/pkg-node/liquid_cells_wasm.js');
const BASE = process.env.LC_SERVICE || 'http://127.0.0.1:8910';

async function rpc(path, method = 'GET', body) {
  const opt = { method };
  if (body !== undefined) {
    opt.body = typeof body === 'string' ? body : JSON.stringify(body);
    opt.headers = { 'content-type': 'application/json' };
  }
  const r = await fetch(BASE + path, opt);
  const text = await r.text();
  if (!r.ok) throw new Error(`${path} -> ${r.status} ${text}`);
  try { return JSON.parse(text); } catch { return text; }
}

(async () => {
  // Wait for the service, then read its pool identity (accounts must be scoped to it).
  let info;
  for (let i = 0; i < 40; i++) {
    try { info = await rpc('/info'); break; } catch { await new Promise((r) => setTimeout(r, 300)); }
  }
  if (!info) throw new Error('service not reachable at ' + BASE);
  console.log('service:', BASE, '| pool', info.pool_id.slice(0, 18) + '...', '| chain', info.chain_id, '| seq', info.seq);

  const pool = info.pool_id;
  const chain = BigInt(info.chain_id);
  const alice = new m.WasmAccount(pool, chain, '0x' + '00'.repeat(31) + '0a');
  const bobKey = new m.WasmAccount(pool, chain, '0x' + '00'.repeat(31) + '0b').key();
  console.log('alice', alice.key());
  console.log('bob  ', bobKey);

  // 1. Fund Alice (a deposit is L1-authorized; the demo submits it directly).
  await rpc('/submit', 'POST', { type: 'deposit', to_key: alice.key(), amount: '1000000' });
  await rpc('/seal', 'POST', { current_epoch: 1 });
  console.log('alice funded:', (await rpc('/leaf?key=' + alice.key())).balance);

  // 2. Alice signs a transfer to Bob IN THE SDK, and submits the signed JSON over HTTP.
  const transfer = alice.transfer(bobKey, '250000', '10', 100n);
  console.log('wasm-signed transfer, sig', JSON.parse(transfer).sig.slice(0, 26) + '...');
  await rpc('/submit', 'POST', transfer);
  const sealed = await rpc('/seal', 'POST', { current_epoch: 2 });
  console.log('sealed: seq', sealed.seq, 'root', sealed.root.slice(0, 18) + '...');

  // 3. Bob got paid; Alice debited amount + fee.
  const bob = await rpc('/leaf?key=' + bobKey);
  const al = await rpc('/leaf?key=' + alice.key());
  console.log('bob balance  :', bob.balance, '(expected 250000)');
  console.log('alice balance:', al.balance, '(expected 749990)');
  if (bob.balance !== '250000' || al.balance !== '749990') throw new Error('balances wrong');

  // 4. Trustless check: rebuild the root from published DA in the SDK; it must equal the service root.
  const da = await rpc('/da');
  const reconRoot = m.reconstruct_root(JSON.stringify(da.blobs));
  const info2 = await rpc('/info');
  console.log('DA reconstruct root:', reconRoot.slice(0, 18) + '...');
  console.log('service root       :', info2.root.slice(0, 18) + '...');
  if (reconRoot !== info2.root) throw new Error('DA reconstruct != service root');

  console.log('\nEND-TO-END PASSED: WASM-signed payment -> HTTP -> sequencer -> checkpoint, DA verified by the SDK');
})().catch((e) => { console.error('FAILED:', e.message); process.exit(1); });
