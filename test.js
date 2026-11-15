const { peel } = require('./engine.js');
const zlib = require('zlib');
const b64u = o => Buffer.from(JSON.stringify(o)).toString('base64url');
const now = Math.floor(Date.now()/1000);
const jwt = b64u({alg:'HS256',typ:'JWT'})+'.'+b64u({iss:'https://auth.acme.dev',sub:'user_8841',aud:'billing-api',scope:'invoices:read invoices:write',iat:1763190000,exp:1763193600})+'.'+'q7Zk3vXw9LmN2pRs5TuY8aBcDeFgHiJkLmNoPqRsTuV';
const curl = `curl -sS -X POST 'https://api.acme.dev/v2/invoices?since=1763164800&expand=customer' \\\n  -H 'Authorization: Bearer ${jwt}' \\\n  -H 'Content-Type: application/json' \\\n  -d '{"customer_id":"cus_9f2a","amount":4200,"currency":"usd","due_at":1765756800,"notify":true}'`;
const gz = zlib.gzipSync(JSON.stringify({event:'deploy.finished',service:'checkout',commit:'9fceb02d0ae598e95dc970b74767f19372d61af8',finished_at:1763200000,callback:'https://hooks.acme.dev/ci?token=abc123defg&run=8841'})).toString('base64');
const ex = {
 curl, gz,
 cron:'*/15 9-17 * * 1-5', cron2:'0 0 13 * 5', cron3:'30 4 * * *', cron4:'@daily', cron5:'0 */6 * * *',cron6:'5,35 * * * *',
 py:`Traceback (most recent call last):\n  File "/app/worker/main.py", line 42, in <module>\n    run()\n  File "/app/worker/jobs.py", line 118, in run\n    total = summarize(rows)\n  File "/usr/lib/python3.12/site-packages/pandas/core/frame.py", line 4102, in __getitem__\n    indexer = self.columns.get_loc(key)\nKeyError: 'amount_cents'`,
 js:`TypeError: Cannot read properties of undefined (reading 'id')\n    at getUser (/srv/app/src/services/user.js:27:31)\n    at async /srv/app/src/routes/profile.js:14:18\n    at Layer.handle [as handle_request] (/srv/app/node_modules/express/lib/router/layer.js:95:5)\n    at next (/srv/app/node_modules/express/lib/router/route.js:144:13)\n    at process.processTicksAndRejections (node:internal/process/task_queues:95:5)`,
 java:`Exception in thread "main" java.lang.RuntimeException: boom\n\tat com.acme.App.main(App.java:10)\nCaused by: java.lang.NullPointerException: x is null\n\tat org.springframework.web.Foo.bar(Foo.java:22)\n\tat com.acme.Service.load(Service.java:55)\n\tat java.base/java.lang.Thread.run(Thread.java:833)`,
 broken:`{'name': 'checkout', 'replicas': 3, 'debug': False, 'owner': None, 'tags': ['api', 'payments',],}`,
 broken2:`{"a": 1,\n "b": [1,2,\n "c": 3}`,
 url:'https://shop.acme.dev/login?next=https%3A%2F%2Fshop.acme.dev%2Forders%3Fid%3D8841%26ts%3D1763200000&utm_source=newsletter&utm_campaign=nov&fbclid=IwAR0abc',
 ts:'1763200000', ms:'1763200000123', uuid7:'019a8b2e-7c40-7d3a-9f1e-2b6c4d8e0a11', uuid4:'3f2b8c1e-9d4a-4e7b-a1c2-5d6e7f8091a2',
 color:'#f0b90b', cidr:'10.42.7.19/20', n404:'404', n:'86400', sha:'9fceb02d0ae598e95dc970b74767f19372d61af8',
 log:`2026-11-15T09:12:44Z ERROR payment failed request_id=3f2b8c1e-9d4a-4e7b-a1c2-5d6e7f8091a2 ctx={"user":8841,"retry_at":1763200300} from 10.42.7.19`,
 iso:'2026-11-15T09:12:44Z', iso2:'2026-11-15 09:12:44', b64:'eyJ1c2VyIjo4ODQxLCJyb2xlIjoiYWRtaW4ifQ==', word:'password', hello:'hello world this is text',
 esc:'"{\\"a\\":1,\\"b\\":\\"x\\"}"', pct:'name%3DJohn%20Doe%26x%3D1', qs:'a=1&b=hello%20world&c=3', oid:'65a1b2c3d4e5f60718293a4b', chmod:'755', ent:'&lt;div class=&quot;x&quot;&gt;Tom &amp; Jerry&lt;/div&gt;',
 datauri:'data:text/plain;base64,SGVsbG8sIHdvcmxkIQ==', ghp:'export TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789',
 curl2:`curl -u admin:s3cret -k -F 'file=@report.pdf' -F name=q3 http://files.acme.dev/upload`,
};
const show = (r, ind='') => { console.log(ind+`[${r.label}] ${r.score} — ${r.summary}`); (r.rows||[]).forEach(x=>console.log(ind+'   '+x.k+': '+x.v)); (r.notes||[]).forEach(x=>console.log(ind+'   ('+x.level+') '+x.text)); if(r.table) r.table.rows.slice(0,6).forEach(x=>console.log(ind+'   | '+(x.mark?'>> ':'')+x.cells.join(' | '))); if(process.env.B)(r.blocks||[]).forEach(b=>console.log(ind+'   --'+b.title+'--\n'+b.text)); (r.children||[]).forEach(c=>{console.log(ind+'   └ '+c.label); show(c.result, ind+'      ')}); };
(async()=>{
 const only = process.argv[2];
 for (const [k,v] of Object.entries(ex)) { if(only&&k!==only) continue; console.log('\n=== '+k); const out = await peel(v); out.results.forEach(r=>show(r)); if(out.secrets.length) console.log('SECRETS', out.secrets); console.log('layers', out.layers); }
 require('fs').writeFileSync('examples.json', JSON.stringify(ex));
})();
