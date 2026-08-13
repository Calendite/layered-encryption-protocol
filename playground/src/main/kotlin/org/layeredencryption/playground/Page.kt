package org.layeredencryption.playground

/** The playground page. Self-contained: no CDN, no build step, no framework. */
val PLAYGROUND_PAGE = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Layered Encryption Playground</title>
<style>
  :root{--paper:#f7f7f4;--panel:#fff;--rule:#dcdcd4;--soft:#f0f0ea;--text:#12161f;--muted:#5f6672;
    --faint:#9aa1ac;--accent:#3b3f8f;--accentSoft:#3b3f8f14;--pass:#2f6b45;--passSoft:#2f6b4514;
    --fail:#8f3128;--failSoft:#8f31281a;--wire:#8a5a12;--wireSoft:#8a5a1214;
    --pq:#7a2f6b;--pqSoft:#7a2f6b14;--cls:#1f5f6b;--clsSoft:#1f5f6b14;
    --mono:ui-monospace,'SF Mono',Menlo,Consolas,monospace;
    --sans:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;}
  @media (prefers-color-scheme:dark){:root{--paper:#0e1117;--panel:#161a22;--rule:#272d38;--soft:#1b2029;
    --text:#e8e9ec;--muted:#9aa3b2;--faint:#69727f;--accent:#9ba4ff;--accentSoft:#9ba4ff18;
    --pass:#7fc79a;--passSoft:#7fc79a18;--fail:#e0857c;--failSoft:#e0857c1f;--wire:#d9a441;--wireSoft:#d9a44118;
    --pq:#d79ad0;--pqSoft:#d79ad018;--cls:#77c6d4;--clsSoft:#77c6d418;}}
  *{box-sizing:border-box}
  body{margin:0;background:var(--paper);color:var(--text);font-family:var(--sans);font-size:15px;
    line-height:1.55;padding:30px 20px 70px}
  .wrap{max-width:960px;margin:0 auto;display:flex;flex-direction:column;gap:20px}
  h1{font-size:23px;margin:0;font-weight:650}
  .sub{color:var(--muted);font-size:13.5px;max-width:76ch;margin:6px 0 0}
  .panel{background:var(--panel);border:1px solid var(--rule);border-radius:12px;overflow:hidden}
  .panel h2{margin:0;padding:12px 18px;font-size:12px;font-weight:700;letter-spacing:.1em;
    text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--rule);
    display:flex;align-items:center;gap:10px}
  .panel .body{padding:16px 18px}
  textarea{width:100%;min-height:74px;background:var(--soft);color:var(--text);border:1px solid var(--rule);
    border-radius:9px;padding:11px 13px;font:inherit;font-size:14px;resize:vertical}
  textarea:focus{outline:2px solid var(--accent);outline-offset:1px}
  .controls{display:flex;align-items:center;gap:14px;margin-top:11px;flex-wrap:wrap}
  button.send{background:var(--accent);color:#fff;border:none;border-radius:9px;padding:9px 20px;
    font:inherit;font-size:14px;font-weight:600;cursor:pointer}
  button.send:disabled{opacity:.55;cursor:default}
  label.tamper{display:flex;align-items:center;gap:7px;font-size:13px;color:var(--muted);cursor:pointer;
    border:1px solid var(--rule);border-radius:9px;padding:7px 12px}
  label.tamper.on{color:var(--fail);border-color:var(--fail);background:var(--failSoft);font-weight:600}
  .hint{color:var(--faint);font-size:12.5px;margin-left:auto}

  .verdict{display:flex;align-items:center;gap:10px;padding:13px 18px;font-size:14px;font-weight:600;
    border-bottom:1px solid var(--rule)}
  .verdict.delivered{color:var(--pass);background:var(--passSoft)}
  .verdict.rejected{color:var(--fail);background:var(--failSoft)}
  .verdict.idle{color:var(--muted)}
  .verdict .small{font-weight:400;color:var(--muted);font-size:12.5px}

  .step{display:flex;gap:13px;padding:14px 18px;border-bottom:1px solid var(--rule)}
  .step:last-child{border-bottom:none}
  .who{flex:none;width:58px;font-family:var(--mono);font-size:11px;font-weight:700;letter-spacing:.06em;
    text-transform:uppercase;padding-top:3px}
  .who.A{color:var(--accent)} .who.B{color:var(--pass)} .who.wire{color:var(--wire)} .who.both{color:var(--muted)}
  .what{flex:1;min-width:0}
  .title{font-weight:600;font-size:14px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
  .detail{color:var(--muted);font-size:12.5px;margin-top:3px}
  .alg{display:inline-flex;align-items:center;gap:5px;font-family:var(--mono);font-size:10.5px;font-weight:600;
    border-radius:6px;padding:1px 7px;border:1px solid var(--cls);color:var(--cls);background:var(--clsSoft)}
  .alg.pq{border-color:var(--pq);color:var(--pq);background:var(--pqSoft)}
  .alg .dot{width:5px;height:5px;border-radius:50%;background:currentColor}
  table.parts{width:100%;border-collapse:collapse;margin-top:9px;font-size:12px}
  table.parts th{text-align:left;font-size:10px;letter-spacing:.08em;text-transform:uppercase;
    color:var(--faint);font-weight:700;padding:0 10px 5px 0}
  table.parts td{padding:2px 10px 2px 0;color:var(--muted);vertical-align:top}
  table.parts td.n{color:var(--text);font-family:var(--mono);white-space:nowrap}
  table.parts td.b{font-family:var(--mono);white-space:nowrap}
  table.parts td.v{font-family:var(--mono);color:var(--accent);word-break:break-all}
  .bytes{margin-top:9px}
  .hexbtn{font-family:var(--mono);font-size:11.5px;color:var(--muted);background:var(--soft);
    border:1px solid var(--rule);border-radius:8px;padding:7px 11px;width:100%;text-align:left;
    cursor:pointer;word-break:break-all;display:block;line-height:1.6}
  .hexbtn:hover{border-color:var(--accent);color:var(--text)}
  .hexbtn .more{color:var(--accent);font-weight:600}
  .plain{margin-top:9px;background:var(--accentSoft);border:1px solid var(--accent);border-radius:8px;
    padding:9px 12px;font-size:13.5px;color:var(--text)}
  .step.failed{background:var(--failSoft)}
  .step.failed .title,.step.failed .detail{color:var(--fail)}
  .empty{padding:22px 18px;color:var(--faint);font-size:13.5px}
  .usewhen{font-size:11.5px;color:var(--muted);font-style:italic}
  footer{color:var(--faint);font-size:12.5px;max-width:78ch}
  code{font-family:var(--mono);font-size:.92em;background:var(--soft);padding:1px 5px;border-radius:4px}
  dialog{border:1px solid var(--rule);border-radius:12px;background:var(--panel);color:var(--text);
    padding:0;max-width:min(700px,92vw);width:100%}
  dialog::backdrop{background:rgba(8,10,14,.55)}
  dialog header{display:flex;gap:10px;align-items:baseline;padding:13px 17px;border-bottom:1px solid var(--rule)}
  dialog .t{font-weight:650;font-size:14px}
  dialog .n{font-family:var(--mono);font-size:11.5px;color:var(--muted)}
  dialog button{margin-left:auto;background:none;border:1px solid var(--rule);border-radius:7px;
    color:var(--muted);font:inherit;font-size:12px;padding:3px 10px;cursor:pointer}
  dialog .val{padding:15px 17px;font-family:var(--mono);font-size:12px;line-height:1.75;
    word-break:break-all;max-height:52vh;overflow-y:auto}
</style></head><body>
<div class="wrap">
  <div>
    <h1>Layered Encryption Playground</h1>
    <p class="sub">Two devices in one process, paired over a real socket with the real ceremony.
      Type something and watch it become ciphertext on device A, cross a TCP connection, and come
      back out as your words on device B. Every number below came from the library.</p>
  </div>

  <section class="panel">
    <h2>Send something</h2>
    <div class="body">
      <textarea id="text" placeholder="Type anything.">Dentist, Tuesday, 9am</textarea>
      <div class="controls">
        <button class="send" id="send" type="button">Send it through</button>
        <label class="tamper" id="tamperLabel"><input type="checkbox" id="tamper"> Flip a byte in transit</label>
        <span class="hint">device A on 8089, device B on 8090</span>
      </div>
    </div>
  </section>

  <section class="panel">
    <h2>The journey</h2>
    <div id="verdict" class="verdict idle">Nothing sent yet.</div>
    <div id="message"><div class="empty">Type something above and press send.</div></div>
  </section>

  <section class="panel">
    <h2>Algorithms, and where each one works</h2>
    <div id="algorithms"></div>
  </section>

  <section class="panel">
    <h2>How these two devices met</h2>
    <div id="pairing"><div class="empty">Pairing…</div></div>
  </section>

  <footer>The sealed bytes are what <code>Cascade</code> produced and the bytes marked in transit
    are what went down the socket. The pairing below is described by the library's own recorder,
    not by this page. Click any byte string to see all of it.</footer>
</div>

<dialog id="viewer">
  <header><span class="t" id="vname"></span><span class="n" id="vbytes"></span>
    <button id="vclose" type="button">Close</button></header>
  <div class="val" id="vvalue"></div>
</dialog>

<script>
const PQ = /ML-KEM|Kyber|post-quantum/i;
const messageEl = document.getElementById('message');
const pairingEl = document.getElementById('pairing');
const verdictEl = document.getElementById('verdict');
const sendButton = document.getElementById('send');
const tamperBox = document.getElementById('tamper');
const tamperLabel = document.getElementById('tamperLabel');

tamperBox.addEventListener('change', () => tamperLabel.classList.toggle('on', tamperBox.checked));

function escapeHtml(value) {
  const span = document.createElement('span');
  span.textContent = value == null ? '' : value;
  return span.innerHTML;
}

function badges(algorithms) {
  return (algorithms || []).map(a =>
    '<span class="alg' + (PQ.test(a) ? ' pq' : '') + '"><span class="dot"></span>' + escapeHtml(a) + '</span>').join(' ');
}

function partsTable(parts) {
  if (!parts || !parts.length) return '';
  const rows = parts.map(p =>
    '<tr><td class="n">' + escapeHtml(p.name) + '</td><td class="b">' + p.bytes + ' B</td>' +
    '<td class="v">' + escapeHtml(p.value || '') + '</td>' +
    '<td>' + escapeHtml(p.note || '') + '</td></tr>').join('');
  return '<table class="parts"><tr><th>part</th><th>size</th><th>value</th><th></th></tr>' + rows + '</table>';
}

function hexBlock(step) {
  if (!step.hex) return '';
  const preview = step.hex.length > 220 ? step.hex.slice(0, 220) : step.hex;
  const more = step.hex.length > 220 ? '<span class="more"> … show all ' + (step.hex.length / 2) + ' bytes</span>' : '';
  return '<div class="bytes"><button class="hexbtn" data-name="' + escapeHtml(step.title) +
    '" data-bytes="' + (step.hex.length / 2) + ' bytes" data-full="' + step.hex + '">' +
    preview + more + '</button></div>';
}

function render(target, steps, emptyText) {
  if (!steps.length) { target.innerHTML = '<div class="empty">' + emptyText + '</div>'; return; }
  target.innerHTML = steps.map(step =>
    '<div class="step' + (step.failed ? ' failed' : '') + '">' +
      '<div class="who ' + step.side + '">' + step.side + '</div>' +
      '<div class="what">' +
        '<div class="title">' + escapeHtml(step.title) + badges(step.algorithms) + '</div>' +
        '<div class="detail">' + escapeHtml(step.detail) + '</div>' +
        (step.text ? '<div class="plain">' + escapeHtml(step.text) + '</div>' : '') +
        partsTable(step.parts) +
        hexBlock(step) +
      '</div>' +
    '</div>').join('');
}

function renderAlgorithms(uses) {
  document.getElementById('algorithms').innerHTML = uses.map(use =>
    '<div class="step"><div class="what">' +
      '<div class="title"><span class="alg' + (use.pq ? ' pq' : '') + '"><span class="dot"></span>' +
        escapeHtml(use.name) + '</span><span class="usewhen">' + escapeHtml(use['when']) + '</span></div>' +
      '<div class="detail">' + escapeHtml(use.what) + '</div>' +
    '</div></div>').join('');
}

function renderVerdict(data) {
  if (data.verdict === 'delivered') {
    verdictEl.className = 'verdict delivered';
    verdictEl.innerHTML = 'Delivered. Device B read exactly what was typed.' +
      (data.tampered ? ' <span class="small">(and this run was tampered with, which should not have worked: tell somebody)</span>' : '');
  } else if (data.verdict === 'rejected') {
    verdictEl.className = 'verdict rejected';
    verdictEl.innerHTML = 'Rejected. Device B refused the message and returned no plaintext.' +
      (data.tampered
        ? ' <span class="small">This is the expected result: you asked for a byte to be flipped in transit.</span>'
        : ' <span class="small">Nothing was tampered with, so this is a genuine failure worth investigating.</span>');
  } else {
    verdictEl.className = 'verdict idle';
    verdictEl.textContent = 'Nothing sent yet.';
  }
}

async function refresh() {
  const data = await (await fetch('/events')).json();
  renderVerdict(data);
  render(messageEl, data.message, 'Type something above and press send.');
  render(pairingEl, data.pairing, 'Pairing…');
  renderAlgorithms(data.algorithms);
}

sendButton.addEventListener('click', async () => {
  sendButton.disabled = true;
  await fetch('/send', {
    method: 'POST',
    body: 'text=' + encodeURIComponent(document.getElementById('text').value) + '&tamper=' + tamperBox.checked,
  });
  await refresh();
  sendButton.disabled = false;
});

const viewer = document.getElementById('viewer');
document.addEventListener('click', event => {
  const button = event.target.closest('.hexbtn');
  if (!button) return;
  document.getElementById('vname').textContent = button.dataset.name;
  document.getElementById('vbytes').textContent = button.dataset.bytes;
  document.getElementById('vvalue').textContent = button.dataset.full;
  viewer.showModal();
});
document.getElementById('vclose').addEventListener('click', () => viewer.close());

refresh();
setInterval(refresh, 2000);
</script></body></html>
""".trimIndent()
