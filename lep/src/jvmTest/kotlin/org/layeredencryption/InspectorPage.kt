package org.layeredencryption

/**
 * Turns a recorded ceremony into a single self-contained HTML file.
 *
 * The data is the recording; the page is a renderer over it. Nothing here invents a value, which
 * is the whole difference between this and a mockup: if the protocol changes, the page changes,
 * and if the protocol breaks, the page shows the break.
 */
object InspectorPage {

    /** The recording as JSON, which is also what a second implementation would be checked against. */
    fun json(recorder: Any, sas: String): String {
        val collector = recorder as? HasMessages ?: return "{}"
        val steps = collector.recordedMessages().joinToString(",\n") { step ->
            val fields = step.fields.joinToString(",") { field ->
                """{"name":${q(field.name)},"bytes":${field.bytes},"value":${q(field.value)},""" +
                    """"algorithm":${q(field.algorithm)},"note":${q(field.note)}}"""
            }
            """    {"name":${q(step.name)},"tag":${step.tag},"from":${q(step.from)},""" +
                """"size":${step.sizeBytes},"algorithms":[${step.algorithms.joinToString(",") { q(it) }}],""" +
                """"establishes":${q(step.establishes)},"fields":[$fields]}"""
        }
        return "{\n  \"sas\": ${q(sas)},\n  \"messages\": [\n$steps\n  ]\n}"
    }

    fun render(recorder: Any, sas: String): String = TEMPLATE.replace("/*RECORDING*/", json(recorder, sas))

    /** Structural typing rather than a dependency: the test's collector satisfies this. */
    interface HasMessages {
        fun recordedMessages(): List<RecordedMessage>
    }

    private fun q(value: String?): String =
        if (value == null) "null" else "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ") + "\""

    private val TEMPLATE = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ceremony Inspector</title>
<style>
  :root{--paper:#f7f7f4;--panel:#fff;--rule:#dcdcd4;--soft:#f0f0ea;--text:#12161f;--muted:#5f6672;
    --faint:#9aa1ac;--accent:#3b3f8f;--accentSoft:#3b3f8f14;--pass:#2f6b45;--passSoft:#2f6b4514;
    --pq:#7a2f6b;--pqSoft:#7a2f6b14;--cls:#1f5f6b;--clsSoft:#1f5f6b14;
    --mono:ui-monospace,'SF Mono',Menlo,Consolas,monospace;
    --sans:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;}
  @media (prefers-color-scheme:dark){:root{--paper:#0e1117;--panel:#161a22;--rule:#272d38;--soft:#1b2029;
    --text:#e8e9ec;--muted:#9aa3b2;--faint:#69727f;--accent:#9ba4ff;--accentSoft:#9ba4ff18;
    --pass:#7fc79a;--passSoft:#7fc79a18;--pq:#d79ad0;--pqSoft:#d79ad018;--cls:#77c6d4;--clsSoft:#77c6d418;}}
  *{box-sizing:border-box}
  body{margin:0;background:var(--paper);color:var(--text);font-family:var(--sans);font-size:15px;
    line-height:1.55;padding:34px 20px 70px}
  .wrap{max-width:1000px;margin:0 auto;display:flex;flex-direction:column;gap:22px}
  h1{font-size:23px;margin:0;font-weight:650}
  .sub{color:var(--muted);font-size:13.5px;max-width:72ch;margin:0}
  .meta{display:flex;flex-wrap:wrap;gap:8px 18px;font-family:var(--mono);font-size:12px;color:var(--muted)}
  .meta b{color:var(--text)}
  .pill{font-size:12px;font-weight:600;border-radius:999px;padding:4px 12px;border:1px solid var(--pass);
    color:var(--pass);background:var(--passSoft)}
  .panel{background:var(--panel);border:1px solid var(--rule);border-radius:12px;overflow:hidden}
  .panel h2{margin:0;padding:12px 18px;font-size:12px;font-weight:700;letter-spacing:.1em;
    text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--rule)}
  .step{border-bottom:1px solid var(--rule)}
  .step:last-child{border-bottom:none}
  .head{display:flex;align-items:center;gap:10px;padding:12px 18px;flex-wrap:wrap}
  .num{width:24px;height:24px;border-radius:7px;background:var(--accentSoft);color:var(--accent);
    font-family:var(--mono);font-size:12px;font-weight:700;display:flex;align-items:center;justify-content:center;flex:none}
  .dir{font-family:var(--mono);font-size:12px;color:var(--muted)}
  .dir b{color:var(--accent)}
  .msg{font-family:var(--mono);font-size:13px;font-weight:600}
  .tag{font-family:var(--mono);font-size:11px;color:var(--faint);border:1px solid var(--rule);
    border-radius:5px;padding:0 6px}
  .size{margin-left:auto;font-family:var(--mono);font-size:12px;color:var(--muted)}
  .alg{display:inline-flex;align-items:center;gap:5px;font-family:var(--mono);font-size:11px;font-weight:600;
    border-radius:6px;padding:1px 7px;border:1px solid var(--cls);color:var(--cls);background:var(--clsSoft)}
  .alg.pq{border-color:var(--pq);color:var(--pq);background:var(--pqSoft)}
  .alg .dot{width:5px;height:5px;border-radius:50%;background:currentColor}
  .body{padding:0 18px 15px 52px}
  table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:12px}
  th{text-align:left;font-family:var(--sans);font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;
    color:var(--faint);padding:0 12px 6px 0}
  td{padding:3px 12px 3px 0;color:var(--muted);vertical-align:top}
  td.name{color:var(--text);white-space:nowrap}
  .hex{font-family:var(--mono);font-size:12px;color:var(--accent);background:var(--accentSoft);
    border:1px solid transparent;border-radius:5px;padding:0 6px;cursor:pointer}
  .hex:hover{border-color:var(--accent)}
  .hex:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
  .establishes{margin-top:10px;font-size:12.5px;color:var(--muted);border-left:2px solid var(--rule);padding-left:12px}
  .establishes b{color:var(--text)}
  dialog{border:1px solid var(--rule);border-radius:12px;background:var(--panel);color:var(--text);
    padding:0;max-width:min(620px,92vw);width:100%}
  dialog::backdrop{background:rgba(8,10,14,.55)}
  dialog header{display:flex;gap:10px;align-items:baseline;padding:13px 17px;border-bottom:1px solid var(--rule)}
  dialog .t{font-family:var(--mono);font-size:13px;font-weight:650}
  dialog .n{font-family:var(--mono);font-size:11.5px;color:var(--muted)}
  dialog button{margin-left:auto;background:none;border:1px solid var(--rule);border-radius:7px;
    color:var(--muted);font:inherit;font-size:12px;padding:3px 10px;cursor:pointer}
  dialog .val{padding:15px 17px;font-family:var(--mono);font-size:12.5px;word-break:break-all}
  dialog .note{padding:0 17px 15px;font-size:12.5px;color:var(--muted)}
  footer{color:var(--faint);font-size:12.5px;max-width:74ch}
</style></head><body>
<div class="wrap">
  <div>
    <h1>Ceremony Inspector</h1>
    <p class="sub">Generated by running the library. Every value below came off the wire during a
      real pairing; nothing here is illustrative. Click a digest to see the field it summarises.</p>
  </div>
  <div class="meta" id="meta"></div>
  <div><span class="pill" id="verdict">recorded</span></div>
  <section class="panel"><h2>The ceremony</h2><div id="steps"></div></section>
  <footer>Regenerate with <code>./gradlew :lep:jvmTest</code>. The same run asserts that no key
    material appears in this file, so if you can read a private key here, a test is broken.</footer>
</div>
<dialog id="viewer">
  <header><span class="t" id="vname"></span><span class="n" id="vbytes"></span>
    <button id="vclose" type="button">Close</button></header>
  <div class="val" id="vvalue"></div><div class="note" id="vnote"></div>
</dialog>
<script>
const recording = /*RECORDING*/;
const PQ = /ML-KEM|Kyber|post-quantum/i;
const steps = document.getElementById('steps');
document.getElementById('meta').innerHTML =
  '<span><b>messages</b> ' + recording.messages.length + '</span>' +
  '<span><b>bytes exchanged</b> ' + recording.messages.reduce((n, m) => n + m.size, 0) + '</span>' +
  '<span><b>SAS shown</b> ' + recording.sas + '</span>';

recording.messages.forEach((message, index) => {
  const algs = message.algorithms.map(a =>
    '<span class="alg' + (PQ.test(a) ? ' pq' : '') + '"><span class="dot"></span>' + a + '</span>').join(' ');
  const rows = message.fields.map(f =>
    '<tr><td class="name">' + f.name + '</td><td>' + f.bytes + '</td>' +
    '<td>' + (f.algorithm ? '<span class="alg' + (PQ.test(f.algorithm) ? ' pq' : '') +
      '"><span class="dot"></span>' + f.algorithm + '</span>' : '') + '</td>' +
    '<td><button class="hex" data-name="' + f.name + '" data-bytes="' + f.bytes + ' bytes" ' +
    'data-value="' + f.value + '" data-note="' + (f.note || '') + '">' + f.value + '</button></td></tr>').join('');
  const table = message.fields.length
    ? '<table><tr><th>field</th><th>bytes</th><th>algorithm</th><th>digest</th></tr>' + rows + '</table>' : '';
  steps.insertAdjacentHTML('beforeend',
    '<div class="step"><div class="head"><span class="num">' + (index + 1) + '</span>' +
    '<span class="dir">' + message.from + ' <b>sends</b></span>' +
    '<span class="msg">' + message.name + '</span><span class="tag">tag ' + message.tag + '</span>' +
    algs + '<span class="size">' + message.size + ' B</span></div>' +
    '<div class="body">' + table +
    (message.establishes ? '<div class="establishes"><b>Established:</b> ' + message.establishes + '</div>' : '') +
    '</div></div>');
});

const viewer = document.getElementById('viewer');
document.addEventListener('click', event => {
  const button = event.target.closest('.hex');
  if (!button) return;
  document.getElementById('vname').textContent = button.dataset.name;
  document.getElementById('vbytes').textContent = button.dataset.bytes;
  document.getElementById('vvalue').textContent = button.dataset.value;
  document.getElementById('vnote').textContent = button.dataset.note;
  viewer.showModal();
});
document.getElementById('vclose').addEventListener('click', () => viewer.close());
</script></body></html>
""".trimIndent()
}
