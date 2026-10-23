const vscode = acquireVsCodeApi();
const app = document.getElementById("app");

window.addEventListener("message", (event) => {
  const message = event.data;
  if (message.cmd === "error") {
    app.innerHTML = `<div class="error">${esc(message.message)}</div>`;
    return;
  }
  if (message.cmd === "dex") renderDex(message);
  if (message.cmd === "dexList") paintDexClasses(message);
  if (message.cmd === "dexClass") renderDexClass(message.detail);
  if (message.cmd === "dexMethod") renderDexMethod(message.code);
  if (message.cmd === "dexStrings") renderDexStrings(message.strings);
  if (message.cmd === "elf") renderElf(message);
  if (message.cmd === "elfSymbols") renderElfSymbols(message);
  if (message.cmd === "riv") renderRiv(message);
  if (message.cmd === "jar") renderJar(message);
  if (message.cmd === "jarList") paintJar(message);
  if (message.cmd === "pkcs") renderPkcs(message);
});

vscode.postMessage({ cmd: "ready" });

let dexState = null;
let elfState = null;

function renderDex(message) {
  dexState = { ...message, selected: -1, tab: "classes" };
  app.innerHTML = `
    <div class="shell">
      <aside class="side" id="side"></aside>
      <section class="main">
        <div class="tabs">
          <button type="button" data-tab="classes" aria-pressed="true">Classes</button>
          <button type="button" data-tab="strings" aria-pressed="false">Strings</button>
          <button type="button" data-tab="hex" aria-pressed="false">Hex</button>
        </div>
        <div class="toolbar" id="toolbar"><input id="q" type="search" placeholder="Filter classes"></div>
        <div class="list" id="list"></div>
        <div class="detail" id="detail"></div>
      </section>
    </div>`;
  document.getElementById("side").innerHTML = dexSide(message);
  document.querySelectorAll(".tabs button").forEach((button) => {
    button.addEventListener("click", () => setDexTab(button.dataset.tab));
  });
  document.getElementById("q").addEventListener("input", (event) => {
    const query = event.target.value;
    later(() => {
      if (dexState.tab === "strings") vscode.postMessage({ cmd: "dexStrings", query });
      else vscode.postMessage({ cmd: "dexList", query });
    });
  });
  if (message.page) paintDexClasses(message.page);
}

function dexSide(message) {
  const header = message.header;
  return `
    <h1>${esc(message.name)}</h1>
    <div class="stat"><span>Version</span><b>${esc(header.version)}</b></div>
    <div class="stat"><span>Classes</span><b>${header.classCount}</b></div>
    <div class="stat"><span>Methods</span><b>${header.methodCount}</b></div>
    <div class="stat"><span>Fields</span><b>${header.fieldCount}</b></div>
    <div class="stat"><span>Strings</span><b>${header.stringCount}</b></div>
    <div class="stat"><span>Checksum</span><b>${header.checksumOk ? "matches" : "mismatch"}</b></div>
    <div class="stat"><span>SHA-1</span><b>${header.signatureOk ? "matches" : "mismatch"}</b></div>
    <p class="muted">Parsed in ${message.elapsedMs} ms. ${header.fileSize.toLocaleString()} bytes.</p>`;
}

function setDexTab(tab) {
  dexState.tab = tab;
  document.querySelectorAll(".tabs button").forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset.tab === tab));
  });
  const input = document.getElementById("q");
  input.placeholder = tab === "strings" ? "Search the string pool" : "Filter classes";
  document.getElementById("detail").innerHTML = "";
  if (tab === "hex") {
    document.getElementById("list").innerHTML = `<pre>${dexState.hex.map(esc).join("\n")}</pre>`;
  } else if (tab === "strings") {
    vscode.postMessage({ cmd: "dexStrings", query: input.value });
  } else vscode.postMessage({ cmd: "dexList", query: input.value });
}

function paintDexClasses(message) {
  const list = document.getElementById("list");
  if (!list || !dexState || dexState.tab !== "classes") return;
  const shown = message.classes;
  list.innerHTML = shown.map((item) => `<div class="row" data-index="${item.index}"><span>${esc(item.name)}</span><small>${esc(item.access)}</small></div>`).join("")
    + `<p class="muted" style="padding:8px 10px">Showing ${message.shown} of ${message.total} matching classes.</p>`;
  list.querySelectorAll(".row").forEach((row) => {
    row.addEventListener("click", () => {
      list.querySelectorAll(".row").forEach((item) => item.classList.remove("active"));
      row.classList.add("active");
      vscode.postMessage({ cmd: "dexClass", index: Number(row.dataset.index) });
    });
  });
}

function renderDexClass(detail) {
  const detailNode = document.getElementById("detail");
  const methods = detail.methods.map((method, index) => `<div class="row" data-method="${index}"><span class="mono">${esc(method.name)}${esc(method.descriptor)}</span><small>${esc(method.access)}</small></div>`).join("");
  const fields = detail.fields.map((field) => `<div class="row"><span class="mono">${esc(field.name)}: ${esc(field.descriptor)}</span><small>${esc(field.access)}</small></div>`).join("");
  detailNode.innerHTML = `
    <h2>${esc(detail.summary.name)}</h2>
    <p class="sub">${esc(detail.summary.access)} extends ${esc(detail.summary.superClass || "—")}${detail.interfaces.length ? ` implements ${esc(detail.interfaces.join(", "))}` : ""}</p>
    <p class="sub">${esc(detail.summary.jniName)}${detail.summary.sourceFile ? ` · ${esc(detail.summary.sourceFile)}` : ""}</p>
    <h2>Fields</h2>${fields || `<p class="muted">No fields</p>`}
    <h2>Methods</h2>${methods || `<p class="muted">No methods</p>`}
    <div id="code"></div>`;
  detailNode.querySelectorAll("[data-method]").forEach((row) => {
    row.addEventListener("click", () => vscode.postMessage({ cmd: "dexMethod", index: detail.summary.index, method: Number(row.dataset.method) }));
  });
}

function renderDexMethod(code) {
  const node = document.getElementById("code");
  if (!node) return;
  const body = code.lines.length
    ? code.lines.map((line) => `<div class="insn"><span class="addr">${line.address.toString(16).padStart(4, "0")}</span><span>${formatInsn(line.text)}</span></div>`).join("")
    : `<p class="muted">This method has no bytecode.</p>`;
  node.innerHTML = `<h2>Bytecode</h2><p class="mono">${esc(code.header)}</p><pre>${body}</pre>`;
}

function renderDexStrings(strings) {
  document.getElementById("list").innerHTML = strings.map((value) => `<div class="row"><span class="mono">${esc(value)}</span></div>`).join("")
    || `<p class="muted" style="padding:8px 10px">No strings matched.</p>`;
  document.getElementById("detail").innerHTML = `<p class="muted">${strings.length} shown. Search is capped at 200 matches.</p>`;
}

function renderElf(message) {
  elfState = message;
  const file = message.file;
  app.innerHTML = `
    <div class="shell">
      <aside class="side">
        <h1>${esc(message.name)}</h1>
        ${stat("Class", file.summary.class)}
        ${stat("Machine", file.summary.machine)}
        ${stat("Type", file.summary.type)}
        ${stat("Endian", file.summary.encoding)}
        ${stat("OS ABI", file.summary.osAbi)}
        ${stat("Entry", file.summary.entry)}
        ${stat("SONAME", file.summary.soname || "—")}
        ${stat("Sections", file.summary.sectionCount)}
        ${stat("Symbols loaded", file.summary.symbolCount)}
        <h2>Needed</h2>
        ${file.needed.map((name) => `<div class="mono">${esc(name)}</div>`).join("") || `<p class="muted">None</p>`}
        ${file.notes.map((note) => `<p class="muted">${esc(note)}</p>`).join("")}
        <p class="muted">Parsed in ${message.elapsedMs} ms. ${file.summary.fileSize.toLocaleString()} bytes.</p>
      </aside>
      <section class="main">
        <div class="tabs">
          <button type="button" data-tab="symbols" aria-pressed="true">Symbols</button>
          <button type="button" data-tab="sections" aria-pressed="false">Sections</button>
          <button type="button" data-tab="segments" aria-pressed="false">Segments</button>
          <button type="button" data-tab="strings" aria-pressed="false">Strings</button>
          <button type="button" data-tab="hex" aria-pressed="false">Hex</button>
        </div>
        <div class="toolbar"><input id="q" type="search" placeholder="Filter symbols"></div>
        <div class="list" id="list"></div>
      </section>
    </div>`;
  document.querySelectorAll(".tabs button").forEach((button) => button.addEventListener("click", () => setElfTab(button.dataset.tab)));
  document.getElementById("q").addEventListener("input", (event) => {
    const query = event.target.value;
    later(() => {
      if (document.querySelector('[data-tab="symbols"]').getAttribute("aria-pressed") === "true") {
        vscode.postMessage({ cmd: "elfFilter", query });
      }
    });
  });
  if (message.symbols) renderElfSymbols({ symbols: message.symbols, shown: message.symbols.length, total: message.symbolTotal });
}

function setElfTab(tab) {
  document.querySelectorAll(".tabs button").forEach((button) => button.setAttribute("aria-pressed", String(button.dataset.tab === tab)));
  const file = elfState.file;
  const list = document.getElementById("list");
  if (tab === "sections") list.innerHTML = table(["#", "Name", "Type", "Flags", "Address", "Offset", "Size"], file.sections.map((section) => [section.index, section.name, section.type, section.flags, section.address, `0x${section.offset.toString(16)}`, section.size]));
  else if (tab === "segments") list.innerHTML = table(["Type", "Flags", "Address", "Offset", "File", "Memory"], file.programHeaders.map((header) => [header.type, header.flags, header.address, `0x${header.offset.toString(16)}`, header.fileSize, header.memorySize]));
  else if (tab === "strings") list.innerHTML = file.strings.map((value) => `<div class="row"><span class="mono">${esc(value)}</span></div>`).join("");
  else if (tab === "hex") list.innerHTML = `<pre>${elfState.hex.map(esc).join("\n")}</pre>`;
  else vscode.postMessage({ cmd: "elfFilter", query: document.getElementById("q").value });
}

function renderElfSymbols(message) {
  const list = document.getElementById("list");
  if (!list || document.querySelector('[data-tab="symbols"]').getAttribute("aria-pressed") !== "true") return;
  const head = `<div class="sym"><b>Name</b><b>Bind</b><b>Type</b><b>Section</b><b>Value</b><b>Size</b></div>`;
  list.innerHTML = head + message.symbols.map((symbol) => `<div class="sym"><span class="mono">${esc(symbol.name)}</span><span>${esc(symbol.bind)}</span><span>${esc(symbol.type)}</span><span>${esc(symbol.section)}</span><span class="mono">${esc(symbol.value)}</span><span>${symbol.size}</span></div>`).join("")
    + `<p class="muted" style="padding:8px 10px">Showing ${message.shown} of ${message.total} loaded symbols.</p>`;
}

function renderRiv(message) {
  app.innerHTML = `
    <div class="stage">
      <aside class="side">
        <h1>${esc(message.name)}</h1>
        ${stat("Header", message.info.valid ? "RIVE" : "invalid")}
        ${stat("Version", message.info.version || "—")}
        ${stat("File id", message.info.fileId ? message.info.fileId.slice(0, 16) : "—")}
        <p class="muted">${esc(message.info.note)}</p>
        <h2>Names in the file</h2>
        <div class="chips">${message.info.strings.map((name) => `<span class="chip">${esc(name)}</span>`).join("") || `<span class="muted">None</span>`}</div>
        <h2>First bytes</h2>
        <pre>${message.hex.map(esc).join("\n")}</pre>
      </aside>
      <section class="player">
        <div class="toolbar">
          <button class="primary" id="play" type="button">Play</button>
          <button id="pause" type="button">Pause</button>
          <select id="animation"></select>
          <select id="machine"></select>
        </div>
        <canvas id="canvas" width="960" height="540"></canvas>
        <p id="status" class="muted">Loading the Rive runtime…</p>
      </section>
    </div>`;
  const status = document.getElementById("status");
  if (!message.info.valid) {
    status.textContent = message.info.note;
    return;
  }
  if (message.truncated || !message.bytes) {
    status.textContent = "This .riv file is larger than 2 MB, so only the header and names are shown.";
    return;
  }
  status.textContent = "Loading the animation runtime…";
  loadScript(message.riveUrl).then(() => {
    if (window.rive?.RuntimeLoader && message.wasmUrl) window.rive.RuntimeLoader.setWasmUrl(message.wasmUrl);
    startRive(message.bytes);
  }).catch(() => {
    status.textContent = "The animation runtime did not load. Names from the file are still listed.";
  });
}

function loadScript(src) {
  if (window.rive) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = src;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("script"));
    document.body.appendChild(script);
  });
}

function startRive(base64) {
  const status = document.getElementById("status");
  if (!window.rive || !window.rive.Rive) {
    status.textContent = "The Rive runtime did not load. Header names are still listed on the left.";
    return;
  }
  const binary = Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
  const canvas = document.getElementById("canvas");
  const animation = document.getElementById("animation");
  const machine = document.getElementById("machine");
  let current;
  const boot = (options) => {
    if (current) current.cleanup();
    current = new window.rive.Rive({
      buffer: binary.buffer,
      canvas,
      autoplay: true,
      enableRiveAssetCDN: false,
      ...options,
      onLoad: () => {
        current.resizeDrawingSurfaceToCanvas();
        fillSelect(animation, current.animationNames || [], "Animation");
        fillSelect(machine, current.stateMachineNames || [], "State machine");
        status.textContent = `${(current.animationNames || []).length} animations, ${(current.stateMachineNames || []).length} state machines.`;
      },
      onLoadError: () => { status.textContent = "Rive could not play this file. The names on the left still come from the file bytes."; },
    });
  };
  boot({});
  animation.addEventListener("change", () => { if (animation.value) boot({ animations: animation.value }); });
  machine.addEventListener("change", () => { if (machine.value) boot({ stateMachines: machine.value }); });
  document.getElementById("play").addEventListener("click", () => current && current.play());
  document.getElementById("pause").addEventListener("click", () => current && current.pause());
}

function fillSelect(select, names, label) {
  if (select.options.length > 0) return;
  select.innerHTML = `<option value="">${esc(label)}</option>` + names.map((name) => `<option value="${esc(name)}">${esc(name)}</option>`).join("");
}

let jarState = null;

function renderJar(message) {
  jarState = message;
  const manifest = message.manifest;
  app.innerHTML = `
    <div class="shell">
      <aside class="side">
        <h1>${esc(message.name)}</h1>
        ${stat("Kind", manifest.label)}
        ${stat("Entries", manifest.entryCount)}
        <h2>Main attributes</h2>
        ${manifest.main.map((item) => `<div class="stat"><span>${esc(item.key)}</span></div><div class="mono">${esc(item.value)}</div>`).join("")}
        <p class="muted">Parsed in ${message.elapsedMs} ms.</p>
      </aside>
      <section class="main">
        <div class="tabs">
          <button type="button" data-tab="entries" aria-pressed="true">Entries</button>
          <button type="button" data-tab="hex" aria-pressed="false">Hex</button>
        </div>
        <div class="toolbar"><input id="q" type="search" placeholder="Filter entry names"></div>
        <div class="list" id="list"></div>
      </section>
    </div>`;
  document.querySelectorAll(".tabs button").forEach((button) => button.addEventListener("click", () => {
    document.querySelectorAll(".tabs button").forEach((item) => item.setAttribute("aria-pressed", String(item === button)));
    if (button.dataset.tab === "hex") document.getElementById("list").innerHTML = `<pre>${jarState.hex.map(esc).join("\n")}</pre>`;
    else vscode.postMessage({ cmd: "jarList", query: document.getElementById("q").value });
  }));
  document.getElementById("q").addEventListener("input", (event) => {
    const query = event.target.value;
    later(() => vscode.postMessage({ cmd: "jarList", query }));
  });
  if (message.page) paintJar(message.page);
}

function paintJar(message) {
  const list = document.getElementById("list");
  const entriesTab = document.querySelector('[data-tab="entries"]');
  if (!list || entriesTab?.getAttribute("aria-pressed") !== "true") return;
  list.innerHTML = message.entries.map((entry) => `
    <div class="row"><span class="mono">${esc(entry.name)}</span><small>${esc(entry.digests.map((digest) => digest.key.replace(/-Digest$/, "")).join(", "))}</small></div>
    <div class="sub" style="padding:0 10px 8px">${entry.digests.map((digest) => `<div class="mono">${esc(digest.key)}: ${esc(digest.value)}</div>`).join("")}</div>
  `).join("") + `<p class="muted" style="padding:8px 10px">Showing ${message.shown} of ${message.total} entries.</p>`;
}

let pendingTimer = 0;
function later(work) {
  clearTimeout(pendingTimer);
  pendingTimer = setTimeout(work, 60);
}

function renderPkcs(message) {
  const block = message.block;
  const certificates = block.certificates.map((certificate, index) => `
    <h2>Certificate ${index + 1}</h2>
    ${stat("Subject", certificate.subject)}
    ${stat("Issuer", certificate.issuer)}
    ${stat("Serial", certificate.serial)}
    ${stat("Valid from", certificate.validFrom)}
    ${stat("Valid to", certificate.validTo)}
    ${stat("Public key", certificate.publicKey)}
    ${stat("Self-signed", certificate.selfSigned ? "yes" : "no")}
    <div class="mono">SHA-256 ${esc(certificate.fingerprint256)}</div>
    <div class="mono">SHA-1 ${esc(certificate.fingerprint)}</div>
  `).join("");
  const signers = block.signers.map((signer, index) => `
    <h2>Signer ${index + 1}</h2>
    ${stat("Version", signer.version)}
    ${stat("Digest", signer.digestAlgorithm)}
    ${stat("Signature", signer.signatureAlgorithm)}
    ${stat("Signature bytes", signer.signatureBytes)}
    ${signer.attributes.map((item) => `<div class="stat"><span>${esc(item.key)}</span></div><div class="mono">${esc(item.value)}</div>`).join("")}
  `).join("");
  app.innerHTML = `
    <div class="shell">
      <aside class="side">
        <h1>${esc(message.name)}</h1>
        ${stat("Kind", block.label)}
        ${stat("Content", block.contentType)}
        ${stat("Digests", block.digestAlgorithms.join(", ") || "—")}
        ${stat("Certificates", block.certificates.length)}
        ${stat("Signers", block.signers.length)}
        ${block.notes.map((note) => `<p class="muted">${esc(note)}</p>`).join("")}
        <p class="muted">Parsed in ${message.elapsedMs} ms.</p>
      </aside>
      <section class="main">
        <div class="tabs">
          <button type="button" data-tab="cert" aria-pressed="true">Certificates</button>
          <button type="button" data-tab="hex" aria-pressed="false">Hex</button>
        </div>
        <div class="detail" id="detail">${certificates}${signers || `<p class="muted">No signer info.</p>`}</div>
      </section>
    </div>`;
  const detail = document.getElementById("detail");
  const certHtml = detail.innerHTML;
  document.querySelectorAll(".tabs button").forEach((button) => button.addEventListener("click", () => {
    document.querySelectorAll(".tabs button").forEach((item) => item.setAttribute("aria-pressed", String(item === button)));
    detail.innerHTML = button.dataset.tab === "hex" ? `<pre>${message.hex.map(esc).join("\n")}</pre>` : certHtml;
  }));
}

function stat(label, value) {
  return `<div class="stat"><span>${esc(label)}</span><b>${esc(String(value))}</b></div>`;
}

function table(headers, rows) {
  return `<table><thead><tr>${headers.map((header) => `<th>${esc(header)}</th>`).join("")}</tr></thead><tbody>${rows.map((row) => `<tr>${row.map((cell) => `<td class="mono">${esc(String(cell))}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
}

function formatInsn(text) {
  const split = text.split("  // ");
  if (split.length === 1) return esc(text);
  return `${esc(split[0])}  <span class="comment">// ${esc(split.slice(1).join("  // "))}</span>`;
}

function esc(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[char]));
}
