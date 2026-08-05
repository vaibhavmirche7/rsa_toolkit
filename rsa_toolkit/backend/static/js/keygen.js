// keygen.js — drives /keygen: generation, ledger rendering, exports,
// and the string encrypt/decrypt panels. No server-side state — the
// last generated key just lives in `lastKey` for this page load.

let lastKey = null;

// ---------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------

function el(id) { return document.getElementById(id); }

function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function downloadBlob(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function ledgerRow(idx, label, value) {
  const row = document.createElement("div");
  row.className = "ledger-row";
  row.innerHTML = `
    <span class="ledger-idx">${idx}</span>
    <span class="ledger-label">${label}</span>
    <span class="ledger-value" title="${value}">${value}</span>
    <button class="copy-btn" type="button">copy</button>
  `;
  row.querySelector(".copy-btn").addEventListener("click", (e) => {
    navigator.clipboard.writeText(value).then(() => {
      e.target.textContent = "copied";
      e.target.classList.add("copied");
      setTimeout(() => { e.target.textContent = "copy"; e.target.classList.remove("copied"); }, 1200);
    });
  });
  return row;
}

async function postJSON(url, body) {
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(data.detail || `request failed (${resp.status})`);
  }
  return data;
}

// ---------------------------------------------------------------
// mode hint text
// ---------------------------------------------------------------

const MODE_HINTS = {
  standard: null,
  weak_fermat: "p and q will be generated close together on purpose — the Crack page's Fermat factorization attack will break this almost instantly.",
  weak_wiener: "d (the private exponent) will be generated small on purpose — e is derived from it, so the e field is disabled. Wiener's attack will recover d almost instantly.",
};

el("f-mode").addEventListener("change", () => {
  const mode = el("f-mode").value;
  const hint = el("mode-hint");
  const eWrap = el("f-e-wrap");
  if (MODE_HINTS[mode]) {
    hint.textContent = MODE_HINTS[mode];
    hint.style.display = "block";
  } else {
    hint.style.display = "none";
  }
  eWrap.style.display = mode === "weak_wiener" ? "none" : "flex";
});

// ---------------------------------------------------------------
// generate
// ---------------------------------------------------------------

el("btn-generate").addEventListener("click", async () => {
  const btn = el("btn-generate");
  const bits = parseInt(el("f-bits").value, 10);
  const mode = el("f-mode").value;
  const e = parseInt(el("f-e").value || "65537", 10);

  btn.disabled = true;
  btn.textContent = "Generating…";

  try {
    const data = await postJSON("/api/keygen", { bits, e, mode });
    lastKey = data;
    renderResult(data);
  } catch (err) {
    el("panel-result").classList.remove("hidden");
    el("result-status").innerHTML = `<div class="result-status error">Error: ${err.message}</div>`;
    el("ledger-math").innerHTML = "";
  } finally {
    btn.disabled = false;
    btn.textContent = "Generate keypair";
  }
});

function renderResult(data) {
  el("panel-result").classList.remove("hidden");
  el("panel-strength").classList.remove("hidden");
  el("panel-export").classList.remove("hidden");

  el("result-status").innerHTML = `<div class="result-status success">
    ${data.bits}-bit key generated in ${data.generation_ms}ms — mode: ${data.mode}
  </div>`;

  const ledger = el("ledger-math");
  ledger.innerHTML = "";
  data.math_steps.forEach((step, i) => {
    ledger.appendChild(ledgerRow(i + 1, step.label, step.value));
  });

  el("fingerprint").textContent = data.fingerprint_sha256;

  const notesWrap = el("strength-notes");
  notesWrap.innerHTML = "";
  data.strength.notes.forEach((note) => {
    let cls = "ok";
    if (note.includes("Fermat") && data.strength.fermat_risk) cls = "risk";
    else if (note.includes("Wiener") && data.strength.wiener_risk) cls = "risk";
    else if (note.includes("weak by modern")) cls = "warn";
    const p = document.createElement("div");
    p.className = `strength-note ${cls}`;
    p.textContent = note;
    notesWrap.appendChild(p);
  });

  // auto-offer both public and private keys immediately
  setTimeout(() => triggerExport("private_pkcs1_pem", "private_pkcs1.pem", data), 50);
  setTimeout(() => triggerExport("public_pem", "public.pem", data), 350);
}

function triggerExport(key, fname, data) {
  const value = data.export[key];
  downloadBlob(value, fname, "application/x-pem-file");
}

document.querySelectorAll("[data-export]").forEach((btn) => {
  btn.addEventListener("click", () => {
    if (!lastKey) return;
    const key = btn.dataset.export;
    const fname = btn.dataset.fname;
    const value = lastKey.export[key];
    if (btn.dataset.json) {
      downloadBlob(JSON.stringify(value, null, 2), fname, "application/json");
    } else if (btn.dataset.b64) {
      downloadBlob(b64ToBytes(value), fname, "application/octet-stream");
    } else {
      downloadBlob(value, fname, "application/x-pem-file");
    }
  });
});

// ---------------------------------------------------------------
// key-source toggles (encrypt / decrypt)
// ---------------------------------------------------------------

function wireKeySource(selectId, wraps) {
  const sel = el(selectId);
  sel.addEventListener("change", () => {
    Object.entries(wraps).forEach(([val, id]) => {
      el(id).classList.toggle("hidden", sel.value !== val);
    });
  });
}

wireKeySource("enc-keysource", { pem: "enc-pem-wrap", raw: "enc-raw-wrap" });
wireKeySource("dec-keysource", { pem: "dec-pem-wrap", raw: "dec-raw-wrap" });

// ---------------------------------------------------------------
// encrypt string
// ---------------------------------------------------------------

el("btn-encrypt").addEventListener("click", async () => {
  const btn = el("btn-encrypt");
  const source = el("enc-keysource").value;
  const mode = el("enc-oaep").checked ? "oaep" : "raw";
  const plaintext = el("enc-plaintext").value;
  const body = { plaintext, mode };

  if (source === "generated") {
    if (!lastKey) return showEncError("Generate a key above first, or choose a different key source.");
    body.n = lastKey.n; body.e = lastKey.e;
  } else if (source === "pem") {
    body.pem = el("enc-pem").value;
  } else {
    body.n = el("enc-n").value; body.e = el("enc-e").value;
  }

  btn.disabled = true; btn.textContent = "Encrypting…";
  try {
    const data = await postJSON("/api/encrypt-string", body);
    const ledger = el("ledger-enc-result");
    ledger.innerHTML = "";
    ledger.classList.remove("hidden");
    if (data.ciphertext_b64) ledger.appendChild(ledgerRow("→", "ciphertext (base64)", data.ciphertext_b64));
    ledger.appendChild(ledgerRow("→", "ciphertext (integer)", data.ciphertext_int));
  } catch (err) {
    showEncError(err.message);
  } finally {
    btn.disabled = false; btn.textContent = "Encrypt";
  }
});

function showEncError(msg) {
  const ledger = el("ledger-enc-result");
  ledger.innerHTML = `<div class="result-status error" style="margin:0;">Error: ${msg}</div>`;
  ledger.classList.remove("hidden");
}

// ---------------------------------------------------------------
// decrypt string
// ---------------------------------------------------------------

el("btn-decrypt").addEventListener("click", async () => {
  const btn = el("btn-decrypt");
  const source = el("dec-keysource").value;
  const mode = el("dec-oaep").checked ? "oaep" : "raw";
  const ciphertext = el("dec-ciphertext").value.trim();
  const body = { mode };

  // OAEP ciphertext is normally base64 (that's what /api/encrypt-string
  // returns), but someone might paste the integer form instead — a
  // pure-digit string is treated as the integer, anything else as base64.
  // Raw/textbook mode is always an integer.
  if (mode === "oaep" && !/^\d+$/.test(ciphertext)) {
    body.ciphertext_b64 = ciphertext;
  } else {
    body.ciphertext_int = ciphertext;
  }

  if (source === "generated") {
    if (!lastKey) return showDecError("Generate a key above first, or choose a different key source.");
    body.n = lastKey.n; body.d = lastKey.d; body.p = lastKey.p; body.q = lastKey.q; body.e = lastKey.e;
  } else if (source === "pem") {
    body.pem = el("dec-pem").value;
  } else {
    body.n = el("dec-n").value; body.d = el("dec-d").value;
    body.p = el("dec-p").value; body.q = el("dec-q").value; body.e = el("dec-e").value;
  }

  btn.disabled = true; btn.textContent = "Decrypting…";
  try {
    const data = await postJSON("/api/decrypt-string", body);
    const ledger = el("ledger-dec-result");
    ledger.innerHTML = "";
    ledger.classList.remove("hidden");
    ledger.appendChild(ledgerRow("→", "plaintext", data.plaintext));
  } catch (err) {
    showDecError(err.message);
  } finally {
    btn.disabled = false; btn.textContent = "Decrypt";
  }
});

function showDecError(msg) {
  const ledger = el("ledger-dec-result");
  ledger.innerHTML = `<div class="result-status error" style="margin:0;">Error: ${msg}</div>`;
  ledger.classList.remove("hidden");
}
