// crack.js — drives /crack: PEM vs manual field entry, a flexible
// challenge-file parser, PEM-paste auto-detection, a live "here's
// what I'll do" preview, and rendering the analyze/crack result.

function el(id) { return document.getElementById(id); }

function ledgerRow(idx, label, value) {
  const row = document.createElement("div");
  row.className = "ledger-row";
  row.innerHTML = `
    <span class="ledger-idx">${idx}</span>
    <span class="ledger-label">${label}</span>
    <span class="ledger-value" title="${value}">${value}</span>
    <button class="copy-btn" type="button">copy</button>
  `;
  row.querySelector(".copy-btn").addEventListener("click", (ev) => {
    navigator.clipboard.writeText(value).then(() => {
      ev.target.textContent = "copied";
      ev.target.classList.add("copied");
      setTimeout(() => { ev.target.textContent = "copy"; ev.target.classList.remove("copied"); }, 1200);
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
  if (!resp.ok) throw new Error(data.detail || `request failed (${resp.status})`);
  return data;
}

// ---------------------------------------------------------------
// input method toggle
// ---------------------------------------------------------------

el("input-method").addEventListener("change", () => {
  const pemMode = el("input-method").value === "pem";
  el("pem-wrap").classList.toggle("hidden", !pemMode);
  el("manual-wrap").classList.toggle("hidden", pemMode);
  updatePlanPreview();
});

// ---------------------------------------------------------------
// PEM-paste auto-detect on manual fields
// ---------------------------------------------------------------

document.querySelectorAll("[data-manual-field]").forEach((input) => {
  input.addEventListener("paste", (ev) => {
    const text = (ev.clipboardData || window.clipboardData).getData("text");
    if (text && text.includes("-----BEGIN")) {
      ev.preventDefault();
      el("input-method").value = "pem";
      el("pem-wrap").classList.remove("hidden");
      el("manual-wrap").classList.add("hidden");
      el("f-pem").value = text;
      updatePlanPreview();
    }
  });
});

// ---------------------------------------------------------------
// PEM file upload
// ---------------------------------------------------------------

el("f-pem-file").addEventListener("change", async (ev) => {
  const file = ev.target.files[0];
  if (!file) return;
  const text = await file.text();
  el("f-pem").value = text;
  updatePlanPreview();
});

// ---------------------------------------------------------------
// challenge file — flexible key=value / key: value parser
// ---------------------------------------------------------------

el("f-challenge").addEventListener("change", async (ev) => {
  const file = ev.target.files[0];
  if (!file) return;
  const text = await file.text();

  if (text.includes("-----BEGIN")) {
    el("input-method").value = "pem";
    el("pem-wrap").classList.remove("hidden");
    el("manual-wrap").classList.add("hidden");
    el("f-pem").value = text;
    updatePlanPreview();
    return;
  }

  const fieldMap = { n: "f-n", e: "f-e", d: "f-d", p: "f-p", q: "f-q" };
  const cRe = /\b(c|ct|ciphertext|cipher_text|enc)\s*[:=]\s*(0x[0-9a-fA-F]+|[0-9]+|[A-Za-z0-9+/=]{8,})/i;
  const cMatch = text.match(cRe);
  if (cMatch) el("f-ciphertext").value = cMatch[2];

  for (const [key, fieldId] of Object.entries(fieldMap)) {
    const re = new RegExp(`\\b${key}\\s*[:=]\\s*(0x[0-9a-fA-F]+|[0-9]+)`, "i");
    const m = text.match(re);
    if (m) el(fieldId).value = m[1];
  }
  updatePlanPreview();
});

// ---------------------------------------------------------------
// live "what will happen" preview
// ---------------------------------------------------------------

function currentManualFields() {
  return {
    n: el("f-n").value.trim(), e: el("f-e").value.trim(), d: el("f-d").value.trim(),
    p: el("f-p").value.trim(), q: el("f-q").value.trim(),
  };
}

function updatePlanPreview() {
  const preview = el("plan-preview");
  const pemMode = el("input-method").value === "pem";
  const hasCiphertext = el("f-ciphertext").value.trim().length > 0;

  if (pemMode) {
    preview.textContent = el("f-pem").value.trim()
      ? (hasCiphertext ? "PEM loaded — will decrypt directly if it's a private key, or run the attack chain if it's public."
                        : "PEM loaded — will show the key material (no ciphertext given to decrypt).")
      : "Paste a PEM above to continue.";
    return;
  }

  const f = currentManualFields();
  if (f.d && f.n) {
    preview.textContent = hasCiphertext
      ? "You've given n and d — will decrypt directly, no attacks needed."
      : "You've given n and d — nothing else to derive without a ciphertext.";
  } else if (f.p && f.q) {
    preview.textContent = f.e
      ? "You've given p, q, e — will derive n, φ(n), and d."
      : "You've given p and q — will derive n. Add e to also derive d.";
  } else if (f.n && f.e) {
    preview.textContent = hasCiphertext
      ? "You've given n, e, and a ciphertext — will run the attack chain (Wiener → Fermat → factordb → general factoring) and decrypt if it succeeds."
      : "You've given n and e — will run the attack chain to try to recover d (add a ciphertext to also decrypt on success).";
  } else {
    preview.textContent = "Fill in a PEM, p+q, or n+e to get started.";
  }
}

["f-n", "f-e", "f-d", "f-p", "f-q", "f-ciphertext", "f-pem"].forEach((id) => {
  el(id).addEventListener("input", updatePlanPreview);
});
updatePlanPreview();

// ---------------------------------------------------------------
// analyze / crack
// ---------------------------------------------------------------

el("btn-crack").addEventListener("click", async () => {
  const btn = el("btn-crack");
  const pemMode = el("input-method").value === "pem";
  const body = { ciphertext: el("f-ciphertext").value.trim() || null };

  if (pemMode) {
    body.pem = el("f-pem").value.trim() || null;
  } else {
    const f = currentManualFields();
    body.n = f.n || null; body.e = f.e || null; body.d = f.d || null;
    body.p = f.p || null; body.q = f.q || null;
  }

  btn.disabled = true; btn.textContent = "Analyzing…";
  try {
    const data = await postJSON("/api/crack", body);
    renderCrackResult(data);
  } catch (err) {
    el("panel-crack-result").classList.remove("hidden");
    el("crack-status").innerHTML = `<div class="result-status error">Error: ${err.message}</div>`;
    el("ledger-crack-math").innerHTML = "";
    el("plaintext-wrap").classList.add("hidden");
    el("panel-attack-log").classList.add("hidden");
  } finally {
    btn.disabled = false; btn.textContent = "Analyze / Crack";
  }
});

function renderCrackResult(data) {
  el("panel-crack-result").classList.remove("hidden");

  const statusClass = data.status === "decrypted" ? "success"
    : data.status === "attack_failed" ? "error" : "success";
  el("crack-status").innerHTML = `<div class="result-status ${statusClass}">${data.message}</div>`;

  const ledger = el("ledger-crack-math");
  ledger.innerHTML = "";
  data.math_steps.forEach((step, i) => ledger.appendChild(ledgerRow(i + 1, step.label, step.value)));

  const ptWrap = el("plaintext-wrap");
  if (data.plaintext !== null || data.plaintext_hex !== null) {
    ptWrap.classList.remove("hidden");
    const ptLedger = el("ledger-plaintext");
    ptLedger.innerHTML = "";
    if (data.plaintext !== null) {
      ptLedger.appendChild(ledgerRow("→", "plaintext (text)", data.plaintext));
    } else {
      ptLedger.appendChild(ledgerRow("→", "plaintext (hex, not valid utf-8)", data.plaintext_hex));
    }
  } else {
    ptWrap.classList.add("hidden");
  }

  const logPanel = el("panel-attack-log");
  const logList = el("attack-log-list");
  if (data.ran_attacks && data.attack_log && data.attack_log.length) {
    logPanel.classList.remove("hidden");
    logList.innerHTML = data.attack_log.map((a) => {
      const mark = a.success ? "✓" : "✗";
      const color = a.success ? "var(--cyan)" : "var(--text-muted)";
      const note = a.note ? ` — ${a.note}` : "";
      return `<div style="padding:4px 0; color:${color};">${mark} ${a.attack} (${a.time_ms}ms)${note}</div>`;
    }).join("");
  } else {
    logPanel.classList.add("hidden");
  }
}
