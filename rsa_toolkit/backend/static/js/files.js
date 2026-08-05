// files.js — drives /files: hybrid AES+RSA encrypt/decrypt of an
// uploaded file. Every call is a plain multipart POST; the response
// is the resulting file bytes, downloaded straight from the blob.

function el(id) { return document.getElementById(id); }

function wireKeySource(selectId, wraps) {
  const sel = el(selectId);
  sel.addEventListener("change", () => {
    Object.entries(wraps).forEach(([val, id]) => {
      el(id).classList.toggle("hidden", sel.value !== val);
    });
  });
}
wireKeySource("enc-keysource", { auto: "enc-auto-wrap", raw: "enc-raw-wrap" });
wireKeySource("dec-keysource", { pem: "dec-pem-wrap", raw: "dec-raw-wrap" });

// weak_wiener derives e itself — hide the e field for that mode, same as Key Gen page
el("enc-mode").addEventListener("change", () => {
  el("enc-e-wrap").style.display = el("enc-mode").value === "weak_wiener" ? "none" : "flex";
});

function statusOk(id, msg) {
  el(id).innerHTML = `<div class="result-status success">${msg}</div>`;
}
function statusErr(id, msg) {
  el(id).innerHTML = `<div class="result-status error">Error: ${msg}</div>`;
}

function downloadText(content, filename, mime) {
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

function downloadBlobResult(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

async function postForm(url, formData) {
  const resp = await fetch(url, { method: "POST", body: formData });
  if (!resp.ok) {
    let detail = `request failed (${resp.status})`;
    try { detail = (await resp.json()).detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  const blob = await resp.blob();
  let filename = "download.bin";
  const header = resp.headers.get("X-Original-Filename");
  if (header) filename = decodeURIComponent(header);
  return { blob, filename };
}

async function generateKeyForEncrypt() {
  const bits = parseInt(el("enc-bits").value, 10);
  const mode = el("enc-mode").value;
  const e = parseInt(el("enc-e-auto").value || "65537", 10);
  const resp = await fetch("/api/keygen", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ bits, e, mode }),
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.detail || "key generation failed");

  // download both key files right away — the private one is what you'll
  // need on the Decrypt side later, so it has to leave the browser now
  downloadText(data.export.private_pkcs1_pem, "private_pkcs1.pem", "application/x-pem-file");
  setTimeout(() => downloadText(data.export.public_pem, "public.pem", "application/x-pem-file"), 300);

  return data;
}

// ---------------------------------------------------------------
// PEM file upload (decrypt panel)
// ---------------------------------------------------------------

el("dec-pem-file").addEventListener("change", async (ev) => {
  const file = ev.target.files[0];
  if (!file) return;
  el("dec-pem").value = await file.text();
});

// ---------------------------------------------------------------
// encrypt
// ---------------------------------------------------------------

el("btn-encrypt-file").addEventListener("click", async () => {
  const btn = el("btn-encrypt-file");
  const fileInput = el("enc-file");
  if (!fileInput.files.length) return statusErr("enc-file-status", "choose a file first");

  const source = el("enc-keysource").value;
  btn.disabled = true;

  try {
    let n, e;
    if (source === "auto") {
      btn.textContent = "Generating key…";
      const kg = await generateKeyForEncrypt();
      n = kg.n; e = kg.e;
      statusOk("enc-file-status", `${kg.bits}-bit key generated and downloaded — encrypting now…`);
    } else {
      n = el("enc-n").value;
      e = el("enc-e").value;
      if (!n || !e) return statusErr("enc-file-status", "enter at least n and e");
    }

    const fd = new FormData();
    fd.append("file", fileInput.files[0]);
    fd.append("n", n);
    fd.append("e", e);

    btn.textContent = "Encrypting…";
    const { blob, filename } = await postForm("/api/encrypt-file", fd);
    downloadBlobResult(blob, filename);
    statusOk("enc-file-status",
      source === "auto"
        ? `Encrypted — downloaded as "${filename}". Keep private_pkcs1.pem safe, you'll need it to decrypt.`
        : `Encrypted — downloaded as "${filename}"`);
  } catch (err) {
    statusErr("enc-file-status", err.message);
  } finally {
    btn.disabled = false; btn.textContent = "Encrypt & download";
  }
});

// ---------------------------------------------------------------
// decrypt
// ---------------------------------------------------------------

el("btn-decrypt-file").addEventListener("click", async () => {
  const btn = el("btn-decrypt-file");
  const fileInput = el("dec-file");
  if (!fileInput.files.length) return statusErr("dec-file-status", "choose a .rwtenc bundle first");

  const fd = new FormData();
  fd.append("file", fileInput.files[0]);
  const source = el("dec-keysource").value;
  if (source === "pem") {
    if (!el("dec-pem").value.trim()) return statusErr("dec-file-status", "upload or paste a private key PEM");
    fd.append("pem", el("dec-pem").value);
  } else {
    fd.append("n", el("dec-n").value);
    fd.append("e", el("dec-e").value);
    fd.append("d", el("dec-d").value);
    fd.append("p", el("dec-p").value);
    fd.append("q", el("dec-q").value);
  }

  btn.disabled = true; btn.textContent = "Decrypting…";
  try {
    const { blob, filename } = await postForm("/api/decrypt-file", fd);
    downloadBlobResult(blob, filename);
    statusOk("dec-file-status", `Decrypted — downloaded as "${filename}"`);
  } catch (err) {
    statusErr("dec-file-status", err.message);
  } finally {
    btn.disabled = false; btn.textContent = "Decrypt & download";
  }
});
