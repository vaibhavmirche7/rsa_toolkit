"""
main.py — FastAPI entrypoint for the RSA Web Toolkit.

Run locally:
    pip install -r requirements.txt
    uvicorn main:app --reload
"""

from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from typing import Optional
import urllib.parse

from core.keygen import generate_key, KeygenError, ALLOWED_BITS
from core.string_crypto import encrypt_string, decrypt_string, CryptoError
from core.file_crypto import encrypt_file, decrypt_file
from core.crack_flow import analyze, CrackError

app = FastAPI(title="RSA Web Toolkit")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# Pages

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request, "index.html", {"active": "home"})


@app.get("/keygen", response_class=HTMLResponse)
def keygen_page(request: Request):
    return templates.TemplateResponse(request, "keygen.html", {"allowed_bits": ALLOWED_BITS, "active": "keygen"})


@app.get("/files", response_class=HTMLResponse)
def files_page(request: Request):
    return templates.TemplateResponse(request, "files.html", {"active": "files"})


@app.get("/crack", response_class=HTMLResponse)
def crack_page(request: Request):
    return templates.TemplateResponse(request, "crack.html", {"active": "crack"})


# API: key generation


class KeygenRequest(BaseModel):
    bits: int
    e: int = 65537
    mode: str = Field(default="standard", pattern="^(standard|weak_fermat|weak_wiener)$")


@app.post("/api/keygen")
def api_keygen(req: KeygenRequest):
    try:
        result = generate_key(bits=req.bits, e=req.e, mode=req.mode)
    except KeygenError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result.to_dict()


# API: string encrypt / decrypt

class EncryptStringRequest(BaseModel):
    plaintext: str
    mode: str = Field(default="oaep", pattern="^(oaep|raw)$")
    pem: Optional[str] = None
    n: Optional[str] = None
    e: Optional[str] = None


@app.post("/api/encrypt-string")
def api_encrypt_string(req: EncryptStringRequest):
    try:
        result = encrypt_string(
            plaintext=req.plaintext, mode=req.mode, pem=req.pem,
            n=int(req.n) if req.n else None,
            e=int(req.e) if req.e else None,
        )
    except CryptoError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result


class DecryptStringRequest(BaseModel):
    mode: str = Field(default="oaep", pattern="^(oaep|raw)$")
    pem: Optional[str] = None
    n: Optional[str] = None
    d: Optional[str] = None
    p: Optional[str] = None
    q: Optional[str] = None
    e: Optional[str] = None
    ciphertext_int: Optional[str] = None
    ciphertext_b64: Optional[str] = None


@app.post("/api/decrypt-string")
def api_decrypt_string(req: DecryptStringRequest):
    try:
        result = decrypt_string(
            mode=req.mode, pem=req.pem,
            n=int(req.n) if req.n else None,
            d=int(req.d) if req.d else None,
            p=int(req.p) if req.p else None,
            q=int(req.q) if req.q else None,
            e=int(req.e) if req.e else None,
            ciphertext_int=req.ciphertext_int,
            ciphertext_b64=req.ciphertext_b64,
        )
    except CryptoError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result

# API: file / image hybrid (AES-GCM + RSA-OAEP) encrypt / decrypt

def _content_disposition(filename: str) -> str:
    # RFC 5987 — safe for filenames with spaces/unicode/special chars
    quoted = urllib.parse.quote(filename)
    return f"attachment; filename*=UTF-8''{quoted}"


@app.post("/api/encrypt-file")
async def api_encrypt_file(
    file: UploadFile = File(...),
    pem: Optional[str] = Form(None),
    n: Optional[str] = Form(None),
    e: Optional[str] = Form(None),
):
    data = await file.read()
    try:
        bundle = encrypt_file(
            data, file.filename or "file.bin", pem=pem or None,
            n=int(n) if n else None, e=int(e) if e else None,
        )
    except CryptoError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    out_name = (file.filename or "file") + ".rwtenc"
    return Response(
        content=bundle,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": _content_disposition(out_name),
            "X-Original-Filename": urllib.parse.quote(out_name),
        },
    )


@app.post("/api/decrypt-file")
async def api_decrypt_file(
    file: UploadFile = File(...),
    pem: Optional[str] = Form(None),
    n: Optional[str] = Form(None),
    d: Optional[str] = Form(None),
    p: Optional[str] = Form(None),
    q: Optional[str] = Form(None),
    e: Optional[str] = Form(None),
):
    bundle = await file.read()
    try:
        data, original_name = decrypt_file(
            bundle, pem=pem or None,
            n=int(n) if n else None, d=int(d) if d else None,
            p=int(p) if p else None, q=int(q) if q else None,
            e=int(e) if e else None,
        )
    except CryptoError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": _content_disposition(original_name),
            "X-Original-Filename": urllib.parse.quote(original_name),
        },
    )


# API: crack a weak key

class CrackRequest(BaseModel):
    pem: Optional[str] = None
    n: Optional[str] = None
    e: Optional[str] = None
    d: Optional[str] = None
    p: Optional[str] = None
    q: Optional[str] = None
    ciphertext: Optional[str] = None


@app.post("/api/crack")
def api_crack(req: CrackRequest):
    try:
        result = analyze(
            pem=req.pem or None,
            n=int(req.n) if req.n else None,
            e=int(req.e) if req.e else None,
            d=int(req.d) if req.d else None,
            p=int(req.p) if req.p else None,
            q=int(req.q) if req.q else None,
            ciphertext=req.ciphertext or None,
        )
    except CrackError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result
