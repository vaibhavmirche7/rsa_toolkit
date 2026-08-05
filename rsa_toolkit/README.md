# RSA Web Toolkit

A browser-based workbench for RSA: generate real (or deliberately
weak) key pairs, encrypt/decrypt strings and files, and run classic
CTF-style attacks against weak keys. No accounts, no database
everything server-side is stateless and nothing you generate is
stored; the browser holds your keys/results and downloads them
directly.

## Quick start

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

Then open **http://127.0.0.1:8000**.

## Project structure

```
backend/
  main.py              FastAPI app + all routes/API endpoints
  core/
    keygen.py           RSA key generation (standard + 2 weak modes),
                         strength meter, fingerprint, PEM/DER/JSON exports
    string_crypto.py    RSA-OAEP and raw/textbook string encrypt & decrypt
  templates/             Jinja2 HTML pages
  static/css/style.css   design system (dark "cipher workbench" theme)
  static/js/keygen.js    Key Gen page interactivity
  requirements.txt
PROGRESS.md              stage tracker — read this first if resuming work
```
