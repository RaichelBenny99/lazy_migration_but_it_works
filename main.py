"""
main.py
-------
FastAPI application for the Cryptographically Agile Password Vault.

Key concepts demonstrated:
  1. Versioned Encryption  — each credential tracks its scheme_version.
  2. Lazy Migration        — upgrade from v1 → v2 happens automatically
                             the first time a v1 credential is accessed,
                             not in a big-bang batch migration.
  3. Hybrid Encryption     — v2 combines classical (RSA+AES) with a
                             simulated post-quantum commitment layer.

Run with:
  uvicorn main:app --reload
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

import db
import crypto_utils


# ---------------------------------------------------------------------------
# RSA Key Pair — loaded once at startup
# ---------------------------------------------------------------------------
# In production: load from a secrets manager / HSM.
# Here we persist keys to disk to keep vault decryptable across reloads.

PRIVATE_KEY_PEM: bytes = b""
PUBLIC_KEY_PEM: bytes = b""
KEY_DIR = "keys"
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "private.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "public.pem")


def _load_or_create_rsa_keys() -> tuple[bytes, bytes]:
    """Load PEM keys from disk or generate and persist them."""
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR, exist_ok=True)

    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_key = f.read()
        with open(PUBLIC_KEY_PATH, "rb") as f:
            public_key = f.read()
        print("Loaded existing RSA key pair from disk.")
        return private_key, public_key

    private_key, public_key = crypto_utils.generate_rsa_key_pair()
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_key)
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_key)

    print("Generated and persisted new RSA key pair.")
    return private_key, public_key


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: initialize DB and load/generate RSA key pair."""
    global PRIVATE_KEY_PEM, PUBLIC_KEY_PEM

    db.init_db()

    PRIVATE_KEY_PEM, PUBLIC_KEY_PEM = _load_or_create_rsa_keys()
    print("\nVault ready. RSA key pair loaded and vault initialized.\n")

    yield   # application runs here


app = FastAPI(
    title="Cryptographically Agile Password Vault",
    description=(
        "Demonstrates versioned encryption (v1/v2) and lazy migration "
        "from classical to hybrid post-quantum encryption."
    ),
    version="1.0.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class AddPasswordRequest(BaseModel):
    site: str
    username: str
    password: str


class AddPasswordResponse(BaseModel):
    id: int
    site: str
    username: str
    scheme_version: str
    message: str


class GetPasswordResponse(BaseModel):
    id: int
    site: str
    username: str
    password: str               # plaintext, returned only for demo
    scheme_version: str
    migrated: bool              # True if lazy migration just ran
    message: str


# ---------------------------------------------------------------------------
# Helper: Lazy Migration
# ---------------------------------------------------------------------------

def lazy_migrate_if_needed(credential_id: int, row: dict) -> tuple[str, bool]:
    """
    LAZY MIGRATION CORE LOGIC
    --------------------------
    This function is called every time a credential is accessed.

    If the stored scheme is v1:
      1. Decrypt with v1 (RSA+AES).
      2. Re-encrypt with v2 (RSA+AES+PQC simulation).
      3. Persist the updated ciphertext and bump scheme_version to "v2".
      4. Return the plaintext and migrated=True.

    If the stored scheme is already v2:
      1. Just decrypt with v2.
      2. Return the plaintext and migrated=False.

    This "lazy" approach means:
      - No downtime: we never run a bulk migration script.
      - Gradual rollout: v1 entries disappear naturally as users access them.
      - Atomic per-entry: each upgrade is a single DB transaction.
    """
    scheme = row["scheme_version"]

    if scheme == "v1":
        # --- Step 1: Decrypt using v1 ---
        print(f"  [Migration] Entry {credential_id} is v1 → decrypting...")
        plaintext = crypto_utils.decrypt_v1(
            row["password_ciphertext"],
            row["encrypted_key"],
            PRIVATE_KEY_PEM,
        )

        # --- Step 2: Re-encrypt using v2 ---
        print(f"  [Migration] Re-encrypting entry {credential_id} as v2...")
        new_data = crypto_utils.encrypt_v2(plaintext, PUBLIC_KEY_PEM)

        # --- Step 3: Persist upgraded entry ---
        db.update_credential_scheme(
            credential_id,
            new_data["password_ciphertext"],
            new_data["encrypted_key"],
            new_data["scheme_version"],
        )
        print(f"  [Migration] ✅ Entry {credential_id} migrated v1 → v2.\n")
        return plaintext, True   # migrated=True

    elif scheme == "v2":
        # Already on latest scheme — just decrypt
        plaintext = crypto_utils.decrypt_v2(
            row["password_ciphertext"],
            row["encrypted_key"],
            PRIVATE_KEY_PEM,
        )
        return plaintext, False  # migrated=False

    else:
        raise ValueError(f"Unknown scheme_version: {scheme}")


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.post("/add-password", response_model=AddPasswordResponse)
def add_password(req: AddPasswordRequest):
    """
    Add a new password to the vault.

    Always stores using v1 (classical AES+RSA) to simulate
    a legacy system that hasn't migrated yet.
    The lazy migration will upgrade it on first access.
    """
    # Encrypt with v1
    encrypted = crypto_utils.encrypt_v1(req.password, PUBLIC_KEY_PEM)

    # Persist to DB
    new_id = db.insert_credential(
        site=req.site,
        username=req.username,
        password_ciphertext=encrypted["password_ciphertext"],
        encrypted_key=encrypted["encrypted_key"],
        scheme_version=encrypted["scheme_version"],
    )

    return AddPasswordResponse(
        id=new_id,
        site=req.site,
        username=req.username,
        scheme_version="v1",
        message=f"Password stored with v1 encryption. Will migrate to v2 on first access.",
    )


@app.get("/get-password/{credential_id}", response_model=GetPasswordResponse)
def get_password(credential_id: int):
    """
    Retrieve a password by ID.

    LAZY MIGRATION happens here:
      - v1 entries are decrypted, re-encrypted as v2, saved, then returned.
      - v2 entries are just decrypted and returned.

    The caller can see whether migration occurred via the `migrated` field.
    """
    row = db.get_credential(credential_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Credential {credential_id} not found.")

    row_dict = dict(row)

    try:
        plaintext, migrated = lazy_migrate_if_needed(credential_id, row_dict)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption error: {str(e)}")

    # Fetch fresh row to return current scheme_version
    updated_row = db.get_credential(credential_id)

    return GetPasswordResponse(
        id=credential_id,
        site=updated_row["site"],
        username=updated_row["username"],
        password=plaintext,
        scheme_version=updated_row["scheme_version"],
        migrated=migrated,
        message=(
            "Migrated from v1 → v2 on this access." if migrated
            else "Already on v2; no migration needed."
        ),
    )


@app.get("/list-passwords")
def list_passwords():
    """
    List all vault entries with their scheme_version.
    Does NOT return plaintext passwords — use /get-password/{id} for that.

    Useful for monitoring migration progress across the vault.
    """
    entries = db.list_credentials()
    v1_count = sum(1 for e in entries if e["scheme_version"] == "v1")
    v2_count = sum(1 for e in entries if e["scheme_version"] == "v2")

    return {
        "total": len(entries),
        "v1_count": v1_count,
        "v2_count": v2_count,
        "entries": entries,
        "note": (
            "v1 entries will automatically migrate to v2 when accessed via /get-password/{id}"
        ),
    }


@app.get("/", response_class=HTMLResponse)
def root():
    return """
    <!DOCTYPE html>
    <html lang='en'>
    <head>
      <meta charset='UTF-8'>
      <meta name='viewport' content='width=device-width, initial-scale=1.0'>
      <title>Crypto Vault UI</title>
      <style>
        :root {
          --bg: #0f172a;
          --card: #111827;
          --panel: #1f2937;
          --accent: #22d3ee;
          --accent2: #a855f7;
          --text: #e2e8f0;
          --muted: #94a3b8;
          --error: #fb7185;
          --success: #34d399;
        }

        body { font-family: 'Inter', 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 0; background: linear-gradient(120deg, #040b1d, #0e1b40 60%, #131f4f); color: var(--text); }
        .container { max-width: 960px; margin: 1.5rem auto; padding: 1.25rem; background: var(--card); border-radius: 16px; box-shadow: 0 16px 40px rgba(0,0,0,.4); border: 1px solid rgba(56, 189, 248, .2); }
        h1 { margin-top:0; color: var(--accent); letter-spacing: 0.04em; }
        h2 { color: var(--text); margin: 0.75rem 0 0.45rem; }
        p { margin: 0.4rem 0 1rem; color: var(--muted); }

        .card { background: var(--panel); border-radius: 12px; border: 1px solid rgba(148, 163, 184, .2); padding: 1rem; box-shadow: inset 0 0 0 1px rgba(71, 85, 105, .10); margin-bottom: 1.0rem; }
        label { display: block; margin: .45rem 0 .15rem; font-size: 0.90rem; color: #cbd5e1; }
        input { width: 100%; margin: 0.25rem 0 .8rem; padding: .68rem; border: 1px solid #334155; border-radius: 8px; background: #0f172a; color: #e2e8f0; }
        input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(34, 211, 238, .20); }
        button { width: 100%; margin: .3rem 0 .8rem; padding: .75rem; border: 0; border-radius: 10px; background: linear-gradient(120deg, var(--accent), var(--accent2)); color: #0f172a; font-weight: 700; cursor: pointer; transition: transform .15s ease, filter .15s ease; }
        button:hover { transform: translateY(-1px); filter: brightness(1.05); }

        .two-cols { display:grid; grid-template-columns: 1fr; gap:1rem; }
        @media (min-width: 760px) { .two-cols { grid-template-columns: 1fr 1fr; } }

        .log { border: 1px solid rgba(100, 116, 139, .4); border-radius: 10px; padding: .9rem; background: rgba(15, 23, 42, .95); min-height: 210px; font-family: 'Courier New', monospace; color: #e2e8f0; white-space: pre-wrap; overflow-y: auto; }
        .tag { display: inline-block; margin: .2rem .2rem .2rem 0; padding: .2rem .5rem; color: #fff; border-radius: 999px; font-size: .81rem; }
        .tag-success { background: var(--success); }
        .tag-info { background: var(--accent); }
        .tag-error { background: var(--error); }
      </style>
    </head>
    <body>
      <div class='container'>
        <h1>Cryptographically Agile Vault</h1>

        <section>
          <h2>Add password (v1 encrypted)</h2>
          <label for='site'>Site</label><input id='site' placeholder='github.com'/>
          <label for='username'>Username</label><input id='username' placeholder='alice@example.com'/>
          <label for='password'>Password</label><input id='password' type='password' placeholder='hunter2' />
          <button onclick='addPassword()'>Add Password</button>
        </section>

        <section>
          <h2>Get password by ID (lazy migrate)</h2>
          <label for='readId'>Credential ID</label><input id='readId' placeholder='1' />
          <button onclick='getPassword()'>Get Password</button>
        </section>

        <section>
          <h2>List credentials</h2>
          <button onclick='listPasswords()'>Load List</button>
        </section>

        <section>
          <h2>Output</h2>
          <div id='log' class='log'>Ready. Use forms above.</div>
        </section>
      </div>

      <script>
        const log = document.getElementById('log');
        function logMessage(msg, level='info') {
          const time = new Date().toLocaleTimeString();
          let prefix = `[${time}]`;
          /*if (level === 'success') prefix += '1';
          if (level === 'error') prefix += '0';"*/
          log.textContent += `${prefix} ${msg}\n`;
          log.scrollTop = log.scrollHeight;
        }

        function validate(inputs) {
          return inputs.every(v => v && v.trim().length > 0);
        }

        async function addPassword() {
          const site = document.getElementById('site').value;
          const username = document.getElementById('username').value;
          const password = document.getElementById('password').value;

          if (!validate([site, username, password])) {
            logMessage('Add Password: all fields are required', 'error');
            return;
          }

          const payload = { site, username, password };
          try {
            const res = await fetch('/add-password', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
            const data = await res.json();
            if (res.ok) {
              logMessage(`ADDED ID=${data.id} site=${data.site} scheme=${data.scheme_version}`, 'success');
            } else {
              logMessage(`ADD  ${JSON.stringify(data)}`, 'error');
            }
          } catch (err) { logMessage('ADD ERROR: ' + err, 'error'); }
        }

        async function getPassword() {
          const id = document.getElementById('readId').value;
          if (!validate([id])) {
            logMessage('Get Password: ID is required', 'error');
            return;
          }
          try {
            const res = await fetch('/get-password/' + encodeURIComponent(id));
            const data = await res.json();
            if (res.ok) {
              logMessage(`ID=${data.id}`);
              logMessage(`migrated=${data.migrated}`);
              logMessage(`scheme=${data.scheme_version}`);
              logMessage(`password=${data.password}`);
            } else {
              logMessage(`Get Password failed: ${data.detail || JSON.stringify(data)}`, 'error');
            }
          } catch (err) { logMessage('Get Password failed: ' + err, 'error'); }
        }

        async function listPasswords() {
          try {
            const res = await fetch('/list-passwords');
            const data = await res.json();
            if (res.ok) {
              logMessage(`LIST  total=${data.total} v1=${data.v1_count} v2=${data.v2_count}`,'success');
              logMessage(JSON.stringify(data.entries, null, 2));
            } else {
              logMessage(`LIST  ${JSON.stringify(data)}`, 'error');
            }
          } catch (err) { logMessage('LIST ERROR: ' + err, 'error'); }
        }
      </script>
    </body>
    </html>
    """
