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
from pydantic import BaseModel

import db
import crypto_utils


# ---------------------------------------------------------------------------
# RSA Key Pair — loaded once at startup
# ---------------------------------------------------------------------------
# In production: load from a secrets manager / HSM.
# Here we generate fresh keys each run (fine for a prototype).

PRIVATE_KEY_PEM: bytes = b""
PUBLIC_KEY_PEM: bytes = b""


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: initialize DB and generate RSA key pair."""
    global PRIVATE_KEY_PEM, PUBLIC_KEY_PEM

    db.init_db()

    PRIVATE_KEY_PEM, PUBLIC_KEY_PEM = crypto_utils.generate_rsa_key_pair()
    print("\n✅ Vault ready. RSA key pair generated for this session.\n")

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


@app.get("/")
def root():
    return {
        "name": "Cryptographically Agile Password Vault",
        "version": "1.0.0",
        "endpoints": {
            "POST /add-password":            "Store a new password (encrypted as v1)",
            "GET  /get-password/{id}":       "Retrieve password + trigger lazy migration",
            "GET  /list-passwords":          "See all entries and their scheme versions",
        },
        "demo_flow": [
            "1. POST /add-password  →  stored as v1",
            "2. GET  /get-password/1  →  migrated to v2, migrated=true",
            "3. GET  /get-password/1  →  already v2, migrated=false",
        ],
    }
