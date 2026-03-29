"""
demo.py
-------
Self-contained demonstration of the vault's core logic.
Runs WITHOUT needing uvicorn — just: python demo.py

Shows the full lifecycle:
  Step 1: Add password  → stored as v1
  Step 2: First access  → lazy migration v1 → v2
  Step 3: Second access → already v2, no migration
"""

import sys
import os

# Make sure we can import from the same directory
sys.path.insert(0, os.path.dirname(__file__))

import db
import crypto_utils

# Use a fresh in-memory-style DB for the demo
db.DB_PATH = "demo_vault.db"

# ── Setup ────────────────────────────────────────────────────────────────────
print("=" * 60)
print("  Cryptographically Agile Password Vault — Demo")
print("=" * 60)

db.init_db()
private_pem, public_pem = crypto_utils.generate_rsa_key_pair()
print("\n✅ RSA key pair generated.\n")


# ── Step 1: Add password (stored as v1) ──────────────────────────────────────
print("─" * 60)
print("STEP 1: Add password → encrypted with v1 (AES + RSA)")
print("─" * 60)

site     = "github.com"
username = "alice@example.com"
password = "super_secret_42!"

encrypted = crypto_utils.encrypt_v1(password, public_pem)
cred_id = db.insert_credential(
    site=site,
    username=username,
    password_ciphertext=encrypted["password_ciphertext"],
    encrypted_key=encrypted["encrypted_key"],
    scheme_version=encrypted["scheme_version"],
)

row = db.get_credential(cred_id)
print(f"  Stored ID      : {cred_id}")
print(f"  Site           : {row['site']}")
print(f"  Username       : {row['username']}")
print(f"  Scheme version : {row['scheme_version']}  ← classical encryption")
print(f"  Ciphertext[:40]: {row['password_ciphertext'][:40]}...")


# ── Step 2: First access → lazy migration ────────────────────────────────────
print("\n" + "─" * 60)
print("STEP 2: First access → LAZY MIGRATION v1 → v2")
print("─" * 60)

row = db.get_credential(cred_id)

if row["scheme_version"] == "v1":
    print("  Detected v1 entry. Starting migration...")

    # Decrypt with v1
    plaintext = crypto_utils.decrypt_v1(
        row["password_ciphertext"],
        row["encrypted_key"],
        private_pem,
    )
    print(f"  Decrypted (v1) : '{plaintext}'")

    # Re-encrypt with v2
    new_data = crypto_utils.encrypt_v2(plaintext, public_pem)
    db.update_credential_scheme(
        cred_id,
        new_data["password_ciphertext"],
        new_data["encrypted_key"],
        new_data["scheme_version"],
    )

    row = db.get_credential(cred_id)
    print(f"  Scheme version : {row['scheme_version']}  ← upgraded to hybrid encryption")
    print(f"  Ciphertext[:40]: {row['password_ciphertext'][:40]}...")
    print("  ✅ Migration complete! (migrated=True)")


# ── Step 3: Second access → no migration needed ──────────────────────────────
print("\n" + "─" * 60)
print("STEP 3: Second access → ALREADY v2, no migration")
print("─" * 60)

row = db.get_credential(cred_id)
print(f"  Scheme version : {row['scheme_version']}")

if row["scheme_version"] == "v2":
    plaintext = crypto_utils.decrypt_v2(
        row["password_ciphertext"],
        row["encrypted_key"],
        private_pem,
    )
    print(f"  Decrypted (v2) : '{plaintext}'")
    print("  ✅ No migration needed. (migrated=False)")


# ── Summary ───────────────────────────────────────────────────────────────────
print("\n" + "─" * 60)
print("SUMMARY")
print("─" * 60)
entries = db.list_credentials()
for e in entries:
    print(f"  ID={e['id']}  site={e['site']}  scheme={e['scheme_version']}")

print("\n  All entries are now on v2.")
print("  Original password was never stored in plaintext in the DB.")
print("  Migration happened transparently on first access.\n")

# Cleanup
import os
if os.path.exists("demo_vault.db"):
    os.remove("demo_vault.db")
