# Cryptographically Agile Password Vault with Lazy Migration

A Python/FastAPI prototype demonstrating **cryptographic agility**, **lazy migration**, and **hybrid post-quantum encryption concepts**.

---

## 📁 File Structure

```
vault/
├── main.py          # FastAPI app + lazy migration endpoint logic
├── crypto_utils.py  # v1 and v2 encryption/decryption functions
├── db.py            # SQLite CRUD operations
├── demo.py          # Standalone demo (no server needed)
├── requirements.txt # Python dependencies
└── README.md        # This file
```

---

## ⚙️ Setup & Installation

```bash
# 1. Create and activate a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # macOS/Linux
venv\Scripts\activate           # Windows

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start the server
uvicorn main:app --reload
```

The API will be available at: **http://127.0.0.1:8000**

Interactive Swagger docs: **http://127.0.0.1:8000/docs**

---

## 🚀 Quick Demo (no server needed)

```bash
python demo.py
```

This runs the full 3-step lifecycle (add → migrate → access) in a single script.

---

## 🔌 API Endpoints

### `POST /add-password`
Store a new credential. Always encrypts with **v1** (classical).

```bash
curl -X POST http://127.0.0.1:8000/add-password \
  -H "Content-Type: application/json" \
  -d '{"site": "github.com", "username": "alice@example.com", "password": "hunter2"}'
```

**Response:**
```json
{
  "id": 1,
  "site": "github.com",
  "username": "alice@example.com",
  "scheme_version": "v1",
  "message": "Password stored with v1 encryption. Will migrate to v2 on first access."
}
```

---

### `GET /get-password/{id}`
Retrieve a password. **Triggers lazy migration** if scheme is v1.

```bash
# First access → migrates v1 → v2
curl http://127.0.0.1:8000/get-password/1
```

**Response (first access):**
```json
{
  "id": 1,
  "site": "github.com",
  "username": "alice@example.com",
  "password": "hunter2",
  "scheme_version": "v2",
  "migrated": true,
  "message": "Migrated from v1 → v2 on this access."
}
```

```bash
# Second access → already v2, no migration
curl http://127.0.0.1:8000/get-password/1
```

**Response (second access):**
```json
{
  "id": 1,
  "site": "github.com",
  "username": "alice@example.com",
  "password": "hunter2",
  "scheme_version": "v2",
  "migrated": false,
  "message": "Already on v2; no migration needed."
}
```

---

### `GET /list-passwords`
List all entries with their current scheme version. Shows migration progress.

```bash
curl http://127.0.0.1:8000/list-passwords
```

**Response:**
```json
{
  "total": 1,
  "v1_count": 0,
  "v2_count": 1,
  "entries": [
    {"id": 1, "site": "github.com", "username": "alice@example.com", "scheme_version": "v2"}
  ],
  "note": "v1 entries will automatically migrate to v2 when accessed via /get-password/{id}"
}
```

---

## 🔐 Encryption Schemes

### v1 — Classical (AES + RSA)

```
plaintext_password
       │
       ▼
  [Fernet/AES-128-CBC]  ←──  random AES key
       │                           │
       ▼                           ▼
password_ciphertext        [RSA-OAEP encrypt]
                                   │
                                   ▼
                             encrypted_key
```

### v2 — Hybrid + Simulated PQC

```
plaintext_password
       │
       ▼
  [Fernet/AES-128-CBC]  ←──  random AES key
       │                           │
       ▼                    ┌──────┴──────┐
password_ciphertext    [RSA-OAEP]   [SHAKE-256]
                            │              │
                            ▼              ▼
                       rsa_wrapped_key  pqc_commitment
                            │              │
                            └──────┬───────┘
                               JSON bundle
                                   │
                             base64 encode
                                   │
                              encrypted_key
```

The **PQC commitment** (SHAKE-256 hash of the AES key) simulates what a real lattice-based KEM (like CRYSTALS-Kyber) would add: an additional binding that remains hard to break even on quantum hardware.

---

## 🔄 How Lazy Migration Works

```
User calls GET /get-password/1
              │
              ▼
      Read entry from DB
              │
              ▼
   scheme_version == "v1"?
        │            │
       YES           NO
        │            │
        ▼            ▼
  decrypt_v1()    decrypt_v2()
        │            │
        ▼            │
  encrypt_v2()       │
        │            │
        ▼            │
  update DB          │
  (now v2)           │
        │            │
        └─────┬──────┘
              ▼
       return plaintext
       (+ migrated flag)
```

**Key insight:** The migration is **triggered by access**, not by a scheduled batch job. This means:
- Zero downtime — no maintenance window required
- Gradual rollout — entries migrate organically as users use the system
- Rollback-safe — you can still read v1 entries at any time

---

## 📚 Concepts Explained

| Term | This Prototype |
|------|---------------|
| **Cryptographic Agility** | `scheme_version` field lets the system use different algorithms per entry |
| **Lazy Migration** | v1→v2 upgrade happens in `get-password`, not a batch script |
| **Hybrid Encryption** | AES (fast, for data) + RSA (slow, for key wrapping) |
| **Simulated PQC** | SHAKE-256 commitment models the role of a real KEM like Kyber |
| **Key Wrapping** | RSA encrypts the AES key, so we only need to protect one private key |
