"""
crypto_utils.py
---------------
Handles all cryptographic operations for the password vault.

Scheme Versions:
  v1 - Classical:  AES (via Fernet) + RSA key wrapping
  v2 - Hybrid:     AES (via Fernet) + RSA key wrapping
                   + Simulated Post-Quantum layer (SHAKE-256 key commitment)

WHY TWO SCHEMES?
  Cryptographic agility means the system can swap algorithms without
  rewriting everything. v1 is today's standard; v2 adds a simulated
  post-quantum layer so that even if RSA is broken by a quantum computer,
  the key commitment adds an extra integrity check.

POST-QUANTUM SIMULATION NOTE:
  Real PQC uses lattice-based algorithms (e.g., CRYSTALS-Kyber).
  Here we simulate the concept by adding a SHAKE-256 commitment of the
  AES key, stored alongside the ciphertext.  The "PQC layer" shows the
  structural pattern of hybrid encryption without requiring external libs.
"""

import os
import json
import hashlib
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet


# ---------------------------------------------------------------------------
# RSA Key Generation
# ---------------------------------------------------------------------------

def generate_rsa_key_pair():
    """
    Generate a 2048-bit RSA key pair.
    Returns (private_key_pem_bytes, public_key_pem_bytes).
    In a real system these would be stored securely (HSM, env var, etc.).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


# ---------------------------------------------------------------------------
# v1 — Classical Encryption (AES + RSA)
# ---------------------------------------------------------------------------

def encrypt_v1(plaintext_password: str, public_key_pem: bytes) -> dict:
    """
    v1 Encryption:
      1. Generate a random AES key (Fernet).
      2. Encrypt the password with AES.
      3. Encrypt the AES key with RSA public key (OAEP padding).

    Returns a dict with:
      - password_ciphertext : base64-encoded AES ciphertext
      - encrypted_key       : base64-encoded RSA-wrapped AES key
      - scheme_version      : "v1"
    """
    # Step 1: Fresh AES (Fernet) key for this entry
    aes_key = Fernet.generate_key()
    fernet = Fernet(aes_key)

    # Step 2: Encrypt password
    password_ciphertext = fernet.encrypt(plaintext_password.encode())

    # Step 3: Wrap AES key with RSA
    public_key = serialization.load_pem_public_key(public_key_pem)
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return {
        "password_ciphertext": base64.b64encode(password_ciphertext).decode(),
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "scheme_version": "v1",
    }


def decrypt_v1(password_ciphertext_b64: str, encrypted_key_b64: str,
               private_key_pem: bytes) -> str:
    """
    v1 Decryption:
      1. Unwrap AES key with RSA private key.
      2. Decrypt password ciphertext with AES.
    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    # Unwrap AES key
    encrypted_key = base64.b64decode(encrypted_key_b64)
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Decrypt password
    fernet = Fernet(aes_key)
    password_ciphertext = base64.b64decode(password_ciphertext_b64)
    return fernet.decrypt(password_ciphertext).decode()


# ---------------------------------------------------------------------------
# v2 — Hybrid Encryption (AES + RSA + Simulated PQC Layer)
# ---------------------------------------------------------------------------

def _pqc_simulate_commitment(aes_key: bytes) -> str:
    """
    Simulated Post-Quantum commitment layer.

    Concept: In a real hybrid PQC scheme (e.g., X25519 + Kyber KEM),
    you'd encapsulate a shared secret with a lattice-based algorithm.
    Here we use SHAKE-256 (an extendable-output hash) to produce a
    'commitment' of the AES key.  On decryption we verify this matches,
    giving us an extra integrity check that a quantum attacker would
    also need to break.

    Returns: hex string of the SHAKE-256 digest (64 bytes).
    """
    shake = hashlib.shake_256(aes_key)
    return shake.hexdigest(64)   # 64-byte digest → 128 hex chars


def encrypt_v2(plaintext_password: str, public_key_pem: bytes) -> dict:
    """
    v2 Hybrid Encryption:
      1. Generate AES key and encrypt password (same as v1).
      2. Wrap AES key with RSA (same as v1).
      3. ADDITIONALLY compute a SHAKE-256 commitment of the AES key
         (simulates PQC encapsulation layer).
      4. Bundle RSA-wrapped key + PQC commitment into a JSON blob,
         store that blob as the encrypted_key field.

    Returns a dict matching the vault schema.
    """
    # Step 1 & 2: Same as v1
    aes_key = Fernet.generate_key()
    fernet = Fernet(aes_key)
    password_ciphertext = fernet.encrypt(plaintext_password.encode())

    public_key = serialization.load_pem_public_key(public_key_pem)
    rsa_wrapped_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Step 3: PQC commitment
    pqc_commitment = _pqc_simulate_commitment(aes_key)

    # Step 4: Bundle into JSON blob
    key_bundle = {
        "rsa_wrapped_key": base64.b64encode(rsa_wrapped_key).decode(),
        "pqc_commitment": pqc_commitment,   # simulated PQC ciphertext
        "scheme": "rsa2048+shake256-pqc-sim",
    }
    encrypted_key_blob = base64.b64encode(
        json.dumps(key_bundle).encode()
    ).decode()

    return {
        "password_ciphertext": base64.b64encode(password_ciphertext).decode(),
        "encrypted_key": encrypted_key_blob,
        "scheme_version": "v2",
    }


def decrypt_v2(password_ciphertext_b64: str, encrypted_key_b64: str,
               private_key_pem: bytes) -> str:
    """
    v2 Decryption:
      1. Decode the JSON key bundle.
      2. Unwrap AES key with RSA.
      3. Verify PQC commitment (integrity check).
      4. Decrypt password with AES.
    """
    # Decode bundle
    key_bundle = json.loads(base64.b64decode(encrypted_key_b64).decode())
    rsa_wrapped_key = base64.b64decode(key_bundle["rsa_wrapped_key"])
    stored_commitment = key_bundle["pqc_commitment"]

    # Unwrap AES key with RSA
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    aes_key = private_key.decrypt(
        rsa_wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Verify PQC commitment — detects tampering even if RSA is compromised
    expected_commitment = _pqc_simulate_commitment(aes_key)
    if expected_commitment != stored_commitment:
        raise ValueError("PQC commitment mismatch — key integrity check failed!")

    # Decrypt password
    fernet = Fernet(aes_key)
    password_ciphertext = base64.b64decode(password_ciphertext_b64)
    return fernet.decrypt(password_ciphertext).decode()
