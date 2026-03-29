"""
db.py
-----
All database interactions for the password vault.
Uses SQLite via Python's built-in sqlite3 module.

Table schema:
  vault(
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    site               TEXT    NOT NULL,
    username           TEXT    NOT NULL,
    password_ciphertext TEXT   NOT NULL,   -- base64 AES ciphertext
    encrypted_key      TEXT    NOT NULL,   -- base64 RSA-wrapped key (v1)
                                           -- or base64 JSON bundle (v2)
    scheme_version     TEXT    NOT NULL    -- "v1" or "v2"
  )
"""

import sqlite3
from typing import Optional

DB_PATH = "vault.db"


def get_connection() -> sqlite3.Connection:
    """Return a SQLite connection with row_factory for dict-like access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row   # rows behave like dicts
    return conn


def init_db():
    """
    Create the vault table if it doesn't exist yet.
    Call this once at application startup.
    """
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vault (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                site                TEXT    NOT NULL,
                username            TEXT    NOT NULL,
                password_ciphertext TEXT    NOT NULL,
                encrypted_key       TEXT    NOT NULL,
                scheme_version      TEXT    NOT NULL
            )
        """)
        conn.commit()


# ---------------------------------------------------------------------------
# CRUD helpers
# ---------------------------------------------------------------------------

def insert_credential(site: str, username: str,
                       password_ciphertext: str, encrypted_key: str,
                       scheme_version: str) -> int:
    """Insert a new vault entry and return its auto-generated id."""
    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO vault (site, username, password_ciphertext,
                               encrypted_key, scheme_version)
            VALUES (?, ?, ?, ?, ?)
            """,
            (site, username, password_ciphertext, encrypted_key, scheme_version),
        )
        conn.commit()
        return cur.lastrowid


def get_credential(credential_id: int) -> Optional[sqlite3.Row]:
    """Fetch a single vault entry by id, or None if not found."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM vault WHERE id = ?", (credential_id,)
        ).fetchone()
    return row


def update_credential_scheme(credential_id: int,
                              password_ciphertext: str,
                              encrypted_key: str,
                              scheme_version: str):
    """
    Update the ciphertext, key blob, and scheme version for an entry.
    Called by the lazy migration process after re-encrypting with v2.
    """
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE vault
               SET password_ciphertext = ?,
                   encrypted_key       = ?,
                   scheme_version      = ?
             WHERE id = ?
            """,
            (password_ciphertext, encrypted_key, scheme_version, credential_id),
        )
        conn.commit()


def list_credentials() -> list:
    """Return all vault entries (without decrypted passwords)."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, site, username, scheme_version FROM vault"
        ).fetchall()
    return [dict(row) for row in rows]
