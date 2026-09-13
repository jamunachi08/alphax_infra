# Copyright (c) 2026, Neotec Integrated Solutions
"""
Canonical JSON (RFC 8785 / JCS) and Ed25519 batch verification.

Why this module exists at all: a detached signature over "the JSON" is
meaningless unless both sides agree byte-for-byte on what "the JSON" is.
Python's json.dumps, Go's encoding/json and JavaScript's JSON.stringify all
disagree on key order, float formatting and non-ASCII escaping. Signing a
non-canonical form is the single most common way a signed-ingest pipeline
ends up intermittently rejecting valid batches, and the failures look random.

So: every batch is canonicalised with JCS before hashing, on the collector
side and on this side, and the signature covers the JCS bytes.

Ed25519 is verified through `cryptography` when it is installed (it is a
transitive dependency of the Frappe stack) and falls back to a pure-Python
implementation otherwise, so a bench without it still validates rather than
silently accepting unverified batches.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from typing import Any

# ---------------------------------------------------------------------------
# JCS — RFC 8785 canonical JSON
# ---------------------------------------------------------------------------

_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _escape_string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if cp in _ESCAPES:
            out.append(_ESCAPES[cp])
        elif cp < 0x20:
            out.append("\\u%04x" % cp)
        else:
            # JCS keeps everything else literal, including non-ASCII.
            out.append(ch)
    out.append('"')
    return "".join(out)


def _serialize_number(n) -> str:
    """ECMAScript Number::toString semantics, which is what JCS mandates."""
    if isinstance(n, bool):  # bool is an int subclass — must be caught first
        return "true" if n else "false"
    if isinstance(n, int):
        return str(n)
    if not math.isfinite(n):
        raise ValueError("NaN and Infinity are not representable in canonical JSON")
    if n == 0:
        # -0.0 canonicalises to "0"
        return "0"
    if n == int(n) and abs(n) < 1e21:
        return str(int(n))
    # repr() gives the shortest round-tripping representation in Python 3,
    # which matches what ECMAScript produces for the overlapping range.
    r = repr(n)
    if "e" in r or "E" in r:
        mantissa, exponent = re.split("[eE]", r)
        exp = int(exponent)
        mantissa = mantissa.rstrip("0").rstrip(".") if "." in mantissa else mantissa
        return f"{mantissa}e{'+' if exp >= 0 else '-'}{abs(exp)}"
    return r


def canonicalize(value: Any) -> bytes:
    """Serialise `value` to RFC 8785 canonical JSON bytes (UTF-8)."""

    def enc(v) -> str:
        if v is None:
            return "null"
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return _serialize_number(v)
        if isinstance(v, str):
            return _escape_string(v)
        if isinstance(v, (list, tuple)):
            return "[" + ",".join(enc(i) for i in v) + "]"
        if isinstance(v, dict):
            # JCS sorts by UTF-16 code units, which for the key shapes we
            # accept (ASCII fact keys) is identical to sorting the str.
            items = sorted(v.items(), key=lambda kv: _utf16_sort_key(kv[0]))
            return "{" + ",".join(f"{_escape_string(k)}:{enc(val)}" for k, val in items) + "}"
        raise TypeError(f"{type(v).__name__} is not JSON-serialisable")

    return enc(value).encode("utf-8")


def _utf16_sort_key(s: str):
    return tuple(s.encode("utf-16-be"))


def digest(value: Any) -> str:
    """SHA-256 hex digest of the canonical form. This is the batch hash."""
    return hashlib.sha256(canonicalize(value)).hexdigest()


def content_hash(value: Any) -> str:
    """Short content address used to deduplicate identical observations."""
    return hashlib.blake2b(canonicalize(value), digest_size=16).hexdigest()


# ---------------------------------------------------------------------------
# Ed25519 verification
# ---------------------------------------------------------------------------


class SignatureError(Exception):
    pass


def _b64d(s: str) -> bytes:
    s = (s or "").strip()
    pad = "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s + pad)
    except Exception as exc:  # noqa: BLE001
        raise SignatureError(f"signature or key is not valid base64: {exc}") from exc


def verify_signature(payload: Any, signature_b64: str, public_key_b64: str) -> bool:
    """
    Verify a detached Ed25519 signature over the canonical form of `payload`.

    Returns True on success. Raises SignatureError when the signature is
    malformed, the key is unusable, or no verifier is available — never
    returns False for "could not check", because a soft failure here is
    indistinguishable from an accepted forgery.
    """
    message = canonicalize(payload)
    sig = _b64d(signature_b64)
    key = _b64d(public_key_b64)

    if len(sig) != 64:
        raise SignatureError(f"Ed25519 signature must be 64 bytes, got {len(sig)}")
    if len(key) != 32:
        raise SignatureError(f"Ed25519 public key must be 32 bytes, got {len(key)}")

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return _verify_pure_python(message, sig, key)

    try:
        Ed25519PublicKey.from_public_bytes(key).verify(sig, message)
        return True
    except InvalidSignature:
        return False
    except Exception as exc:  # noqa: BLE001
        raise SignatureError(f"Ed25519 verification failed: {exc}") from exc


# --- pure-Python Ed25519 fallback (RFC 8032 reference construction) ---------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _x_recover(y: int) -> int:
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if x % 2 != 0:
        x = _P - x
    return x


_BY = (4 * pow(5, _P - 2, _P)) % _P
_B = (_x_recover(_BY) % _P, _BY, 1, (_x_recover(_BY) * _BY) % _P)


def _edwards_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (t1 * 2 * _D * t2) % _P
    dd = (z1 * 2 * z2) % _P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _scalar_mult(p, e: int):
    q = (0, 1, 1, 0)
    while e > 0:
        if e & 1:
            q = _edwards_add(q, p)
        p = _edwards_add(p, p)
        e >>= 1
    return q


def _decode_point(s: bytes):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    sign = s[31] >> 7
    x = _x_recover(y)
    if x & 1 != sign:
        x = _P - x
    p = (x, y, 1, (x * y) % _P)
    # on-curve check
    xx, yy, zz, tt = p
    if (-xx * xx + yy * yy - zz * zz - _D * tt * tt) % _P != 0:
        raise SignatureError("public key is not a valid curve point")
    return p


def _point_equal(p, q) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _verify_pure_python(message: bytes, sig: bytes, key: bytes) -> bool:
    try:
        a = _decode_point(key)
        r = _decode_point(sig[:32])
    except SignatureError:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + key + message).digest(), "little") % _L
    return _point_equal(_scalar_mult(_B, s), _edwards_add(r, _scalar_mult(a, h)))


# ---------------------------------------------------------------------------
# Batch envelope
# ---------------------------------------------------------------------------

REQUIRED_ENVELOPE_KEYS = (
    "schema_version",
    "collector_id",
    "collector_version",
    "module",
    "module_version",
    "client",
    "sequence",
    "nonce",
    "collected_at",
    "observations",
)

SCHEMA_VERSION = 1


def validate_envelope(envelope: dict) -> list[str]:
    """Structural validation. Returns a list of problems; empty means valid."""
    problems: list[str] = []
    if not isinstance(envelope, dict):
        return ["envelope must be a JSON object"]

    for key in REQUIRED_ENVELOPE_KEYS:
        if key not in envelope:
            problems.append(f"missing required field: {key}")

    sv = envelope.get("schema_version")
    if sv is not None and sv != SCHEMA_VERSION:
        problems.append(f"unsupported schema_version {sv} (this build accepts {SCHEMA_VERSION})")

    seq = envelope.get("sequence")
    if seq is not None and (not isinstance(seq, int) or isinstance(seq, bool) or seq < 0):
        problems.append("sequence must be a non-negative integer")

    obs = envelope.get("observations")
    if obs is not None:
        if not isinstance(obs, list):
            problems.append("observations must be an array")
        elif not obs:
            problems.append("observations array is empty")
        else:
            for idx, o in enumerate(obs[:2000]):
                if not isinstance(o, dict):
                    problems.append(f"observations[{idx}] is not an object")
                    continue
                for req in ("fact_key", "value"):
                    if req not in o:
                        problems.append(f"observations[{idx}] missing {req}")

    nonce = envelope.get("nonce")
    if nonce is not None and (not isinstance(nonce, str) or len(nonce) < 16):
        problems.append("nonce must be a string of at least 16 characters")

    return problems


def signing_payload(envelope: dict) -> dict:
    """
    The exact subset that gets signed. Excludes the signature itself and any
    server-added fields, so a collector and the server always sign the same
    object regardless of transport additions.
    """
    return {k: envelope[k] for k in REQUIRED_ENVELOPE_KEYS if k in envelope}


def to_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), default=str)
