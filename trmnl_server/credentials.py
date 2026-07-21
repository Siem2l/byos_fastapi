"""Constant-time secret comparison that cannot 500 on hostile input.

`hmac.compare_digest` accepts two `str` arguments only when both are pure
ASCII; anything else raises `TypeError: comparing strings with non-ASCII
characters is not supported`. Every secret this app checks arrives from the
network — the panel's `Access-Token` header, the UI secret in a header or a
JSON body, the signature half of a session cookie — and the `Access-Token`
path is reachable from the open internet, because the Pangolin edge bypasses
SSO for `/api/*` so an ESP32 can talk to it. So

    curl -H 'Access-Token: café' https://trmnl.example/api/display

turned a 401 into an unhandled 500: an availability bug on a device path, a
fingerprinting oracle for anyone probing the deployment, and a stack trace
per request in the journal.

Comparing *bytes* has no ASCII restriction, so every value is encoded first
and anything that cannot be encoded is simply "not equal". The timing
property is preserved: the comparison itself is still `compare_digest`, and
the reject paths run one anyway so they cost the same as a mismatch.

stdlib only, so `propagatedBuildInputs` stays
`pillow fastapi uvicorn httpx sqlalchemy`.
"""

from __future__ import annotations

import hmac

_EMPTY = b""


def _as_bytes(value: object) -> bytes | None:
    """UTF-8 bytes for `value`, or None if it is not comparable at all."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        try:
            # surrogatepass, not strict: a JSON body may decode to lone
            # surrogates (`{"token": "\ud800"}`), which plain UTF-8 refuses
            # to encode — another TypeError-shaped 500 if left to chance.
            return value.encode("utf-8", "surrogatepass")
        except (UnicodeEncodeError, ValueError):
            return None
    return None


def secret_equal(supplied: object, expected: object) -> bool:
    """True when `supplied` matches `expected`, in constant time.

    Never raises. `None`, a non-string, and an unencodable string are all
    just "no match", which is the answer the caller wants: the response is a
    401, never a 500.
    """
    candidate = _as_bytes(supplied)
    reference = _as_bytes(expected)
    if candidate is None or reference is None or not reference:
        # Burn one comparison so an unencodable or absent credential is not
        # distinguishable from a merely wrong one by response timing.
        hmac.compare_digest(_EMPTY, _EMPTY)
        return False
    return hmac.compare_digest(candidate, reference)
