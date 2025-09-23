"""
unsafe_bash_bridge_append_eof.py

Safe replacement for a previously unsafe "bash bridge" watermarking method.

Original file documented calling out to shell with user-controlled inputs
(which is unsafe and enables command injection). This module implements the
same high-level behaviour (append authenticated payload after PDF EOF)
but entirely in Python (no shell invocation). If you truly need to call an
external helper, do so only with a vetted binary and fixed arguments; that
pattern is NOT implemented here.

Shen 9.20:
- Removed any use of subprocess/shell to eliminate command-injection / RCE risk.
- Implemented payload format and HMAC verification in-Python.
- Hardened payload parsing (hex validation, base64 and UTF-8 decoding checks).
- Kept API compatible with WatermarkingMethod so it can be registered in the project.
"""

from __future__ import annotations

from typing import Final
import base64
import hashlib
import hmac
import json

from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
    PdfSource,  # Shen 9.20: added for typing correctness
)


class UnsafeBashBridgeAppendEOF(WatermarkingMethod):
    """
    NOTE: This is a safe Python-only replacement for the original unsafe
    bash-bridge implementation. The class name is preserved to keep backwards
    compatibility with code that imports this symbol, but it no longer shells out.

    Format (all UTF-8):

        <original PDF bytes ...>%%EOF\n
        %%WM-BASH-BRIDGE-APPEND:v1\n
        <base64url(JSON payload)>\n

    JSON payload schema (version 1):
        {"v":1,"alg":"HMAC-SHA256","mac":"<hex>","secret":"<b64>"}

    MAC is computed over b"wm:bash-bridge-append:v1:" + secret_bytes
    using the provided key with HMAC-SHA256.
    """

    name: Final[str] = "bash-bridge-eof"

    # Constants
    _MAGIC: Final[bytes] = b"\n%%WM-BASH-BRIDGE-APPEND:v1\n"
    _CONTEXT: Final[bytes] = b"wm:bash-bridge-append:v1:"

    # ---------------------
    # Public API overrides
    # ---------------------

    @staticmethod
    def get_usage() -> str:
        # Preserve original intent text but accurate: this implementation is safe.
        return (
            "Toy method that appends a watermark record after the PDF EOF. "
            "This implementation is Python-only (no shell) and validates HMAC-SHA256."
        )

    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """
        Return a new PDF with a watermark record appended.

        The `position` parameter is accepted for API compatibility but ignored.
        Shen 9.20: removed subprocess usage and implemented payload construction in Python.
        """
        data = load_pdf_bytes(pdf)

        if not isinstance(secret, str) or not secret:
            raise ValueError("Secret must be a non-empty string")
        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        payload = self._build_payload(secret, key)

        # Append after the last EOF marker; if none is found, append at end.
        out = data
        if not out.endswith(b"\n"):
            out += b"\n"
        out += self._MAGIC + payload + b"\n"
        return out

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        # Shen 9.20: consistent with other EOF appenders - always applicable
        return True

    def read_secret(self, pdf, key: str) -> str:
        """
        Extract the secret if present and authenticated by `key`.

        Raises SecretNotFoundError when the marker/payload is not found or is malformed.
        Raises InvalidKeyError if the MAC does not validate under the given key.
        """
        data = load_pdf_bytes(pdf)

        if not isinstance(key, str) or not key:
            raise ValueError("Key must be a non-empty string")

        idx = data.rfind(self._MAGIC)
        if idx == -1:
            raise SecretNotFoundError("No BashBridgeAppendEOF watermark found")

        start = idx + len(self._MAGIC)
        # Payload ends at the next newline or EOF
        end_nl = data.find(b"\n", start)
        end = len(data) if end_nl == -1 else end_nl
        b64_payload = data[start:end].strip()
        if not b64_payload:
            raise SecretNotFoundError("Found marker but empty payload")

        try:
            payload_json = base64.urlsafe_b64decode(b64_payload)
            payload = json.loads(payload_json)
        except Exception as exc:
            # Shen 9.20: do not leak low-level parsing errors; report as malformed payload
            raise SecretNotFoundError("Malformed watermark payload") from exc

        if not (isinstance(payload, dict) and payload.get("v") == 1):
            raise SecretNotFoundError("Unsupported watermark version or format")
        if payload.get("alg") != "HMAC-SHA256":
            raise WatermarkingError(f"Unsupported MAC algorithm: {payload.get('alg')}")

        try:
            mac_hex = str(payload["mac"])
            # Validate mac is hexadecimal to avoid unexpected types
            if not isinstance(mac_hex, str) or not all(c in "0123456789abcdef" for c in mac_hex.lower()):
                raise ValueError("mac field not valid hex")

            secret_b64 = str(payload["secret"]).encode("ascii")
            secret_bytes = base64.b64decode(secret_b64)
            secret_str = secret_bytes.decode("utf-8")
        except Exception as exc:
            # Shen 9.20: normalize malformed payload field errors
            raise SecretNotFoundError("Invalid payload fields") from exc

        expected = self._mac_hex(secret_bytes, key)
        if not hmac.compare_digest(mac_hex, expected):
            raise InvalidKeyError("Provided key failed to authenticate the watermark")

        return secret_str

    # ---------------------
    # Internal helpers
    # ---------------------

    def _build_payload(self, secret: str, key: str) -> bytes:
        """Build the base64url-encoded JSON payload to append."""
        secret_bytes = secret.encode("utf-8")
        mac_hex = self._mac_hex(secret_bytes, key)
        obj = {
            "v": 1,
            "alg": "HMAC-SHA256",
            "mac": mac_hex,
            "secret": base64.b64encode(secret_bytes).decode("ascii"),
        }
        # Compact JSON for determinism
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return base64.urlsafe_b64encode(j)

    def _mac_hex(self, secret_bytes: bytes, key: str) -> str:
        """Compute HMAC-SHA256 over the contextualized secret and return hex."""
        hm = hmac.new(key.encode("utf-8"), self._CONTEXT + secret_bytes, hashlib.sha256)
        return hm.hexdigest()


__all__ = ["UnsafeBashBridgeAppendEOF"]
