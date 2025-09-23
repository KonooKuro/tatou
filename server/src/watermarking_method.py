# -*- coding: utf-8 -*-
"""
watermarking_method.py

Abstract base classes and common utilities for PDF watermarking methods.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import IO, TypeAlias, Union
import os

# ----------------------------
# Public type aliases & errors
# ----------------------------

PdfSource: TypeAlias = Union[bytes, str, os.PathLike[str], IO[bytes]]
"""Accepted input type for a PDF document.

Implementations should *not* assume the input is a file path; always call
:func:`load_pdf_bytes` to normalize a :class:`PdfSource` into
``bytes`` before processing.
"""


class WatermarkingError(Exception):
    """Base class for all watermarking-related errors."""


class SecretNotFoundError(WatermarkingError):
    """Raised when a watermark/secret cannot be found in the PDF."""


class InvalidKeyError(WatermarkingError):
    """Raised when the provided key does not validate/decrypt correctly."""


# ----------------------------
# Helper functions
# ----------------------------

def load_pdf_bytes(src: PdfSource) -> bytes:
    """Normalize a :class:`PdfSource` into raw ``bytes``."""
    if isinstance(src, (bytes, bytearray)):
        data = bytes(src)
    elif isinstance(src, (str, os.PathLike)):
        with open(os.fspath(src), "rb") as fh:
            data = fh.read()
    elif hasattr(src, "read"):
        data = src.read()  # type: ignore[attr-defined]
    else:
        raise TypeError("Unsupported PdfSource; expected bytes, path, or binary IO")

    if not is_pdf_bytes(data):
        raise ValueError("Input does not look like a valid PDF (missing %PDF header)")
    return data


def is_pdf_bytes(data: bytes) -> bool:
    """Lightweight check that the data looks like a PDF file."""
    return data.startswith(b"%PDF-")


# ---------------------------------
# Abstract base class (the contract)
# ---------------------------------

class WatermarkingMethod(ABC):
    """Stable contract that concrete methods must implement."""

    # user-visible identifier for CLI (e.g., "hidden-object-b64")
    name: str = "abstract"

    @staticmethod
    @abstractmethod
    def get_usage() -> str:
        """Return a short human-readable usage string."""
        raise NotImplementedError

    @abstractmethod
    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        position: str | None = None,
    ) -> bytes:
        """Embed `secret` into `pdf` and return a new PDF as bytes."""
        raise NotImplementedError

    @abstractmethod
    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: str | None = None,
    ) -> bool:
        """Return whether the method is applicable to the given PDF."""
        raise NotImplementedError

    @abstractmethod
    def read_secret(self, pdf: PdfSource) -> str:
        """Extract and return the embedded secret from `pdf`."""
        raise NotImplementedError


__all__ = [
    "PdfSource",
    "WatermarkingError",
    "SecretNotFoundError",
    "InvalidKeyError",
    "load_pdf_bytes",
    "is_pdf_bytes",
    "WatermarkingMethod",
]
