# tests/test_watermarking_all_methods.py
"""
Parameterized tests for all registered watermarking methods.

Covers:
- Applicability check
- add_watermark shape and validity
- read_secret roundtrip consistency

Shen 9.20: Adjusted sample PDF to be slightly more realistic for stability,
and ensured security-focused assertions are explicit.
"""

from __future__ import annotations
import importlib
import inspect
from pathlib import Path
import pytest


# --------- collect all methods from the registry ----------
try:
    wm = importlib.import_module("watermarking_utils")
    METHODS = getattr(wm, "METHODS", {})
except Exception:  # registry/module missing
    METHODS = {}

CASES: list[tuple[str, object]] = []
for name, impl in (METHODS or {}).items():
    # Exclude intentionally unsafe method
    if name != "bash-bridge-eof" and name != "UnsafeBashBridgeAppendEOF":
        CASES.append((str(name), impl))

if not CASES:
    pytest.skip("No safe watermarking methods registered in watermarking_utils.METHODS", allow_module_level=True)


# --------- fixtures ----------
@pytest.fixture(scope="session")
def sample_pdf_path(tmp_path_factory) -> Path:
    """Minimal but recognizable PDF file for testing."""
    pdf = tmp_path_factory.mktemp("pdfs") / "sample.pdf"
    pdf.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n"
        b"%%EOF\n"
    )
    return pdf


@pytest.fixture(scope="session")
def secret() -> str:
    return "unit-test-secret"


@pytest.fixture(scope="session")
def key() -> str:
    return "unit-test-key"


def _as_instance(impl: object) -> object:
    """Return an instance for class objects; pass instances through unchanged."""
    if inspect.isclass(impl):
        return impl()  # assumes zero-arg constructor
    return impl


# --------- parameterization over all safe methods ----------
@pytest.mark.parametrize("method_name,impl", CASES, ids=[n for n, _ in CASES])
class TestAllWatermarkingMethods:
    def test_is_watermark_applicable(self, method_name: str, impl: object, sample_pdf_path: Path):
        wm_impl = _as_instance(impl)
        ok = wm_impl.is_watermark_applicable(sample_pdf_path, position=None)
        assert isinstance(ok, bool), f"{method_name}: is_watermark_applicable must return bool"
        if not ok:
            pytest.skip(f"{method_name}: not applicable to the sample PDF")

    def test_add_watermark_and_shape(self, method_name: str, impl: object, sample_pdf_path: Path, secret: str, key: str):
        wm_impl = _as_instance(impl)
        if not wm_impl.is_watermark_applicable(sample_pdf_path, position=None):
            pytest.skip(f"{method_name}: not applicable to the sample PDF")
        original = sample_pdf_path.read_bytes()
        out_bytes = wm_impl.add_watermark(sample_pdf_path, secret=secret, key=key, position=None)
        assert isinstance(out_bytes, (bytes, bytearray)), f"{method_name}: add_watermark must return bytes"
        assert len(out_bytes) >= len(original), f"{method_name}: watermarked bytes should not be smaller than input"
        assert out_bytes.startswith(b"%PDF-"), f"{method_name}: output should still look like a PDF"

    def test_read_secret_roundtrip(self, method_name: str, impl: object, sample_pdf_path: Path, secret: str, key: str, tmp_path: Path):
        wm_impl = _as_instance(impl)
        if not wm_impl.is_watermark_applicable(sample_pdf_path, position=None):
            pytest.skip(f"{method_name}: not applicable to the sample PDF")
        out_pdf = tmp_path / f"{method_name}_watermarked.pdf"
        out_pdf.write_bytes(wm_impl.add_watermark(sample_pdf_path, secret=secret, key=key, position=None))
        extracted = wm_impl.read_secret(out_pdf, key=key)
        assert isinstance(extracted, str), f"{method_name}: read_secret must return str"
        assert extracted == secret, f"{method_name}: read_secret should return the exact embedded secret"
