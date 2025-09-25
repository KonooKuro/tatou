# -*- coding: utf-8 -*-

from __future__ import annotations

from typing import Optional
import io
import base64

from watermarking_method import (
    PdfSource,
    WatermarkingError,
    SecretNotFoundError,
    load_pdf_bytes,
    WatermarkingMethod,
)

# 第三方
try:
    import pikepdf
except Exception:  # pragma: no cover
    pikepdf = None

# ------------ 常量 ------------
SUBTYPE = "/XML"
ALG_NAME = "/Filter"
VERSION = "PDF-1.4"
HIDDEN_KEY_NAME = pikepdf.Name("/ColorSpace")

def _require_deps():
    if pikepdf is None:
        raise WatermarkingError("需要安装 pikepdf：pip install pikepdf")


class HiddenObjectB64Method(WatermarkingMethod):
    """
    将 Base64 编码后的密文放入一个不被引用的流对象中（孤立对象）。
    读取时遍历所有间接对象，匹配标记并解码。
    """
    name: str = "Hide_Watermark"

    @staticmethod
    def get_usage() -> str:
        return (
            "A method that hide watermark in the PDF."
        )

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        position: Optional[str] = None # 未使用
    ) -> bytes:
        _require_deps()
        if not secret:
            raise ValueError("Secret cannot be empty")

        data = load_pdf_bytes(pdf)
        try:
            with pikepdf.open(io.BytesIO(data)) as doc:
                root = doc.trailer.get("/Root")  # PDF Catalog
                meta = pikepdf.Dictionary({
                    "/Subtype": pikepdf.Name(SUBTYPE),
                })
                # 无引用对象
                payload = base64.urlsafe_b64encode(secret.encode("utf-8"))

                # --- 兼容多版本 pikepdf 的“新增孤立流对象” ---
                if hasattr(doc, "make_stream"):
                    # 新版 pikepdf：直接创建并登记为间接流对象
                    _ref = doc.make_stream(payload, meta)
                else:
                    # 老版本：先构造 Stream，再用 make_indirect 挂进 xref（不建立任何引用）
                    stream = pikepdf.Stream(doc, payload, meta)
                    if hasattr(doc, "make_indirect"):
                        _ref = doc.make_indirect(stream)
                    else:
                        raise WatermarkingError(
                            "当前 pikepdf 过旧，既无 make_stream 也无 make_indirect；"
                            "请运行 `pip install -U pikepdf` 升级"
                        )
                if root is None:
                    raise WatermarkingError("PDF 缺少 /Root 对象，无法挂接隐藏对象")
                root[HIDDEN_KEY_NAME] = _ref

                out = io.BytesIO()
                doc.save(out)
                return out.getvalue()

        except Exception as e:
            raise WatermarkingError(f"failed to write watermark: {e}") from e

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: Optional[str] = None,
    ) -> bool:
        if pikepdf is None:
            return False
        try:
            data = load_pdf_bytes(pdf)
            with pikepdf.open(io.BytesIO(data)):
                return True
        except Exception:
            return False

    def read_secret(self, pdf: PdfSource) -> str:
        _require_deps()

        data = load_pdf_bytes(pdf)
        try:
            with pikepdf.open(io.BytesIO(data)) as doc:
                # 先尝试从 /Root 的隐蔽引用直接读取（若存在）
                try:
                    root = doc.trailer.get("/Root")
                    if root is not None:
                        ref = root.get(HIDDEN_KEY_NAME, None)

                        if isinstance(ref, pikepdf.Stream):
                            encoded = ref.read_bytes()
                            return base64.urlsafe_b64decode(encoded).decode("utf-8")

                        # 某些版本返回的是一个“间接引用”，再解引用一次
                        if ref is not None:
                            try:
                                stream_obj = pikepdf.Stream(doc, ref)
                                encoded = stream_obj.read_bytes()
                                return base64.urlsafe_b64decode(encoded).decode("utf-8")
                            except Exception:
                                pass
                except Exception:
                    # 忽略 Root 路径的错误，退回到全量扫描
                    pass

                # 兜底：遍历所有对象（包含无引用对象）
                found_any = False
                last_err: Optional[Exception] = None

                for obj in doc.objects:
                    if not isinstance(obj, pikepdf.Stream):
                        continue
                    try:
                        subtype = obj.get("/Subtype", None)
                        alg = obj.get("/Alg", None)
                        if subtype != pikepdf.Name(SUBTYPE) or alg != pikepdf.Name(ALG_NAME):
                            continue

                        found_any = True
                        encoded = obj.read_bytes()
                        try:
                            text = base64.urlsafe_b64decode(encoded).decode("utf-8")
                            return text
                        except Exception as e:
                            last_err = e
                            continue
                    except Exception as e:
                        last_err = e
                        continue

            if found_any and last_err is not None:
                raise SecretNotFoundError(f"failed to decode: {last_err}")
            raise SecretNotFoundError("No watermark found")
        except SecretNotFoundError:
            raise
        except Exception as e:
            raise SecretNotFoundError(f"Read watermark failed: {e}")



# 工厂实例（供注册表使用）
METHOD_INSTANCE = HiddenObjectB64Method()
