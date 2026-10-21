import dataclasses
import importlib.metadata
from typing import Any

project = "Nitrokey Python SDK"
copyright = "2024, Nitrokey"
author = "Nitrokey"
release = "0.1.0"
extensions = ["sphinx.ext.autodoc"]
html_theme = "alabaster"
autodoc_class_signature = "separated"
autodoc_member_order = "groupwise"
autodoc_typehints = "description"


nitrokey_sdk_version = importlib.metadata.version("nitrokey")
rst_epilog = f".. |nitrokey_sdk_version| replace:: v{nitrokey_sdk_version}"


def _drop_generated_dataclass_docstring(
    app: Any, what: str, name: str, obj: Any, options: Any, lines: list[str]
) -> None:
    """
    Drop the signature docstring that Python adds to dataclasses without one.
    """
    if what not in ("class", "exception") or not dataclasses.is_dataclass(obj):
        return
    content = [line for line in lines if line.strip()]
    if len(content) == 1 and content[0].startswith(f"{obj.__name__}(") and content[0].endswith(")"):
        lines.clear()


def setup(app: Any) -> None:
    app.connect("autodoc-process-docstring", _drop_generated_dataclass_docstring)
