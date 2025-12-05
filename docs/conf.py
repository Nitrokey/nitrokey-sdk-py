import importlib.metadata

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
