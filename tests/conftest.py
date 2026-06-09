"""Shared pytest setup — make the project's modules importable.

validation.py lives at the repo root; the scan/RAG modules live under backend/.
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BACKEND = os.path.join(_ROOT, "backend")

for path in (_ROOT, _BACKEND):
    if path not in sys.path:
        sys.path.insert(0, path)
