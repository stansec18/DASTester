#!/usr/bin/env python3
"""Convenience entry point so DASTester runs without installation:

    python dastester.py https://example.com -I
    python dastester.py --update
"""
import sys

from dastester.cli import main

if __name__ == "__main__":
    sys.exit(main())
