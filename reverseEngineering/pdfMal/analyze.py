#!/bin/python3

import sys
from pypdf import PdfReader, PdfWriter

if __name__ == "__main__":
    if len(sys.argv) > 1:
        f = sys.argv[1]
    else: sys.exit("Missing pdf")

    r = PdfReader(f)
    page = r.pages[0]

    meta = r.metadata

    print("=== Metadata ===")
    print(meta.title)
    print(meta.author)
    print(meta.subject)
    print(meta.creator)
    print(meta.producer)
    print(meta.creation_date)
    print(meta.modification_date)

