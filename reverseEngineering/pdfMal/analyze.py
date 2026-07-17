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
    xmeta = r.xmp_metadata

    print("=== Overview ===")
    print(f"File Name: {sys.argv[1]}")
    print("Content:\n"+page.extract_text())


    print("\n=== Metadata ===")
    print(f"Title: {meta.title}")
    print(f"Author: {meta.author}")
    print(f"Subject: {meta.subject}")
    print(f"Creator: {meta.creator}")
    print(f"Producer: {meta.producer}")
    print(f"Creation Date: {meta.creation_date}")
    print(f"Extracted UTC Offset: {str(meta.creation_date)[-6:]}")
    print(f"Modification Date: {meta.modification_date}")
    print(f"\nXMP Title: {xmeta.dc_title}")
    print(f"XMP Description: {xmeta.dc_description}")
    print(f"XMP Date: {xmeta.xmp_create_date}")
    print(f"XMP Creator: {xmeta.dc_creator}")
    print(f"PDF Producer: {xmeta.pdf_producer}")
    print(f"PDF Version: {xmeta.pdf_pdfversion}")
