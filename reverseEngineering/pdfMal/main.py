#!/bin/python3

import sys
import argparse
from pypdf import PdfReader, PdfWriter

if __name__ == "__main__":
    if len(sys.argv) > 1:
        f = sys.argv[1]
    else: sys.exit("Missing pdf")

    r = PdfReader(f)
    page = r.pages[0]

    out = PdfWriter()
    out.metadata = None
    out.add_page(page)
    #out.add_js("<script>alert(1)</script>")
    out.add_js("app.alert('You have been pwned. Enjoy this virus!', 3);")

    with open("out.pdf", "wb") as file:
        out.write(file)
