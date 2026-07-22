#!/bin/python3

import sys
import argparse
from pypdf import PdfReader, PdfWriter

def CreateArgs():
    parser = argparse.ArgumentParser(description="A tool to analyze pdfs and create sample malware for testing purposes.")

    #input file
    parser.add_argument("input", help="Input pdf to inject or analyze")

    #output file
    parser.add_argument("-o", "--output", type=str, default="./out.pdf", help="File name to output injected pdf")

    #analyze flag
    parser.add_argument("-a", "--analyze", action="store_true", help="Flag that, when set, analyzes the input pdf instead of injecting it.")

    return parser

def Analyzer(reader):
    ''' Analyze a PDF page '''
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
    try:
        print(f"\nXMP Title: {xmeta.dc_title}")
        print(f"XMP Description: {xmeta.dc_description}")
        print(f"XMP Date: {xmeta.xmp_create_date}")
        print(f"XMP Creator: {xmeta.dc_creator}")
        print(f"PDF Producer: {xmeta.pdf_producer}")
        print(f"PDF Version: {xmeta.pdf_pdfversion}") 
    except:
        print("\nNo XMP data found.")

def InjectPayload(page):
    out = PdfWriter()
    out.metadata = None
    out.add_page(page)
    out.add_js("app.alert('You have been pwned. Enjoy this virus!', 3);")

    with open(outF, "wb") as file:
        out.write(file)

if __name__ == "__main__":
    #create args
    parser = CreateArgs()
    args = parser.parse_args()

    f = str(args.input)
    outF = args.output
    analyze = args.analyze

    #read pdf
    r = PdfReader(f)
    page = r.pages[0]

    if (not analyze):
        InjectPayload(page)
    else:
        Analyzer(r)
