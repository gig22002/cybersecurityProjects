#!/bin/python3

import sys, os
import argparse
from pypdf import PdfReader, PdfWriter

def CreateArgs():
    parser = argparse.ArgumentParser(description="A tool to analyze pdfs and create sample malware for testing purposes.")

    #input file
    parser.add_argument("input", help="Input pdf to inject or analyze.")

    #output file
    parser.add_argument("-o", "--output", type=str, default="./out.pdf", help="File name to output injected pdf.")

    #payload file
    parser.add_argument("-p", "--payload", type=str, default=None, help="Optional file name for a specified payload.")

    #analyze flag
    parser.add_argument("-a", "--analyze", action="store_true", help="Flag that, when set, analyzes the input pdf instead of injecting it.")

    #dir flag
    parser.add_argument("-d", "--scandir", action="store_true", help="Whether to scan a directory (outputting to greppable file) or not.")

    #skip content flag
    parser.add_argument("-n", "--nocontent", action="store_true", help="When this flag is set, analyzing a pdf does not output its text content.")

    return parser

def ScanDir(path, out="out.txt", n=False):
    ''' Scan a directory for pdf analysis '''
    outF = open(out, "w")
    stdout = sys.stdout
    sys.stdout = outF
    print(f"<==> Scanning {path} <==>")
    print(f"OUTPUT PATH: {out}")
    print(f"NO CONTENT: {n}\n")

    for f in os.scandir(path):
        if not f.is_file(): continue
        #obtain file name
        fname = os.path.basename(f.name)
        fname = f"{path}/{fname}"

        #skip if not pdf
        if fname[-3:].lower() != "pdf": continue
        print(fname)

        #read and analyze
        r = PdfReader(fname)
        Analyzer(r, n)
        print("--------------------------------")

    sys.stdout = stdout
    outF.close()

def Analyzer(r, n=False):
    ''' Analyze a PDF page '''
    page = r.pages[0]

    meta = r.metadata

    print("=== Overview ===")
    print(f"File Name: {sys.argv[1]}")
    if (not n): print("Content:\n"+page.extract_text())

    try:
        print("\n=== Metadata ===")
        print(f"Title: {meta.title}")
        print(f"Author: {meta.author}")
        print(f"Subject: {meta.subject}")
        print(f"Creator: {meta.creator}")
        print(f"Producer: {meta.producer}")
        print(f"Creation Date: {meta.creation_date}")
        print(f"Extracted UTC Offset: {str(meta.creation_date)[-6:]}")
        print(f"Modification Date: {meta.modification_date}")
    except:
        print("\nFailed to extract metadata.")
    try:
        xmeta = r.xmp_metadata
        print(f"\nXMP Title: {xmeta.dc_title}")
        print(f"XMP Description: {xmeta.dc_description}")
        print(f"XMP Date: {xmeta.xmp_create_date}")
        print(f"XMP Creator: {xmeta.dc_creator}")
        print(f"PDF Producer: {xmeta.pdf_producer}")
        print(f"PDF Version: {xmeta.pdf_pdfversion}") 
    except:
        print("\nNo XMP data found.")

def InjectPayload(page, payload):
    out = PdfWriter()
    out.metadata = None
    out.add_page(page)
    out.add_js(payload)

    with open(outF, "wb") as file:
        out.write(file)

if __name__ == "__main__":
    #create args
    parser = CreateArgs()
    args = parser.parse_args()

    f = str(args.input)
    outF = args.output
    analyze = args.analyze
    scandir = args.scandir
    nocontent = args.nocontent
    #obtain payload
    payloadF = args.payload
    try:
        with open(payloadF, "r") as js:
            payload = js.read()
    except:
        print("Failed to open payload file.")
        payload="app.alert('You have been pwned. Enjoy this virus!', 3);"

    #read pdf
    if (not scandir):
        r = PdfReader(f)
        page = r.pages[0]

    if (not analyze):
        InjectPayload(page, payload)
        print(f"Injected payload {payload} to file {outF}")
    elif (analyze and scandir):
        ScanDir(f, outF, nocontent)
    else:
        Analyzer(r, nocontent)
