# PDF Malware Testing

## Overview

This is a small project in PDF analysis and malware. The `main.py` program takes a file path as input and
inserts a JavaScript payload set to run on open. The `-a` or `--analyze` flag instead reads the contents and metadata of the input filepath. Optionally, using `-o [outfile]` (default=./out.pdf) will allow the user to specify an output file path.

The `-n` or `--nocontent` flag will, when the analyze flag is used, the content of the pdf file will not be printed.

The `-d` or `--scandir` flag will instead require a directory to be passed as input, scanning it for pdf files, then analyzing them. The analysis will be outputted to the outfile.

The `-p` or `--payload` flag will take a file path containing a JavaScript payload to insert. The default is a simple alert.

Install with `pip install -r requirements.txt` and run `python3 main.py path/to/file.pdf`

## TODO

- Better PDF analysis (e.g. extract any payloads)  
