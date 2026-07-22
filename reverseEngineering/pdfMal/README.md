# PDF Malware Testing

## Overview

This is a small project in PDF analysis and malware. The `main.py` program takes a file path as input and
inserts a JavaScript payload set to run on open. The `-a` or `--analyze` flag instead reads the contents and metadata of the input filepath. Optionally, using `-o [outfile]` will allow the user to specify an output file path.

Install with `python3 -r requirements.txt` and run `python3 main.py path/to/file.pdf`

## TODO

- Custom payload support (involves deeper understanding of JS scripting)  
- Better PDF analysis (e.g. extract any payloads)  
