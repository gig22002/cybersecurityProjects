# Copy Fail Testing

In order to better understand the payload for the Copy Fail exploit, here I de-obfuscate the space-optimized code provided by Xint.

Variables and function names are translated to be more human-readable, and comments are added with succinct description and applicable translation.

The goal of this project was to better understand the complicated exploit, as the kernel-level sockets and memory operations did not immediately make sense after reading the write up. After analyzing the code line by line to figure out its functionality and purpose, I have a much better grasp of how the Copy Fail works.

https://github.com/theori-io/copy-fail-CVE-2026-31431/blob/main/copy_fail_exp.py
