#!/usr/bin/env python3
# Python 3.6.5

import argparse
import subprocess
import sys
import re
import os

def main(argv):
    def generateTOC(filename):
        return subprocess.check_output([os.path.join(os.path.dirname(__file__), 'lib/gh-md-toc'), filename]).decode()

    with open(argv.filename, 'r+') as f:
        origin_content = f.read()
        assert re.findall(r'\[TOC\]', origin_content), f'[TOC] tag is not found in {argv.filename}'
        toc = generateTOC(argv.filename)
        if argv.url:
            toc = f"**It's recommended to read our responsive [web version](https://balsn.github.io/ctf_writeup/{argv.url}/) of this writeup.**\n\n\n"+ toc
        new_content = re.sub(r'\[TOC\]', toc, origin_content)
        f.seek(0)
        f.write(new_content)
        f.truncate() #https://stackoverflow.com/questions/2424000/read-and-overwrite-a-file-in-python


def parseArgv():
    parser = argparse.ArgumentParser(prog=sys.argv[0])
    parser.add_argument('filename', type=str)
    parser.add_argument('--url', type=str)
    return parser.parse_args()

if __name__ == '__main__':
    argv = parseArgv()
    main(argv)
