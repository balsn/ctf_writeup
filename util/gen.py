#!/usr/bin/env python3
# Python 3.6.4

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
        toc = generateTOC(argv.filename)
        new_content = re.sub(r'\[TOC\]', toc, origin_content)
        f.seek(0)
        f.write(new_content)
        f.truncate() #https://stackoverflow.com/questions/2424000/read-and-overwrite-a-file-in-python


def parseArgv():
    parser = argparse.ArgumentParser(prog=sys.argv[0])
    parser.add_argument('filename', type=str)
    return parser.parse_args()

if __name__ == '__main__':
    argv = parseArgv()
    main(argv)
