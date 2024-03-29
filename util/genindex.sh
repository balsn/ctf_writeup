#!/usr/bin/env bash
set -e

root_dir=`git rev-parse --show-toplevel`
cd $root_dir

toc_list=""
for i in `ls -d [0-9]*/ | sort -g | tac | sed 's/\/$//'`; do
  toc_list="$toc_list- [$i]($i/)"$'\n'
done

cat << EOF
# Balsn CTF writeups

Balsn is CTF team from Taiwan founded in 2016. We actively participate in CTF competitions, and publish writeups on challenges.
The writeups are in markdown + kaTeX format in our GitHub repository [balsn/ctf_writeup](https://github.com/balsn/ctf_writeup).

For more information, please refer to [our website](https://balsn.tw/).

## Table of Contents

$toc_list

## Questions

If you have any question regarding our writeups, please feel free to [create an issue](https://github.com/balsn/ctf_writeup/issues) in the writeup repository.

EOF
