#!/usr/bin/env bash
set -e

if [ $# -ne 2 ]; then
    echo "Usage: ./util/gen.sh YYYYMMDD-ctfname your-ctf-writeup.md"
    exit -1
fi

root_dir=`git rev-parse --show-toplevel`
ctf_dir="$root_dir/$1"
md="$2"

mkdir $ctf_dir
cp $md $ctf_dir/README.md
$root_dir/util/markdown-to-html/node_modules/markdown-styles/bin/generate-md \
  --layout balsn \
  --input $ctf_dir/README.md \
  --output $ctf_dir
sed -r 's/^<p>\[TOC\]<\/p>$//' -i $ctf_dir/README.html
mv $ctf_dir/README.html $ctf_dir/index.html
$root_dir/util/markdown-to-html/gen-sidebar.py $ctf_dir/index.html
$root_dir/util/markdown-toc-generator/gen-toc.py $ctf_dir/README.md --url "$1"

echo "Generate index page......"
$root_dir/util/genindex.sh > $root_dir/README.md
$root_dir/util/markdown-to-html/node_modules/markdown-styles/bin/generate-md \
  --layout balsn \
  --input $root_dir/README.md \
  --output $root_dir
mv $root_dir/README.html $root_dir/index.html
$root_dir/util/markdown-to-html/gen-sidebar.py $root_dir/index.html
sed -i '1,16s/\.\.\/assets/assets/' $root_dir/index.html

