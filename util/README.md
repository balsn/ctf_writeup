## Install

### markdown-toc-generator

Generate table of contents in Markdown.

Install: Python 3.6 is required.

### markdown-to-html

Render Markdown to stunning responsive web page with LaTeX support.

```sh
cd markdown-to-html
# Install Markdown to static HTML generator (https://github.com/mixu/markdown-styles)
npm install markdown-styles
# Install customized layout 
cp -r balsn node_modules/markdown-styles/layouts/
```

## Generate a CTF Writeup

Make sure your working directory is the root of Git repository.

### Automatically

```sh

```

### Manually

```sh
mkdir YYYYMMDD-ctfname
cp your-ctf-writeup.md YYYYMMDD-ctfname/README.md
./util/markdown-to-html/node_modules/markdown-styles/bin/generate-md --layout balsn --input YYYYMMDD-ctfname/README.md --output YYYYMMDD-ctfname
mv YYYYMMDD-ctfname/README.html YYYYMMDD-ctfname/index.html
./util/markdown-to-html/gen-sidebar.py YYYYMMDD-ctfname/index.html

./util/markdown-toc-generator/gen-toc.py YYYYMMDD-ctfname/README.md
```

## Troubleshooting

### TOC

In order to generate table of contents correctly in Markdown, your input should like this:

```markdown
# Balsn CTF

[TOC]

## Web

### web 1

## Reverse

### reverse 1
```
