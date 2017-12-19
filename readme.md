# CryptoPing
CryptoPing is python tool to send and receive encrypted messages/files over ICMP protocol. CryptoPing uses ICMP ECHO REQUEST and ECHO REPLAY data fields. Communication handshake will be over RSA, where client and server exchange public keys. After handshake, all the communication will be encrypted with AES.

## Example
```
ping.py client <destination (server)IP>
ping.py server <destination (client)IP>
```
#### +Note+
**In _Linux_ ping.py can be used with client and server mode. In _Windows_ is available only client mode.**

## Overview
- client:
  - Using ICMP ECHO REQUEST

- server:
  - Using ICMP ECHO REPLY

