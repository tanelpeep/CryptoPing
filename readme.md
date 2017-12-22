# CryptoPing
CryptoPing is python tool to send and receive encrypted messages/files over ICMP protocol. CryptoPing uses ICMP ECHO REQUEST and ECHO REPLAY data fields. Communication handshake will be over RSA, where client and server exchange public keys. After handshake, all the communication will be encrypted with AES.

## Example
```
ping.py client <destination (server)IP>
ping.py server <destination (client)IP>
```

**In _Linux_ ping.py can be used with client and server mode. In _Windows_ is available only client mode.**

## Overview
- client:
  - Using ICMP ECHO REQUEST

- server:
  - Using ICMP ECHO REPLY

## Handshake
<p align="center">
  <img height="346px" width="216px" src="https://i.imgur.com/lhjTNXs.png" />
</p>

## Versions

- [x] 1.0 - Send and receive messages over ICMP (not encrypted)
- [x] 2.0 - Send and receive secure messages over ICMP (encrypted)
- [ ] 3.0 - Send and receive files

## Tasks

- [ ] Server mode listening (accept incoming connection)
- [ ] Secure and insecure option for communication
- [ ] Optimizing code
