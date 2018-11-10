# pydns
Python DNS Server. Implementation of [IETF Domain Names](https://tools.ietf.org/html/rfc1035)
Managed by Django ORM
### Warning! pydns needs to have root privileges to run on 53 port

### Roadmap 

- [x] UDP Server

- [x] Response with AUTHORITY and ADDITIONAL

- [ ] All responses

- [ ] Reversed zone

- [ ] Truncation

- [ ] TCP Server

- [ ] Recursion

- [ ] Master / Slave implementation

- [ ] DNSSEC

##Responses
** *
### TYPES
- [x] A
- [x] NS
- [ ] MD
- [ ] MF
- [x] CNAME
- [ ] SOA
- [x] MB
- [x] MG
- [x] MR 
- [ ] NULL
- [ ] WKS
- [ ] PTR
- [X] HINFO
- [ ] MINFO
- [ ] MX
- [x] TXT
### QTYPES
- [ ] AXFR
- [ ] MAILB
- [ ] MAILA
- [ ] \* 
### CLASSES
- [ ] IN
- [ ] CS
- [ ] CH
- [ ] HS
### QCLASSES
- [ ] \*
** *