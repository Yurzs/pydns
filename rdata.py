from dns_objects import Message

TYPE = {
    1: Message.Rdata.A,
    2: Message.Rdata.Ns,
    3: Message.Rdata.Md,
    4: Message.Rdata.Mf,
    5: Message.Rdata.Cname,
    6: Message.Rdata.Soa,
    7: Message.Rdata.Mb,
    8: Message.Rdata.Mg,
    9: Message.Rdata.Mr,
    10: Message.Rdata.Null,
    11: Message.Rdata.Wks,
    12: Message.Rdata.Ptr,
    13: Message.Rdata.Hinfo,
    14: Message.Rdata.Minfo,
    15: Message.Rdata.Mx,
    16: Message.Rdata.Txt
        }



QTYPE = {
    252: 'AXFR',
    253: 'MAILB',
    254: 'MAILA'
}

CLASS = {
    1: 'IN',
    2: 'CS',
    3: 'CH',
    4: 'HS'
}
