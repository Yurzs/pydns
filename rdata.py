from dns_objects import Message

TYPED = {
    1: 'A',
    2: 'NS',
    3: 'MD',
    4: 'MF',
    5: 'CNAME',
    6: 'SOA',
    7: 'MB',
    8: 'MG',
    9: 'MR',
    10: 'NULL',
    11: 'WKS',
    12: 'PRT',
    13: 'HINFO',
    14: 'MINFO',
    15: 'MX',
    16: 'TXT'
}



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
