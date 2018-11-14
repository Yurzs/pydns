import socket
from dns_objects import Message
from DNS.models import SubDomain, SOA
from rdata import TYPE
import random
import dns.resolver
import json


def send_request(host:str, port:int, request:bytes):
    """
    Sends DNS request to DNS server
    :param host: IP address of DNS server
    :param port: Port of DNS server
    :param request: Message object
    :return: DNS response
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(request, (host, port))
    return sock.recv(1024)

if __name__ == '__main__':
    result = {}
    for rdata_type in TYPE:
        try:
            soa = SOA.objects.get(name='testzone')
            try:
                if not rdata_type == 6:
                    subdomain = soa.subdomain.get(name='test', type=rdata_type)
            except SubDomain.DoesNotExist:
                soa.subdomain.create(name='test', type=rdata_type, dns_class=1, target='test.testzone')
            myResolver = dns.resolver.Resolver ()
            myResolver.nameservers = ['80.211.196.34',]
            myAnswers = myResolver.query ("test.testzone", TYPE[rdata_type].__name__.upper())
            result.update ({TYPE[rdata_type].__name__.upper (): True})
        except:
            result.update({TYPE[rdata_type].__name__.upper(): False})
        # result = send_request (host='localhost', port=53, request=message.to_bin ().bytes)
    print(json.dumps(result,indent=4))