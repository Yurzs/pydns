import unittest
from dns_objects import Message
from rdata import TYPE
from client import send_request
import pydns
pydns.setup()
from DNS.models import SOA, SubDomain
import random
import dns.resolver

class TestAllTypes(unittest.TestCase):
    def test_type(self):
        for rdata_type in TYPE:
            try:
                soa = SOA.objects.get (name='testzone')
                try:
                    if not rdata_type == 6:
                        subdomain = soa.subdomain.get (name='test', type=rdata_type)
                except SubDomain.DoesNotExist:
                    soa.subdomain.create (name='test', type=rdata_type, dns_class=1, target='test.testzone')
                myResolver = dns.resolver.Resolver ()
                myResolver.nameservers = ['80.211.196.34', ]
                myAnswers = myResolver.query ("test.testzone", TYPE[rdata_type].__name__.upper ())
                answer = True
            except:
                answer = False
            self.assertTrue(answer, TYPE[rdata_type].__name__.upper ())




