from django.db import models

# from server import TYPE, CLASS
# Create your models here.


class SOA(models.Model):
    ttl = models.TimeField()
    name = models.TextField(unique=True)
    ns = models.TextField()
    email = models.EmailField()
    serial = models.IntegerField()
    refresh = models.TimeField()
    retry = models.TimeField()
    expire = models.TimeField()
    negative_cache_ttl = models.TimeField()

    def __str__(self):
        return self.name

    @property
    def dns_dict(self):
        from dns_objects import int16,int32, UrlAddress,IpAddress, Message
        return {'name': UrlAddress(self.name),
                'type': int16(6),
                'class': int16(1),
                'ttl': int32((self.refresh.hour * 60 + self.refresh.minute) * 60 + self.refresh.second),
                'rdlength': int16(99),
                'rdata': Message.Rdata.Soa(self)}




class SubDomain(models.Model):
    soa = models.ForeignKey(SOA, on_delete=models.CASCADE, related_name='subdomain')
    name = models.TextField()
    type = models.IntegerField(choices=((1, 'A'), (2, 'NS'), (3, 'MD'), (4, 'MF'), (5, 'CNAME'), (6, 'SOA'), (7, 'MB'),
                                        (8, 'MG'), (9, 'MR'), (10, 'NULL'), (11, 'WKS'), (12, 'PTR'), (13, 'HINFO'),
                                        (14, 'MINFO'), (15, 'MX'), (16, 'TXT')))
    dns_class = models.IntegerField(choices=((1, 'IN'), (2, 'CS'), (3, 'CH'), (4, 'HS')))
    target = models.TextField()


    def __str__(self):
        return self.name + '.' + self.soa.name

    @property
    def dns_dict(self):
        from dns_objects import int16, int32, UrlAddress, IpAddress, Message
        import rdata
        if self.type == 2:
            name = self.soa.name
        else:
            name = self.name + '.' + self.soa.name if not self.name == '@' else self.soa.name
        return {
                'name': UrlAddress(name),
                'type': int16(self.type),
                'class': int16(self.dns_class),
                'ttl': int32((self.soa.ttl.hour * 60 + self.soa.ttl.minute) * 60 + self.soa.ttl.second),
                'rdlength': int16(4),
                'rdata': rdata.TYPE[self.type] (self)
            }

    def ns_dns_dict(self):
        result = {}
        for n, ns in enumerate(self.soa.objects.get().subdomain.filter(type=2)):
            result.update ({
                'authority'+ str(n): {
                    'name': self.name + '.' + self.soa.name,
                    'type': 2,
                    'class': 1,
                    'ttl': self.soa.ttl,
                    'rdlength': 4,
                    'rdata': self.target
                }
        })


