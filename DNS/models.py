from django.db import models
# from server import TYPE, CLASS
# Create your models here.


class SOA(models.Model):
    ttl = models.IntegerField()
    name = models.TextField(unique=True)
    ns = models.TextField()
    email = models.EmailField()
    serial = models.IntegerField()
    refresh = models.TextField()
    retry = models.TextField()
    expire = models.TextField()
    negative_cache_ttl = models.TextField()


class SubDomain(models.Model):
    soa = models.ForeignKey(SOA, on_delete=models.CASCADE, related_name='subdomain')
    name = models.TextField()
    type = models.IntegerField()
    dns_class = models.IntegerField()
    target = models.TextField()

    def to_dns_dict(self):
        return {'answer1': {
                'name': self.name + '.' + self.soa.name,
                'type': self.type,
                'class': self.dns_class,
                'ttl': self.soa.ttl,
                'rdlength': 4,
                'rdata': self.target
            }}
