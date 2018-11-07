from django.db import models
from server import TYPE, CLASS
# Create your models here.


class SOA(models.Model):
    ttl = models.IntegerField()
    name = models.TextField()
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