from django.contrib import admin
from .models import *
from django.forms import TextInput, Textarea
# Register your models here.

class SubdomainInline(admin.TabularInline):
    model = SubDomain
    formfield_overrides = {
        models.TextField: {'widget': Textarea(attrs={'rows': 1, 'cols': 40})},
    }
    extra = 0


class SoaAdmin(admin.ModelAdmin):
    inlines = [SubdomainInline,]
    formfield_overrides = {
        models.TextField: {'widget': Textarea (attrs={'rows': 1, 'cols': 40})},
    }


admin.site.register(SOA, SoaAdmin)
# admin.site.register(SubDomain)
