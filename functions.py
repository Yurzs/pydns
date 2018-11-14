from bitstring import BitArray
import re
import pydns
pydns.setup()
from DNS.models import *


def queryset_to_dict(query_set):
    """
    Converts QuerySet of SubDomain to dict of answers
    :param query_set: QuerySet of SubDomain
    :return: dictionary with answerX elements
    """
    answers = {}
    for n, item in enumerate(query_set):
        answers.update({
            'answer'+ str(n): item.dns_dict})
    return answers


def soa_to_dict(soa) -> dict:
    """
    Converts Soa object to answer record
    :param soa: Soa object
    :return: dict of 1 answer
    """
    return {'answer0': soa.dns_dict}


def ns_to_dict(ns) -> dict:
    """
    Converts NameServers QuerySet to dict of authorities and additional records
    :param ns: QuerySet of SubDomain
    :return:
    """
    ns_dict = {}
    for n, nameserver in enumerate(ns):
        ns_dict.update({'authority'+str(n): nameserver.dns_dict})
        try:
            ns_dict.update ({'additional' + str (n): SubDomain.objects.get(name=nameserver.name,
                                                                           type=1,
                                                                           soa=nameserver.soa).dns_dict})
        except SubDomain.DoesNotExist:
            pass
    return ns_dict


def find_in_db(label, qtype, qclass):
    """
    Searches in database for subdomain or a SOA record by its type (A, NS, TXT, etc.) and class (IN, CH, etc.)
    :param label: domain name
    :param qtype: QTYPE of record . For example TXT
    :param qclass: QCLASS of record. Usually IN (Internet)
    :return: subdomain, SOA, NameServers
    """
    previous = None
    root = {}
    ns = {}
    searched_soa = False
    for domain in reversed(label.split('.')):
        if root and not qtype == 6:
            searched_soa = True
            try:
                subdomain = root.subdomain.filter(name=domain, type=qtype, dns_class=qclass)
                if not subdomain:
                    raise SubDomain.DoesNotExist
                ns = root.subdomain.filter(type=2)
                return subdomain, root, ns
            except SubDomain.DoesNotExist:
                previous = '.'.join([domain, previous]) if previous else domain
                try:
                    subdomain = root.subdomain.filter(name=previous, type=qtype, dns_class=qclass)
                    if not subdomain:
                        raise SubDomain.DoesNotExist
                    ns = root.subdomain.filter (type=2)
                    return subdomain, root, ns
                except SubDomain.DoesNotExist:
                    continue
        elif not root:
            try:
                root = SOA.objects.get(name=domain)
                previous = None
            except SOA.DoesNotExist:
                previous = '.'.join([domain, previous]) if previous else domain
                try:
                    root = SOA.objects.get(name=previous)
                    previous = ''
                except SOA.DoesNotExist:
                    continue
    if not searched_soa and root and not qtype == 6:
        subdomain = root.subdomain.filter(name='@')
        ns = root.subdomain.filter (type=2)
        return subdomain, root, ns
    if root and qtype == 6:
        ns = root.subdomain.filter (type=2)
        return {}, root, ns
    else:
        return {}, {}, ns


def bin_cutter(data: BitArray, octets=2) -> BitArray:
    """
    Cuts part of binary string
    :param data: binary string BitArray
    :param octets: number of bytes (8bit) to cut from beginning of string
    :return: BitArray without cut part
    """
    return BitArray(bin=data.bin[octets*8:])


def attr_to_bin_string(item, url_dict, octet_counter):
    """
    Transforms string attribute of object to a variable length string of octets that describes the resource
    :param item: object
    :return: BitArray with binary string
    """
    from dns_objects import UrlAddress, Message
    bin_string = ''
    length_octet = False
    for n, subitem in enumerate(item.__dict__):
        if not re.match('\_\_[A-z_]+\_\_', subitem) and not subitem == '__data_rest__':
            if subitem == 'rdlength':
                length_octet = len(bin_string)
                length_octet_n = n
            if isinstance(getattr(item, subitem), UrlAddress):
                local_string, url_dict, octet_counter = getattr(item, subitem).binary_with_pos(url_dict, octet_counter)
                bin_string += local_string
            else:
                # try:
                    bin_string += getattr(item, subitem).binary
                    octet_counter += len(getattr(item, subitem).binary) / 8
                # except Exception as e:
                #     print(str(e) +' '+  str(subitem) + ' '+ str(item) + str(getattr(item, subitem)))
        if length_octet:
            if not length_octet_n == n:
                bin_string = bin_string[:length_octet] + str(bin(int(len(bin_string[length_octet:])/8) - 2)[2:]).zfill(16) + bin_string[length_octet+16:]
                length_octet = False
    return bin_string, url_dict, octet_counter


def decode_url(raw_bin_data: BitArray):
    """
    Decodes url from binary string
    :param raw_bin_data:
    :return:
    """
    url = []
    length_octet = raw_bin_data.bin[0:8]
    raw_bin_data = bin_cutter(raw_bin_data, 1)
    while int(length_octet, base=2):
        suburl = ''.join([chr(int(raw_bin_data.bin[i:i + 8], base=2)) for i in range(0, len(raw_bin_data.bin[0:8*int(length_octet, base=2)]), 8)])
        url.append(suburl)
        raw_bin_data = bin_cutter(raw_bin_data, int(length_octet, base=2))
        length_octet = raw_bin_data.bin[0:8]
        if not length_octet:
            break
        else:
            raw_bin_data = bin_cutter(raw_bin_data, 1)
    return '.'.join(url), raw_bin_data