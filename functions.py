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

def string_to_bit(data:str, length) -> str:
    """
    Encodes string or int to bytes
    :param data: string or int
    :param length: length of int (int8, int16, int32) [8,16,32]
    :return: binary_string
    """
    raw_bit_string = ''
    if isinstance(data, int):
        raw_bit_string += str (bin (int (data))[2:]).zfill (length)
    elif re.match (
            '(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])',
            data):
        for n, sub in enumerate (data.split ('.')):
            sub = int (sub)
            raw_bit_string += str (bin (int (sub))[2:]).zfill (8)
    elif re.match('[a-z0-9]+(?:[\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(?:[0-9]{1,5})?(\/.*)?$', data):
        for n, sub in enumerate (data.split ('.')):
            raw_bit_string += str (bin (int (len (sub)))[2:]).zfill (8)
            for char in sub:
                raw_bit_string += str (bin (ord (char))[2:]).zfill (8)
            if n == len (data.split('.')) - 1:
                raw_bit_string += str ('').zfill (8)
    elif isinstance(data, str):
        for row in data.split('\n'):
            raw_bit_string += str (bin (int (len (row)))[2:]).zfill (8)
            for char in row:
                raw_bit_string += str (bin (ord (char))[2:]).zfill (8)
    return raw_bit_string


def bit_to_obj(data, obj_type):
    """
    Decodes binary string to string or integer value
    :param data: bin_string
    :param obj_type: type of object [int, octet_string]
    :return: string or intger value
    """
    if obj_type == 'int':
        return int(data,base=2)
    elif obj_type == 'octet_string':
        string = ''
        chunk = int (data.bin[0:8], base=2)
        data = bin_cutter (data, 1)
        while chunk != 0 and not chunk == '':
            for char in range (chunk):
                string += chr (int (data.bin[0:8], base=2))
                data = bin_cutter (data, 1)
            chunk = int (data.bin[0:8], base=2) if data.bin[0:8] else 0
            data = bin_cutter (data, 1)
            string += '.' if chunk else ''
        return string

def attr_to_bin_string(item):
    """
    Transforms string attribute of object to a variable length string of octets that describes the resource
    :param item: object
    :return: BitArray with binary string
    """
    bin_string = ''
    for subitem in item.__dict__:
        if re.match ('\_(?:[^_]+|[^_][A-z]+)', subitem) and not subitem == '__data_rest__':
            if isinstance (getattr (item, subitem), BitArray):
                bin_string += getattr (item, subitem).bin
            else:
                bin_string += getattr (item, subitem)
    return bin_string

def get_octet_bin_string(data) -> BitArray:
    """
    Transforms string to a variable length string of octets that describes the resource
    :param data: basic ASCII text
    :return: BitArray with binary string
    """
    bin_string = ''
    chunk = data.bin[0:8]
    data = bin_cutter (data, 1)
    while int(chunk,base=2) != 0:
        bin_string += chunk
        for char in range (int(chunk,base=2)):
            bin_string += data.bin[0:8]
            data = bin_cutter (data, 1)
        chunk = data.bin[0:8] if data.bin[0:8] else ''.zfill(8)
        data = bin_cutter (data, 1) if chunk else data
    bin_string += chunk
    return BitArray(bin=bin_string)