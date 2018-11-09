import socketserver
from bitstring import BitArray
import re
import pydns
pydns.setup()
from DNS.models import *
import rdata
from django.db.models.query import QuerySet

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


def queryset_to_dict(query_set):
    answers = {}
    for n, item in enumerate(query_set):
        answers.update({
            'answer'+ str(n): item.dns_dict})
    return answers

def soa_to_dict(soa):
    return {'authority1': soa.dns_dict}

def find_in_db(label,qtype ,qclass):
    previous = None
    root = None
    for domain in reversed(label.split('.')):
        if root:
            try:
                subdomain = root.subdomain.filter(name=domain, type=qtype, dns_class=qclass)
                if not subdomain:
                    raise SubDomain.DoesNotExist
                return subdomain
            except SubDomain.DoesNotExist:
                previous = '.'.join([domain, previous]) if previous else domain
                try:
                    subdomain = root.subdomain.filter(name=previous, type=qtype, dns_class=qclass)
                    if not subdomain:
                        raise SubDomain.DoesNotExist
                    return subdomain
                except SubDomain.DoesNotExist:
                    continue
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
    return root


def bin_cutter(data: BitArray, octets=2) -> BitArray:
    return BitArray(bin=data.bin[octets*8:])

def string_to_bit(data:str, lenght=8) -> str:
    raw_bit_string = ''
    if isinstance(data, int):
        raw_bit_string += str (bin (int (data))[2:]).zfill (lenght)
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
    return raw_bit_string


def bit_to_obj(data, obj_type):
    if obj_type == 'int':
        return int(data,base=2)
    elif obj_type == 'octet_string':
        string = ''
        chunk = int (data.bin[0:8], base=2)
        data = bin_cutter (data, 1)
        while chunk != 0:
            for char in range (chunk):
                string += chr (int (data.bin[0:8], base=2))
                data = bin_cutter (data, 1)
            chunk = int (data.bin[0:8], base=2) if data.bin[0:8] else 0
            data = bin_cutter (data, 1)
            string += '.' if chunk else ''
        return string


def get_octet_bin_string(data):
    bin_string = ''
    chunk = data.bin[0:8]
    data = bin_cutter (data, 1)
    while int(chunk,base=2) != 0:
        bin_string += chunk
        for char in range (int(chunk,base=2)):
            bin_string += data.bin[0:8]
            data = bin_cutter (data, 1)
        chunk = data.bin[0:8]
        data = bin_cutter (data, 1)
    bin_string += chunk
    return BitArray(bin=bin_string)


class Message:
    class Rdata:

        class Cname():
            def __init__(self, target):
                self.cname = target

        class Hinfo:
            def __init__(self, target):
                self.cpu = target.split('\n')[0]
                self.os = target.split('\n')[1]

        class Mb:
            def __init__(self, target):
                self.madname = target

        class Md:
            def __init__(self, target):
                self.madname = target

        class Mf:
            def __init__(self, target):
                self.madname = target

        class Mg:
            def __init__(self, target):
                self.mgname = target

        class Minfo:
            def __init__(self, target):
                self.rmailbx = target.split('\n')[0]
                self.emailbx = target.split('\n')[1]

        class Mr:
            def __init__(self, target):
                self.newname = target

        class Mx:
            def __init__(self, target):
                self.preference = int(target.split('\n')[0])
                self.exchange = target.split('\n')[1]

        class Null:
            def __init__(self, target):
                pass

        class Ns:
            def __init__(self, target):
                self.nsdname = target

        class Ptr:
            def __init__(self, target):
                self.ptrname = target

        class Soa:
            def __init__(self, soa):
                #TODO FIX
                self.mname = soa.name
                self.rname = soa.email.replace('@','.')
                self.serial = soa.serial
                self.refresh = (soa.refresh.hour * 60 + soa.refresh.minute) * 60 + soa.refresh.second
                self.retry = (soa.retry.hour * 60 + soa.retry.minute) * 60 + soa.retry.second
                self.expire = (soa.expire.hour * 60 + soa.expire.minute) * 60 + soa.expire.second
                self.minimum = soa.ttl


        class Txt:
            def __init__(self, target):
                self.txt_data = target

        class A:
            def __init__(self, target):
                self.address = target


        class Wks:
            #TODO FIX THIS
            def __init__(self, target):
                self.address = target
                self.protocol = target
                self.bitmap = target

        class InAddrArpa:
            # TODO FIX THIS
            def __init__(self, target):
                self.address = target

    class Length:
        class Header:
            id = 16
            qr = 1
            opcode = 4
            aa = 1
            tc = 1
            rd = 1
            ra = 1
            z = 3
            rcode = 4
            qdcount = 16
            ancount = 16
            nscount = 16
            arcount = 16
        header = Header

        class Answer:
            name = 16
            type = 16
            cls = 16
            ttl = 32
            rdlength = 16
            rdata = 8*4
        answer = Answer

        class Authority:
            name = 16
            type = 16
            cls = 16
            ttl = 32
            rdlength = 16
            rdata = 8*4
        authority = Answer

        class Additional:
            name = 16
            type = 16
            cls = 16
            ttl = 32
            rdlength = 16
            rdata = 8*4
        additional = Additional

        class Rdata:
            class Cname ():
                pass

            class Hinfo:
                pass

            class Mb:
                pass

            class Md:
                pass

            class Mf:
                pass

            class Mg:
                pass

            class Minfo:
                pass

            class Mr:
                pass

            class Mx:
                pass

            class Null:
                pass

            class Ns:
                pass

            class Ptr:
                pass

            class Soa:
                serial = 32
                refresh = 32
                retry = 32
                expire = 32
                minimum = 32

            class Txt:
                pass

            class A:
                pass

            class Wks:
                protocol = 8

            class InAddrArpa:
                pass

    class Header:
        def __init__(self, data: BitArray=None):
            if data:
                self._id = data.bin[0:16]
                self.id = bit_to_obj(self._id, 'int')
                data = bin_cutter(data)
                self._qr = data.bin[0]
                self.qr = bit_to_obj(self._qr, 'int')
                self._opcode = data.bin[0:4]
                self.opcode = bit_to_obj(self._opcode, 'int')
                self._aa = data.bin[5]
                self.aa = bit_to_obj(self._aa, 'int')
                self._tc = data.bin[6]
                self.tc = bit_to_obj(self._tc, 'int')
                self._rd = data.bin[7]
                self.rd = bit_to_obj(self._rd, 'int')
                self._ra = data.bin[8]
                self.ra = bit_to_obj(self._ra, 'int')
                self._z = data.bin[9:12]
                self.z = bit_to_obj(self._z, 'int')
                self._rcode = data.bin[12:16]
                self.rcode = bit_to_obj(self._rcode, 'int')
                data = bin_cutter(data)
                self._qdcount = data.bin[0:16]
                self.qdcount = bit_to_obj(self._qdcount, 'int')
                data = bin_cutter(data)
                self._ancount = data.bin[0:16]
                self.ancount = bit_to_obj(self._ancount, 'int')
                data = bin_cutter(data)
                self._nscount = data.bin[0:16]
                self.nscount = bit_to_obj(self._nscount, 'int')
                data = bin_cutter(data)
                self._arcount = data.bin[0:16]
                self.arcount = bit_to_obj(self._arcount, 'int')
                self.__data_rest__ = bin_cutter(data)

    class Question:
        def __init__(self, data: BitArray=None):
            if data:
                self._labels = get_octet_bin_string(data)
                self.labels = bit_to_obj(self._labels, 'octet_string')
                data = bin_cutter(data, octets= int(len(self._labels.bin) / 8))
                self._qtype = data.bin[0:16]
                self.qtype = bit_to_obj(self._qtype, 'int')
                data = bin_cutter(data)
                self._qclass = data.bin[0:16]
                self.qclass = bit_to_obj(self._qclass, 'int')
                self.__data_rest__ = bin_cutter(data).bin

    class Answer:
        pass

    class Authority:
        pass

    class Additional:
        pass

    def __init__(self, data: bytes=None):
        if data:
            self.header = self.Header(data=BitArray(bytes=data))
            if self.header.qdcount:
                self.question = self.Question(data=self.header.__data_rest__)
        else:
            self.header = self.Header
        self.__message_items_length__ = self.Length

    def to_dict(self):
        result = {}
        for item in self.__dict__:
            if not re.match ('__[A-z_]+__', item) and not re.match ('_[A-z_]+', item):
                result.update ({item: {}})
                for subitem in getattr(self, item).__dict__:
                    if not re.match ('__[A-z_]+__', subitem) and not re.match ('_[A-z_]+', subitem):
                        if isinstance(getattr(getattr(self, item), subitem), BitArray):
                            result[item].update({subitem: getattr(getattr(self, item), subitem).bin})
                        else:
                            result[item].update({subitem: getattr(getattr(self, item), subitem)})
        return result

    def from_dict(self, data_dict):
        for item in data_dict:
            try:
                if re.match('[A-z]{2,15}[0-9]{1,5}', item):
                    check_item = re.findall('[A-z]{3,15}', item.capitalize())[0]
                else:
                    check_item = item.capitalize()
                if getattr(self, check_item):
                    self.__dict__.update({item: getattr(self, check_item)()})
                    subclass = self.__getattribute__(item)
                    subclass.__dict__.update(**data_dict[item])
                    subclass_dict = subclass.__dict__.copy()
                    for subitem in subclass.__dict__:
                        if subitem == 'rdata':
                            raw_bit_string = ''
                            data = rdata.TYPE.get(subclass_dict.get('type'))
                            if data.__name__.upper() == 'SOA':
                                data = data(subclass_dict[subitem])
                                for item in data.__dict__:
                                    try:
                                        length = getattr(getattr(Message.Length.Rdata,data.__class__.__name__.capitalize ()),
                                                         item)
                                    except AttributeError:
                                        length =  8
                                    raw_bit_string += string_to_bit(data.__dict__[item], length)
                            else:
                                data = data(subclass_dict.get(subitem))
                                for item in data.__dict__:
                                    try:
                                        length = getattr(getattr(Message.Length.Rdata,data.__class__.__name__.capitalize ()),
                                                         item)
                                    except AttributeError:
                                        length =  8
                                    raw_bit_string += string_to_bit (data.__dict__[item], length)
                            subclass_dict.update({'_rdlength': str(bin(int(len(raw_bit_string)/8))[2:]).zfill(16)})
                            subclass_dict.update({'_' + subitem: raw_bit_string})
                        elif isinstance(subclass.__dict__.get(subitem), str):
                            raw_bit_string = ''
                            for n, sub in enumerate(subclass_dict[subitem].split('.')):
                                try:
                                    sub = int(sub)
                                    raw_bit_string += str(bin(int(sub))[2:]).zfill(8)
                                except ValueError:
                                    raw_bit_string += str(bin(int(len(sub)))[2:]).zfill(8)
                                    for char in sub:
                                        raw_bit_string += str(bin(ord(char))[2:]).zfill(8)
                                    if n == len(subclass_dict[subitem].split ('.')) - 1:
                                        raw_bit_string += str('').zfill(8)
                            subclass_dict.update ({'_' + subitem: raw_bit_string})
                        elif isinstance(subclass.__dict__.get(subitem), int):
                            try:
                                lenght = getattr(getattr(Message.Length(), check_item), subitem)
                            except AttributeError:
                                lenght = 16
                            subclass_dict.update({'_' + subitem: str(bin(subclass.__dict__.get(subitem))[2:]).zfill(lenght)})
                    subclass.__dict__.update(**subclass_dict)
            except Exception as e:
                print('error :' + e)
        self.header._ancount = str (
            bin (len ([item for item in self.__dict__ if re.match ('answer[0-9]{1,5}', item)]))[2:]).zfill (16)
        self.header._nscount = str (
            bin (len ([item for item in self.__dict__ if re.match ('authority[0-9]{1,5}', item)]))[2:]).zfill (16)
        self.header._arcount = str (
            bin (len ([item for item in self.__dict__ if re.match ('additional[0-9]{1,5}', item)]))[2:]).zfill (16)
        self.header._qr = '1' if int(self.header._ancount) or int(self.header._nscount) or int(self.header._arcount) else '0'
        return self.to_dict()


    def to_bin(self) -> bytes:
        bin_string = ''
        sum = 0
        for item in self.__dict__:
            if not re.match ('__[A-z_]+__', item) and not re.match ('_[A-z_]+', item):
                for subitem in getattr (self, item).__dict__:
                    if re.match ('\_(?:[^_]+|[^_][A-z]+)', subitem) and not subitem == '__data_rest__':
                        if isinstance(getattr (getattr (self, item), subitem), BitArray):
                            bin_string += getattr (getattr (self, item), subitem).bin
                            sum += len(getattr (getattr (self, item), subitem).bin)
                        else:
                            bin_string += getattr (getattr (self, item), subitem)
                            sum += len (getattr (getattr (self, item), subitem))
        return bin_string


class DNSudpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        message = Message(data=data)
        print ("{} requested: {}".format (self.client_address[0], message.question.labels))
        dns_result_dict = find_in_db(message.question.labels, message.question.qtype,  message.question.qclass)
        if isinstance(dns_result_dict, QuerySet):
            dns_result_dict = queryset_to_dict(dns_result_dict)
        elif isinstance(dns_result_dict, SOA):
            dns_result_dict = soa_to_dict(dns_result_dict)
        else:
            dns_result_dict = {}
        message.from_dict(dns_result_dict)
        socket.sendto(BitArray(bin=message.to_bin()).bytes, self.client_address)


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 53
    with socketserver.UDPServer((HOST, PORT), DNSudpHandler) as server:
        server.serve_forever()