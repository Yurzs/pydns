import socketserver
from bitstring import BitArray
import re
import pydns
pydns.setup()
from DNS.models import *


TYPE = {
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
    12: 'PTR',
    13: 'HINFO',
    14: 'MINFO',
    15: 'MX',
    16: 'TXT'
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


def find_in_db(label,qtype ,qclass):
    previous = None
    root = None
    for domain in reversed(label.split('.')):
        if root:
            try:
                subdomain = root.subdomain.get(name=domain, type=qtype, dns_class=qclass)
                return subdomain
            except SubDomain.DoesNotExist:
                previous = '.'.join([domain, previous]) if previous else domain
                try:
                    subdomain = root.subdomain.get(name=previous, type=qtype, dns_class=qclass)
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
    if not root:
        return False




def bin_cutter(data: BitArray, octets=2) -> BitArray:
    return BitArray(bin=data.bin[octets*8:])


def bin_to_ascii(data):
    labels = ''
    raw = str(data.bin[0:8])
    chunk = int(data.bin[0:8], base=2)
    data = bin_cutter(data, 1)
    while chunk != 0:
        for char in range(chunk):
            raw += data.bin[0:8]
            labels += chr(int(data.bin[0:8], base=2))
            data = bin_cutter(data, 1)
        raw += data.bin[0:8]
        chunk = int(data.bin[0:8], base=2)
        data = bin_cutter(data, 1)
        labels += '.' if chunk else ''
    return labels, data, raw


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


def object_to_bits(data: object, previous_item: list=None):
    raw_bit_string = ''
    for item in data.__dict__:
        if re.match('__[A-z_]+__', item) or re.match('_[A-z_]+', item):
            continue
        if isinstance(getattr(data, item), list):
            #TODO str to bin with octets prefix
            for item in getattr(data, item):
                if 0 <= int(item) <= 255:
                    raw_bit_string += str(bin(int(item))[2:]).zfill(8)
            continue
        if isinstance(getattr(data, item), str):
            #TODO str to bin with octets prefix
            pass
        elif isinstance(getattr(data, item), int):
            obj = Message().Length
            for layer in previous_item:
                obj = getattr(obj, layer)
            raw_bit_string += str(bin(getattr(data, item))[2:]).zfill(getattr(obj, item))
        elif hasattr(getattr(data, item), '__class__'):
            if previous_item:
                previous_item.append(item)
            else:
                previous_item = [item]
            raw_bit_string += object_to_bits(data=getattr(data, item), previous_item=previous_item)
            previous_item = []
    return raw_bit_string

def get_domain(url):
    previous = None
    for subdomain in reversed(url.split('.')):
        if SOA.objects.filter(name=subdomain):
            return SOA.objects.get(name=subdomain)
        if previous:
            previous = '.'.join([subdomain,previous])
        else:
            previous = subdomain
        if SOA.objects.filter(name=previous):
            return SOA.objects.get(name=previous)
    return False

class Message:
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
        # self.answer = self.Answer()

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
                    check_item = item
                if getattr(self, check_item):
                    self.__dict__.update({item: getattr(self, check_item)()})
                    subclass = self.__getattribute__(item)
                    subclass.__dict__.update(**data_dict[item])
                    subclass_dict = subclass.__dict__.copy()
                    for subitem in subclass.__dict__:
                        if isinstance(subclass.__dict__.get(subitem), str):
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
                            except:
                                lenght = 16
                            subclass_dict.update({'_' + subitem: str(bin(subclass.__dict__.get(subitem))[2:]).zfill(lenght)})
                    subclass.__dict__.update(**subclass_dict)
            except Exception as e:
                print(e)
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





class MyUDPHandler(socketserver.BaseRequestHandler):
    #TODO AutomateHeader
    #TODO Add RDATA types
    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        print("{} wrote:".format(self.client_address[0]))
        message = Message(data=data)
        dns_result_dict = find_in_db(message.question.labels, message.question.qtype,  message.question.qclass)
        if dns_result_dict:
            dns_result_dict = dns_result_dict.to_dns_dict()
            message.header._qr = '1'
            message.header._ancount = '0000000000000001'
            message.header._arcount = '0000000000000000'
        else:
            message.header._qr = '1'
            message.header._arcount = '0000000000000000'
            dns_result_dict = {}
        message.from_dict(dns_result_dict)
        socket.sendto(BitArray(bin=message.to_bin()).bytes, self.client_address)


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 53
    with socketserver.UDPServer((HOST, PORT), MyUDPHandler) as server:
        server.serve_forever()