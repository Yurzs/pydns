from bitstring import BitArray
import re
from functions import bin_cutter, attr_to_bin_string, decode_url


class int1(int):
    @property
    def binary(self):
        return str(bin(self)[2:]).zfill(1)


class int3(int):
    @property
    def binary(self):
        return str(bin(self)[2:]).zfill(3)


class int4(int):
    @property
    def binary(self):
        return str(bin(self)[2:]).zfill(4)


class int8(int):
    @property
    def binary(self):
        return str(bin(self)[2:]).zfill(8)


class int16(int):
    @property
    def binary(self):
        return str(bin(self)[2:]).zfill(16)


class int32(int):
    @property
    def binary(self) -> str:
        return str(bin(self)[2:]).zfill(32)


class int128(int):
    @property
    def binary(self) -> str:
        return str(bin(self)[2:]).zfill(128)


class local_str(str):
    @property
    def binary(self):
        return str(bin(len([str(bin(ord(char))[2:]).zfill(8) for char in self]))[2:]).zfill(8) + ''.join([str(bin(ord(char))[2:]).zfill(8) for char in self])

class IpAddress(str):
    @property
    def binary(self):
        return ''.join([str(bin(int(item))[2:]).zfill(8) for item in self.split('.')])

class Ip6Address(str):
    @property
    def binary(self):
        return ''.join([str(bin(int(item))[2:]).zfill(8) for item in self.split(':')])

class UrlAddress(str):
    @property
    def binary(self):
        binary_string = ''
        parts = self.split('.')
        for urlpart in parts:
            binary_string += str(bin(len(urlpart))[2:]).zfill(8)
            for char in urlpart:
                binary_string += str(bin(ord(char))[2:]).zfill(8)
        binary_string += str(bin(0)[2:]).zfill(8)
        return binary_string

    def binary_with_pos(self, urls_dict, octet_counter):
        binary_string = ''
        parts = self.split('.')
        prev = ''
        if urls_dict:
            for n in range(len(parts)):
                if '.'.join(parts[n:len(parts)]) in urls_dict:
                    prev = '.'.join(parts[n:len(parts)])
                    break
            if prev == self:
                binary_string += '11' + str(bin(int(urls_dict[prev]))[2:]).zfill(16-2)
                octet_counter += 2
                return binary_string, urls_dict, octet_counter
            else:
                parts = self.replace(prev, '')[:-1].split('.')
        for n, urlpart in enumerate(parts):
            if prev:
                if not prev + '.' + '.'.join(parts[n:len(parts)]) in urls_dict:
                    binary_string += str(bin(len(urlpart))[2:]).zfill(8)
                    octet_counter += 1
                    for char in urlpart:
                        binary_string += str(bin(ord(char))[2:]).zfill(8)
                        octet_counter += 1
                    break
            else:
                urls_dict.update({'.'.join(parts[n:len(parts)]): int(octet_counter)})
            binary_string += str(bin(len(urlpart))[2:]).zfill(8)
            octet_counter += 1
            for char in urlpart:
                binary_string += str(bin(ord(char))[2:]).zfill(8)
                octet_counter += 1
        if prev:
            binary_string += '11' + str(bin(int(urls_dict[prev]))[2:]).zfill(16 - 2)
            octet_counter += 2
            return binary_string, urls_dict, octet_counter
        binary_string += str(bin(0)[2:]).zfill(8)
        octet_counter += 1
        return binary_string, urls_dict, octet_counter


class Message:
    class Rdata:
        class Cname:
            def __init__(self, subdomain):
                self.cname = UrlAddress(subdomain.target)

            @property
            def binary(self):
                return self.cname.binary

        class Hinfo:
            def __init__(self, subdomain):
                self.cpu = local_str(subdomain.target.split('\n')[0])
                self.os = local_str(subdomain.target.split('\n')[1])

            @property
            def binary(self):
                return ''.join([self.cpu.binary, self.os.binary])

        class Mb:
            def __init__(self, subdomain):
                self.madname = UrlAddress(subdomain.target)

            @property
            def binary(self):
                return self.madname.binary

        class Md:
            def __init__(self, subdomain):
                self.madname = UrlAddress(subdomain.target)

            @property
            def binary(self):
                return self.madname.binary

        class Mf:
            def __init__(self, subdomain):
                self.madname = UrlAddress(subdomain.target)

            @property
            def binary(self):
                return self.madname.binary

        class Mg:
            def __init__(self, subdomain):
                self.mgname = UrlAddress(subdomain.target)

            @property
            def binary(self):
                return self.mgname.binary

        class Minfo:
            def __init__(self, subdomain):
                self.rmailbx = UrlAddress(subdomain.target.split('\n')[0])
                self.emailbx = UrlAddress(subdomain.target.split('\n')[1])

            @property
            def binary(self):
                return ''.join([self.rmailbx.binary, self.emailbx.binary])

        class Mr:
            def __init__(self, subdomain):
                self.newname = UrlAddress(subdomain.target)

            @property
            def binary(self):
                return self.newname.binary

        class Mx:
            def __init__(self, subdomain):
                self.preference = int16(subdomain.target.split('\n')[0])
                self.exchange = UrlAddress(subdomain.target.split('\n')[1])

            @property
            def binary(self):
                return ''.join([self.preference.binary, self.exchange.binary])

        class Null:
            def __init__(self, target):
                pass

            @property
            def binary(self):
                return '00000000'

        class Ns:
            def __init__(self, subdomain):
                self.nsdname = UrlAddress(subdomain.target)

            @property
            def binary(self):
                return self.nsdname.binary

        class Ptr:
            def __init__(self, subdomain):
                self.ptrname = UrlAddress(subdomain.target)

            @property
            def binary(self):
                return self.ptrname.binary

        class Soa:
            def __init__(self, soa):
                #TODO FIX
                self.mname = UrlAddress(soa.ns)
                self.rname = UrlAddress(soa.email.replace('@','.'))
                self.serial = int32(soa.serial)
                self.refresh = int32((soa.refresh.hour * 60 + soa.refresh.minute) * 60 + soa.refresh.second)
                self.retry = int32((soa.retry.hour * 60 + soa.retry.minute) * 60 + soa.retry.second)
                self.expire = int32((soa.expire.hour * 60 + soa.expire.minute) * 60 + soa.expire.second)
                self.minimum = int32((soa.ttl.hour * 60 + soa.ttl.minute) * 60 + soa.ttl.second)

            @property
            def binary(self):
                return ''.join([self.mname.binary,self.rname.binary,self.serial.binary,self.refresh.binary,self.retry.binary,
                                self.expire.binary,self.minimum.binary])

        class Txt:
            def __init__(self, subdomain):
                self.txt_data = local_str(subdomain.target)

            @property
            def binary(self):
                return self.txt_data.binary

        class A:
            def __init__(self, subdomain):
                self.address = IpAddress(subdomain.target)

            @property
            def binary(self):
                return self.address.binary

        class Wks:
            #TODO FIX Bitmap
            def __init__(self, subdomain):
                self.address = IpAddress(subdomain.target.split('\n')[0])
                self.protocol = int8(subdomain.target.split('\n')[1])
                self.bitmap = local_str(subdomain.target.split('\n')[2])

            @property
            def binary(self):
                return ''.join([self.address.binary,self.protocol.binary,self.bitmap.binary])

        class InAddrArpa:
            # TODO FIX THIS
            def __init__(self, subdomain):
                self.address = local_str(subdomain.target)

            @property
            def binary(self):
                return self.address.binary

    class Header:
        def __init__(self, data: BitArray=None):
            if data:
                self.id = int16(data.bin[0:16], base=2)
                data = bin_cutter(data)
                self.qr = int1(data.bin[0], base=2)
                self.opcode = int4(data.bin[0:4], base=2)
                self.aa = int1(data.bin[5], base=2)
                self.tc = int1(data.bin[6], base=2)
                self.rd = int1(data.bin[7], base=2)
                self.ra = int1(data.bin[8], base=2)
                self.z = int3(data.bin[9:12], base=2)
                self.rcode = int4(data.bin[12:16], base=2)
                data = bin_cutter(data)
                self.qdcount = int16(data.bin[0:16], base=2)
                data = bin_cutter(data)
                self.ancount = int16(data.bin[0:16], base=2)
                data = bin_cutter(data)
                self.nscount = int16(data.bin[0:16], base=2)
                data = bin_cutter(data)
                self.arcount = int16(data.bin[0:16], base=2)
                self.__data_rest__ = bin_cutter(data)

    class Question:
        def __init__(self, data: BitArray=None):
            if data:
                self.labels, data = decode_url(data)
                self.labels = UrlAddress(self.labels)
                self.qtype = int16(data.bin[0:16], base=2)
                data = bin_cutter(data)
                self.qclass = int16(data.bin[0:16], base=2)
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

    def from_dict2(self, data_dict) -> bool:
        for item in data_dict:
            if re.match('(header|question|answer[0-9]{0,5}|authority[0-9]{0,5}|additional[0-9]{0,5})', item):
                check_object_string = re.findall('[A-z]{3,15}', item.capitalize())[0]
                if getattr(self, check_object_string):
                    self.__dict__.update({item: getattr(self, check_object_string)()})
                    try:
                        for dict_item in data_dict[item]:
                            setattr(getattr(self,item), dict_item, data_dict[item][dict_item])
                    except AttributeError as error:
                        print(str(error) + str(self.__getattribute__(item).__dict__))
        self.header.arcount = int16(len ([item for item in self.__dict__ if re.match ('additional[0-9]{1,5}', item)]))
        self.header.nscount = int16(len ([item for item in self.__dict__ if re.match ('authority[0-9]{1,5}', item)]))
        self.header.ancount = int16(len ([item for item in self.__dict__ if re.match ('answer[0-9]{1,5}', item)]))
        self.header.qr = int1(1) if self.header.ancount \
                              or self.header.nscount \
                              or self.header.arcount \
            else int1(0)
        return True

    def compose(self):
        url_dict = {}
        octet_counter = 0
        header_bin = ''
        question_bin = ''
        answer_bin = ''
        authority_bin = ''
        additional_bin = ''
        for attr in [attr for attr in self.__dict__ if re.match('(header|question|answer[0-9]{0,5}|authority[0-9]{0,5}|additional[0-9]{0,5})', attr)]:
            if attr == 'header':
                local_bin, url_dict, octet_counter= attr_to_bin_string(getattr(self, attr), url_dict, octet_counter)
                header_bin += local_bin
            elif attr == 'question':
                local_bin, url_dict, octet_counter = attr_to_bin_string(getattr(self, attr), url_dict, octet_counter)
                question_bin += local_bin
            elif re.match('answer[0-9]{1,5}', attr):
                local_bin, url_dict, octet_counter = attr_to_bin_string(getattr(self, attr), url_dict, octet_counter)
                answer_bin += local_bin
            elif re.match('authority[0-9]{1,5}', attr):
                local_bin, url_dict, octet_counter = attr_to_bin_string(getattr(self, attr), url_dict, octet_counter)
                authority_bin += local_bin
            elif re.match('additional[0-9]{1,5}', attr):
                local_bin, url_dict, octet_counter = attr_to_bin_string(getattr(self, attr), url_dict, octet_counter)
                additional_bin += local_bin
        return BitArray(bin=header_bin + question_bin + answer_bin + authority_bin + additional_bin)

    def send(self, ):
        #TODO Maybe send from here?
        pass

