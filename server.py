import socketserver
from bitstring import BitArray
import re


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


def bin_cutter(data: BitArray, octets=2) -> BitArray:
    return BitArray(bin=data.bin[octets*8:])


def bin_to_ascii(data):
    labels = ''
    chunk = int(data.bin[0:8], base=2)
    data = bin_cutter(data, 1)
    while chunk != 0:
        for char in range(chunk):
            labels += chr(int(data.bin[0:8], base=2))
            data = bin_cutter(data, 1)
        chunk = int(data.bin[0:8], base=2)
        data = bin_cutter(data, 1)
        labels += '.' if chunk else ''
    return labels, data


def object_to_bits(data: object, previous_item: list=None):
    raw_bit_string = ''
    for item in data.__dict__:
        if re.match('__[A-z_]+__', item):
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
    return raw_bit_string


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

    class Header:
        def __init__(self, data: BitArray=None):
            if data:
                self.id = int(data.bin[0:16], base=2)
                data = bin_cutter(data)
                self.qr = data.bin[0]
                self.opcode = int(data.bin[0:4], base=2)
                self.aa = int(data.bin[5], base=2)
                self.tc = int(data.bin[6], base=2)
                self.rd = int(data.bin[7], base=2)
                self.ra = int(data.bin[8], base=2)
                self.z = int(data.bin[9:12], base=2)
                self.rcode = data.bin[12:16]
                data = bin_cutter(data)
                self.qdcount = data.bin[0:16]
                data = bin_cutter(data)
                self.ancount = data.bin[0:16]
                data = bin_cutter(data)
                self.nscount = data.bin[0:16]
                data = bin_cutter(data)
                self.arcount = data.bin[0:16]
                self.data_rest = bin_cutter(data)

    class Question:
        def __init__(self, data: BitArray=None):
            if data:
                self.labels, data = bin_to_ascii(data)
                self.qtype = TYPE.get(int(data.bin[0:16], base=2), '*')
                data = bin_cutter(data)
                self.qclass = CLASS.get(data.bin[0:16], '*')
                self.data_rest = bin_cutter(data)

    class Answer:
        def __init__(self, **kwargs):
            self.__dict__.update(**kwargs)

    class Authority:
        pass

    class Additional:
        pass

    def __init__(self, data: bytes=None):
        if data:
            self.header = self.Header(data=BitArray(bytes=data))
            if self.header.qdcount:
                self.question = self.Question(data=self.header.data_rest)
        else:
            self.header = self.Header
        self.__message_items_length__ = self.Length

    def reply(self) -> bytes:
        reply_message = Message()
        reply_message.header.id = self.header.id
        reply_message.header.qr = 1
        reply_message.header.opcode = self.header.opcode
        reply_message.header.aa = 1
        reply_message.header.tc = 0
        reply_message.header.rd = self.header.rd
        reply_message.header.ra = 0
        reply_message.header.z = 0
        reply_message.header.rcode = 2
        reply_message.header.qdcount = 0
        reply_message.header.ancount = 0
        reply_message.header.nscount = 0
        reply_message.header.arcount = 0
        reply_message.bit_data = object_to_bits(reply_message)
        return BitArray(bin=reply_message.bit_data).bytes





class MyUDPHandler(socketserver.BaseRequestHandler):
    """
    This class works similar to the TCP handler class, except that
    self.request consists of a pair of data and client socket, and since
    there is no connection the client address must be given explicitly
    when sending data back via sendto().
    """

    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        print("{} wrote:".format(self.client_address[0]))
        message = Message(data=data)
        print(message.header.__dict__)
        print(message.question.__dict__)
        print(message.reply())
        socket.sendto(message.reply(), self.client_address)


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 53
    with socketserver.UDPServer((HOST, PORT), MyUDPHandler) as server:
        server.serve_forever()