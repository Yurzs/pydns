import socketserver
import binascii
from bitstring import BitStream, BitArray


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


class DNSquery:
    class Header:
        def __init__(self, data: BitArray):
            self.id = int(data.bin[0:16], base=2)
            data = bin_cutter(data)
            self.qr = data.bin[0]
            self.opcode = data.bin[0:4]
            self.aa = data.bin[5]
            self.tc = data.bin[6]
            self.rd = data.bin[7]
            self.ra = data.bin[8]
            self.z = data.bin[9:12]
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
        def __init__(self, data: BitArray):
            self.labels, data = bin_to_ascii(data)
            self.qtype = data.bin[0:16]
            data = bin_cutter(data)
            self.qclass = data.bin[0:16]
            self.data_rest = bin_cutter(data)


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
        query = DNSquery
        header = query.Header(data=BitArray(data))
        question = query.Question(data=header.data_rest)
        print(header.__dict__)
        print(question.__dict__)
        socket.sendto(data.upper(), self.client_address)


if __name__ == "__main__":
    HOST, PORT = "localhost", 53
    with socketserver.UDPServer((HOST, PORT), MyUDPHandler) as server:
        server.serve_forever()