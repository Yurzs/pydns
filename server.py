import socketserver
from dns_objects import Message, int32,int16,int8,int4,int3,int1
from functions import find_in_db,queryset_to_dict,soa_to_dict, ns_to_dict
from typing import get_type_hints
import redis


class Server:
    recursive = False
    nameservers = []


class DNSudpHandler(socketserver.BaseRequestHandler):
    """
    DNS UDP handler
    """
    def handle(self):
        data = self.request[0].strip()
        socketd = self.request[1]
        try:
            message = Message(data=data)
            subdomain, root, ns = find_in_db(message.question.labels, message.question.qtype,  message.question.qclass)
            dns_result_dict = {}
            if subdomain:
                dns_result_dict.update(queryset_to_dict(subdomain))
            elif root:
                dns_result_dict.update(soa_to_dict(root))
            if ns:
                dns_result_dict.update(ns_to_dict(ns))
            elif not root and not subdomain and not ns:
                raise ValueError
            message.from_dict2(dns_result_dict)
            message.header.aa = int1(1)
            print("{} requested: {} [[]]".format(self.client_address[0], message.question.labels, message.question.qtype) +
                  ' and I know this one')
            socketd.sendto(message.compose().bytes, self.client_address)
        except ValueError:
            import socket
            connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            connection.sendto(bytes(data), ('8.8.8.8', 53))
            received = connection.recv(1024)
            print("{} requested something".format(self.client_address[0]) +
                  ' and I\'ve looked it up')
            socketd.sendto(received, self.client_address)
            return


def start_server(host, port, udp=True, tcp=False):
    """
    Run server forever
    :param host:
    :param port:
    :param udp:
    :param tcp:
    :return:
    """
    if udp:
        with socketserver.UDPServer((host, port), DNSudpHandler) as server:
            server.serve_forever()


if __name__ == "__main__":
    start_server(host='0.0.0.0', port=53)