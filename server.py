import socketserver
from dns_objects import Message
from functions import find_in_db,queryset_to_dict,soa_to_dict, ns_to_dict

class DNSudpHandler(socketserver.BaseRequestHandler):
    """
    DNS UDP handler
    """
    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        print(self.client_address[0])
        message = Message(data=data)
        print(message.question.qtype)
        print ("{} requested: {}".format (self.client_address[0], message.question.labels))
        subdomain, root, ns = find_in_db(message.question.labels, message.question.qtype,  message.question.qclass)
        dns_result_dict = {}
        if subdomain:
            dns_result_dict.update(queryset_to_dict(subdomain))
        elif root:
            dns_result_dict.update (soa_to_dict(root))
        if ns:
            dns_result_dict.update(ns_to_dict(ns))
        message.header._aa = '1'
        message.from_dict(dns_result_dict)
        reply_message = message.to_bin()
        socket.sendto(reply_message.bytes, self.client_address)


def start_server(host,port, udp=True, tcp=False):
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