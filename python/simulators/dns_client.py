import random
import socket
import struct
from typing import Optional, Tuple


# DNS message types we care about
QTYPE_A = 1
QTYPE_PTR = 12

# class IN (Internet)
QCLASS_IN = 1

# response codes from the lower nibble of the second flags byte
RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMPL = 4
RCODE_REFUSED = 5


# raw-socket DNS client. used by simulators to resolve "<host>.<zone>" to an ipv4 address through the
# c++ DnsServer instead of relying on docker / kubernetes DNS. this is what closes the chain DHCP -> DNS:
# the simulator gets an ip via DORA, then uses real DNS to find the collector by name
class DnsClient:

    def __init__(self, server_ip: str, server_port: int = 53):

        self.server_ip: str = server_ip      # ip or hostname of the dns server to query
        self.server_port: int = server_port  # dns server udp port; standard is 53

    # send a standard A query for fqdn; returns the first answer's ipv4 string, or None on NXDOMAIN /
    # REFUSED / SERVFAIL / timeout. blocks up to timeout_sec
    def resolve_a(self, fqdn: str, timeout_sec: float = 3.0) -> Optional[str]:

        xid = random.getrandbits(16)
        query = self._build_query(xid, fqdn, QTYPE_A)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("0.0.0.0", 0))
            sock.settimeout(timeout_sec)
            sock.sendto(query, (self.server_ip, self.server_port))

            data, _ = sock.recvfrom(2048)
            answers, rcode = self._parse_response(data, expected_xid=xid)
            if rcode != RCODE_NOERROR:
                return None
            for name, qtype, rdata in answers:
                if qtype == QTYPE_A and len(rdata) == 4:
                    return ".".join(str(b) for b in rdata)
            return None
        except (socket.timeout, OSError):
            return None
        finally:
            sock.close()

    # send a PTR query for an ipv4 (i.e. resolve in-addr.arpa) and return the first decoded name, or None
    def resolve_ptr(self, ip: str, timeout_sec: float = 3.0) -> Optional[str]:

        parts = ip.split(".")
        if len(parts) != 4:
            return None
        arpa = ".".join(reversed(parts)) + ".in-addr.arpa"

        xid = random.getrandbits(16)
        query = self._build_query(xid, arpa, QTYPE_PTR)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("0.0.0.0", 0))
            sock.settimeout(timeout_sec)
            sock.sendto(query, (self.server_ip, self.server_port))

            data, _ = sock.recvfrom(2048)
            answers, rcode = self._parse_response(data, expected_xid=xid)
            if rcode != RCODE_NOERROR:
                return None
            for name, qtype, rdata in answers:
                if qtype == QTYPE_PTR:
                    decoded, _ = self._read_name(data, 0, fresh_buffer=rdata)
                    return decoded
            return None
        except (socket.timeout, OSError):
            return None
        finally:
            sock.close()

    # build a wire-format DNS query packet. flags: standard query (opcode 0), RD set so well-behaved
    # caching resolvers would recurse on our behalf — our server returns RA=false honestly
    def _build_query(self, xid: int, fqdn: str, qtype: int) -> bytes:

        # header: id(2) flags(2) qdcount(2) ancount(2) nscount(2) arcount(2)
        flags = 0x0100  # QR=0, opcode=0, RD=1
        header = struct.pack("!HHHHHH", xid, flags, 1, 0, 0, 0)
        qname = self._encode_name(fqdn)
        return header + qname + struct.pack("!HH", qtype, QCLASS_IN)

    # encode a dotted name into wire-format length-prefixed labels terminated by a zero byte
    @staticmethod
    def _encode_name(fqdn: str) -> bytes:

        out = bytearray()
        for label in fqdn.split("."):
            if not label:
                continue
            label_bytes = label.encode("ascii")[:63]
            out.append(len(label_bytes))
            out.extend(label_bytes)
        out.append(0)
        return bytes(out)

    # parse the DNS response header + answer section. returns (answers, rcode) where each answer is
    # (name, qtype, raw_rdata_bytes). silently bails on anything malformed
    def _parse_response(self, data: bytes, expected_xid: int) -> Tuple[list, int]:

        if len(data) < 12:
            return [], RCODE_FORMERR
        xid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
        if xid != expected_xid:
            return [], RCODE_FORMERR
        rcode = flags & 0x000F

        i = 12
        # skip questions
        for _ in range(qdcount):
            _, i = self._read_name(data, i)
            i += 4  # qtype + qclass

        # parse answers
        answers = []
        for _ in range(ancount):
            name, i = self._read_name(data, i)
            if i + 10 > len(data):
                break
            qtype, qclass, ttl, rdlength = struct.unpack("!HHIH", data[i:i + 10])
            i += 10
            if i + rdlength > len(data):
                break
            rdata = data[i:i + rdlength]
            i += rdlength
            answers.append((name, qtype, rdata))

        return answers, rcode

    # read a wire-format name from data at offset i; supports compression pointers with a hop limit so
    # adversarial packets can't loop us. when fresh_buffer is set we read from that buffer relative to
    # i=0 (used when rdata contains a name to decode against the same packet)
    def _read_name(self, data: bytes, i: int, fresh_buffer: Optional[bytes] = None) -> Tuple[str, int]:

        buf = fresh_buffer if fresh_buffer is not None else data
        labels = []
        hops = 0
        cursor = i
        jumped = False
        end_of_name = i

        while cursor < len(buf):
            b = buf[cursor]
            if b == 0:
                if not jumped:
                    end_of_name = cursor + 1
                return ".".join(labels), end_of_name

            # compression pointer: top two bits set; offset always references the original packet
            if (b & 0xC0) == 0xC0:
                if cursor + 1 >= len(buf):
                    return "", end_of_name
                ptr = ((b & 0x3F) << 8) | buf[cursor + 1]
                if not jumped:
                    end_of_name = cursor + 2
                    jumped = True
                cursor = ptr
                buf = data  # pointers always reference the full packet
                hops += 1
                if hops > 16:
                    return "", end_of_name
                continue

            # regular label
            if cursor + 1 + b > len(buf):
                return "", end_of_name
            labels.append(buf[cursor + 1:cursor + 1 + b].decode("ascii", errors="replace"))
            cursor += 1 + b

        return ".".join(labels), end_of_name


# minimal cli driver for smoke testing against the c++ DnsServer
if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser(description="raw-socket dns client smoke test")
    parser.add_argument("--server", required=True, help="dns server ip / hostname")
    parser.add_argument("--port", type=int, default=53, help="dns server udp port")
    parser.add_argument("--name", required=True, help="fqdn to resolve")
    parser.add_argument("--type", choices=["A", "PTR"], default="A", help="record type")
    args = parser.parse_args()

    client = DnsClient(server_ip=args.server, server_port=args.port)
    if args.type == "A":
        result = client.resolve_a(args.name)
        print(f"A {args.name} -> {result}")
    else:
        result = client.resolve_ptr(args.name)
        print(f"PTR {args.name} -> {result}")
