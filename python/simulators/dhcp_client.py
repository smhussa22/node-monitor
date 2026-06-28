import hashlib
import random
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Optional


# DHCP option codes per RFC 2132
OPT_SUBNET_MASK = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_HOSTNAME = 12
OPT_REQUESTED_IP = 50
OPT_LEASE_TIME = 51
OPT_MSG_TYPE = 53
OPT_SERVER_ID = 54
OPT_PARAM_LIST = 55
OPT_END = 255

# DHCP message types carried in option 53
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7

# the BOOTP magic cookie that immediately follows the 236-byte fixed header
MAGIC_COOKIE = b"\x63\x82\x53\x63"

# option 55 wish list the client sends; the server tries to honor by including these in OFFER / ACK
PARAM_REQUEST_LIST = bytes([OPT_SUBNET_MASK, OPT_ROUTER, OPT_DNS, OPT_LEASE_TIME, OPT_SERVER_ID])


# decoded result of a successful DORA exchange
@dataclass
class DhcpLease:

    ip: str               # acquired ipv4 address in dotted-quad form
    mask: str             # subnet mask (option 1) in dotted-quad form
    gateway: str          # default gateway (option 3); empty string when server didn't send one
    dns: str              # dns server (option 6); empty string when server didn't send one
    lease_seconds: int    # lease duration in seconds (option 51)
    server_id: str        # dhcp server identifier (option 54); used in REQUEST + RELEASE


# derive a deterministic locally-administered ethernet mac from a hostname so each simulated device gets
# a stable, unique 48-bit identifier without needing a DHCP reservation table
def mac_from_hostname(hostname: str) -> bytes:

    h = hashlib.sha256(hostname.encode("utf-8")).digest()
    # set the locally-administered bit (b1=1) and clear the multicast bit (b0=0) on the first octet
    first = (h[0] | 0x02) & 0xFE
    return bytes([first]) + h[1:6]


# raw 4 bytes -> "a.b.c.d"
def bytes_to_ipv4(b: bytes) -> str:

    return ".".join(str(x) for x in b[:4])


# "a.b.c.d" -> raw 4 bytes
def ipv4_to_bytes(ip: str) -> bytes:

    return bytes(int(o) for o in ip.split("."))


# raw-socket dhcp client that runs the full RFC 2131 DORA exchange against a configured unicast server.
# designed for kubernetes overlays where layer-2 broadcast doesn't cross pod boundaries — the dhcp server
# clusterip is injected at deploy time, so the discover packet is unicast directly to it
class DhcpClient:

    def __init__(self, hostname: str, server_ip: str, server_port: int = 67):

        self.hostname: str = hostname                          # name advertised in option 12
        self.server_ip: str = server_ip                        # configured unicast dhcp server address
        self.server_port: int = server_port                    # dhcp server udp port; RFC default 67
        self.mac: bytes = mac_from_hostname(hostname)          # 6-byte ethernet mac derived from hostname
        self.xid: int = random.getrandbits(32)                 # bootp transaction id; rerolled per acquire
        self.lease: Optional[DhcpLease] = None                 # current lease; None until acquire() succeeds
        self.running: bool = False                             # whether the renewal thread is active
        self.renew_thread: Optional[threading.Thread] = None   # background renewal worker

    # run a full DORA exchange. raises RuntimeError on NAK; raises socket.timeout when the server
    # doesn't reply within timeout_sec. returns the bound DhcpLease on success and caches it on self.lease
    def acquire(self, timeout_sec: float = 10.0) -> DhcpLease:

        # fresh transaction id per acquire so renewals don't collide with prior offers in the air
        self.xid = random.getrandbits(32)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("0.0.0.0", 0))
            sock.settimeout(timeout_sec)

            # 1. DISCOVER → wait for OFFER
            sock.sendto(self._build_discover(), (self.server_ip, self.server_port))
            offer = self._recv_with_xid(sock, expect=DHCP_OFFER)
            offered_ip = offer["yiaddr"]
            server_id = offer["options"].get(OPT_SERVER_ID, self.server_ip)

            # 2. REQUEST → wait for ACK
            sock.sendto(self._build_request(offered_ip, server_id), (self.server_ip, self.server_port))
            ack = self._recv_with_xid(sock, expect=DHCP_ACK)

            opts = ack["options"]
            self.lease = DhcpLease(
                ip=ack["yiaddr"],
                mask=opts.get(OPT_SUBNET_MASK, "0.0.0.0"),
                gateway=opts.get(OPT_ROUTER, ""),
                dns=opts.get(OPT_DNS, ""),
                lease_seconds=int(opts.get(OPT_LEASE_TIME, 3600)),
                server_id=opts.get(OPT_SERVER_ID, self.server_ip),
            )
            return self.lease
        finally:
            sock.close()

    # spawn a background thread that renews the lease at T1 (50% of lease). renewal is just a
    # repeat of DORA — simpler than tracking SELECTING / RENEWING state separately and the server
    # treats both flows identically
    def start_renewal(self) -> None:

        if self.running or self.lease is None: return

        self.running = True
        self.renew_thread = threading.Thread(target=self._renewal_loop, daemon=True)
        self.renew_thread.start()

    # stop the renewal thread; safe to call even if start_renewal was never invoked
    def stop(self) -> None:

        self.running = False
        if self.renew_thread is not None and self.renew_thread.is_alive():
            self.renew_thread.join(timeout=2.0)
        self.renew_thread = None

    # send a RELEASE so the server can immediately reclaim the ip on clean shutdown
    def release(self) -> None:

        if self.lease is None: return

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("0.0.0.0", 0))
            sock.sendto(self._build_release(), (self.server_ip, self.server_port))
        finally:
            sock.close()

    # background renewal loop; sleeps in 1-second slices so stop() interrupts quickly
    def _renewal_loop(self) -> None:

        while self.running and self.lease is not None:
            t1 = max(30, self.lease.lease_seconds // 2)
            slept = 0
            while slept < t1 and self.running:
                time.sleep(1.0)
                slept += 1
            if not self.running: break
            try:
                self.acquire()
            except Exception as e:
                print(f"[dhcp] renewal failed for {self.hostname}: {e}")
                time.sleep(5.0)

    # build a DISCOVER packet
    def _build_discover(self) -> bytes:

        opts = (
            self._encode_option(OPT_MSG_TYPE, bytes([DHCP_DISCOVER]))
            + self._encode_option(OPT_PARAM_LIST, PARAM_REQUEST_LIST)
            + self._encode_option(OPT_HOSTNAME, self.hostname.encode("utf-8")[:255])
            + bytes([OPT_END])
        )
        return self._bootp_header(ciaddr=0) + MAGIC_COOKIE + opts

    # build a REQUEST packet referencing the offered ip and server identifier
    def _build_request(self, offered_ip: str, server_id: str) -> bytes:

        opts = (
            self._encode_option(OPT_MSG_TYPE, bytes([DHCP_REQUEST]))
            + self._encode_option(OPT_REQUESTED_IP, ipv4_to_bytes(offered_ip))
            + self._encode_option(OPT_SERVER_ID, ipv4_to_bytes(server_id))
            + self._encode_option(OPT_PARAM_LIST, PARAM_REQUEST_LIST)
            + self._encode_option(OPT_HOSTNAME, self.hostname.encode("utf-8")[:255])
            + bytes([OPT_END])
        )
        return self._bootp_header(ciaddr=0) + MAGIC_COOKIE + opts

    # build a RELEASE packet so the server can clean up our binding
    def _build_release(self) -> bytes:

        ip = self.lease.ip if self.lease else "0.0.0.0"
        srv = self.lease.server_id if self.lease else self.server_ip
        ciaddr_int = struct.unpack("!I", ipv4_to_bytes(ip))[0]
        opts = (
            self._encode_option(OPT_MSG_TYPE, bytes([DHCP_RELEASE]))
            + self._encode_option(OPT_SERVER_ID, ipv4_to_bytes(srv))
            + bytes([OPT_END])
        )
        return self._bootp_header(ciaddr=ciaddr_int) + MAGIC_COOKIE + opts

    # build the fixed 236-byte BOOTP header (no cookie, no options)
    def _bootp_header(self, ciaddr: int) -> bytes:

        op = 1                              # 1 = BOOTREQUEST
        htype = 1                           # 1 = ethernet
        hlen = 6                            # 6 = ethernet mac length
        hops = 0                            # set by relay agents only
        chaddr = self.mac + b"\x00" * 10    # 16 bytes; first 6 = mac, rest zero-padded
        sname = b"\x00" * 64                # optional server hostname; we leave empty
        file_ = b"\x00" * 128               # optional boot file name; we leave empty

        # !BBBB I H H I I I I = 4 + 4 + 2 + 2 + 4*4 = 28 bytes
        header = struct.pack(
            "!BBBBIHHIIII",
            op, htype, hlen, hops,
            self.xid,
            0, 0,                           # secs, flags (flags=0 means unicast reply ok)
            ciaddr, 0, 0, 0,                # ciaddr, yiaddr, siaddr, giaddr
        )
        return header + chaddr + sname + file_

    # encode one option as (code, length, value)
    @staticmethod
    def _encode_option(code: int, value: bytes) -> bytes:
        return bytes([code, len(value)]) + value

    # block until a packet arrives matching our xid and the expected message type; ignores stray packets
    def _recv_with_xid(self, sock: socket.socket, expect: int) -> dict:

        while True:
            data, _ = sock.recvfrom(2048)
            pkt = self._parse_packet(data)
            if pkt is None or pkt["xid"] != self.xid:
                continue
            mt = pkt["options"].get(OPT_MSG_TYPE)
            if mt == DHCP_NAK:
                raise RuntimeError("dhcp server replied with NAK")
            if mt != expect:
                continue
            return pkt

    # parse a raw dhcp packet into a dict with bootp fields + decoded options. returns None on malformed
    def _parse_packet(self, data: bytes) -> Optional[dict]:

        if len(data) < 240:
            return None
        op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr = struct.unpack("!BBBBIHHIIII", data[:28])
        if data[236:240] != MAGIC_COOKIE:
            return None

        # walk the options blob; decode known codes into convenient python types
        opts: dict = {}
        i = 240
        while i < len(data):
            code = data[i]
            if code == 0:
                i += 1
                continue
            if code == OPT_END:
                break
            if i + 1 >= len(data): break
            length = data[i + 1]
            if i + 2 + length > len(data): break
            val = data[i + 2:i + 2 + length]

            if code == OPT_MSG_TYPE and length == 1:
                opts[code] = val[0]
            elif code in (OPT_SUBNET_MASK, OPT_ROUTER, OPT_DNS, OPT_SERVER_ID) and length >= 4:
                opts[code] = bytes_to_ipv4(val[:4])
            elif code == OPT_LEASE_TIME and length == 4:
                opts[code] = struct.unpack("!I", val)[0]
            else:
                opts[code] = val
            i += 2 + length

        return {
            "op": op,
            "xid": xid,
            "yiaddr": bytes_to_ipv4(struct.pack("!I", yiaddr)),
            "ciaddr": bytes_to_ipv4(struct.pack("!I", ciaddr)),
            "options": opts,
            "msg_type": opts.get(OPT_MSG_TYPE),
        }


# minimal cli driver: useful for smoke testing the c++ DhcpServer in a docker compose stack
if __name__ == "__main__":

    import argparse

    parser = argparse.ArgumentParser(description="raw-socket dhcp client smoke test")
    parser.add_argument("--server", required=True, help="dhcp server ip (unicast)")
    parser.add_argument("--port", type=int, default=67, help="dhcp server udp port")
    parser.add_argument("--hostname", default="dhcp-client-test", help="client hostname for option 12")
    parser.add_argument("--renew", action="store_true", help="start the renewal thread after acquire")
    args = parser.parse_args()

    client = DhcpClient(hostname=args.hostname, server_ip=args.server, server_port=args.port)
    lease = client.acquire()
    print(f"acquired: ip={lease.ip} mask={lease.mask} gateway={lease.gateway} dns={lease.dns} lease={lease.lease_seconds}s server={lease.server_id}")

    if args.renew:
        client.start_renewal()
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            client.release()
            client.stop()
