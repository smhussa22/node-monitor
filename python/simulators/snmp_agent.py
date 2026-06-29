import socket
import struct
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple


# ---- BER tag constants -----------------------------------------------------------------------------------

TAG_INTEGER       = 0x02
TAG_OCTET_STRING  = 0x04
TAG_NULL          = 0x05
TAG_OID           = 0x06
TAG_SEQUENCE      = 0x30

TAG_IP_ADDRESS    = 0x40
TAG_COUNTER32     = 0x41
TAG_GAUGE32       = 0x42
TAG_TIME_TICKS    = 0x43
TAG_COUNTER64     = 0x46

TAG_NO_SUCH_OBJECT   = 0x80
TAG_NO_SUCH_INSTANCE = 0x81
TAG_END_OF_MIB_VIEW  = 0x82

TAG_GET_REQUEST      = 0xA0
TAG_GET_NEXT_REQUEST = 0xA1
TAG_RESPONSE         = 0xA2
TAG_GET_BULK_REQUEST = 0xA5


# ---- BER encoders ----------------------------------------------------------------------------------------

# emit BER length: short form for <128, long form (0x8X + X bytes big-endian) otherwise
def _enc_length(n: int) -> bytes:

    if n < 128: return bytes([n])
    raw = b""
    while n > 0:
        raw = bytes([n & 0xFF]) + raw
        n >>= 8
    return bytes([0x80 | len(raw)]) + raw


# wrap raw bytes in a tag+length envelope
def _enc_tlv(tag: int, content: bytes) -> bytes:

    return bytes([tag]) + _enc_length(len(content)) + content


# minimal signed-integer encoder with two's-complement padding rules
def enc_integer(v: int) -> bytes:

    if v == 0:
        body = b"\x00"
    elif v > 0:
        out = b""
        x = v
        while x > 0:
            out = bytes([x & 0xFF]) + out
            x >>= 8
        if out[0] & 0x80:
            out = b"\x00" + out  # avoid being mistaken for negative
        body = out
    else:
        # two's complement: extend until the high byte's sign bit is set and the next shift would lose info
        out = b""
        x = v
        while True:
            b = x & 0xFF
            out = bytes([b]) + out
            x >>= 8
            if x == -1 and (b & 0x80):
                break
        body = out
    return _enc_tlv(TAG_INTEGER, body)


def enc_octet_string(s: str) -> bytes:
    return _enc_tlv(TAG_OCTET_STRING, s.encode("utf-8"))


def enc_null() -> bytes:
    return bytes([TAG_NULL, 0])


# unsigned 32 encoder shared by Counter32 / Gauge32 / TimeTicks; pads with 0x00 if high bit is set
def _enc_uint32_body(v: int) -> bytes:

    if v == 0:
        return b"\x00"
    out = b""
    while v > 0:
        out = bytes([v & 0xFF]) + out
        v >>= 8
    if out[0] & 0x80:
        out = b"\x00" + out
    return out


def enc_counter32(v: int) -> bytes:
    return _enc_tlv(TAG_COUNTER32, _enc_uint32_body(v))


def enc_gauge32(v: int) -> bytes:
    return _enc_tlv(TAG_GAUGE32, _enc_uint32_body(v))


def enc_time_ticks(v: int) -> bytes:
    return _enc_tlv(TAG_TIME_TICKS, _enc_uint32_body(v))


# encode an OID (tuple/list of arcs) using the packed-first-two-arcs + base-128-variable-length form
def enc_oid(arcs) -> bytes:

    if len(arcs) < 2:
        body = b""
        for a in arcs:
            body += _enc_arc(a)
    else:
        packed = arcs[0] * 40 + arcs[1]
        body = _enc_arc(packed)
        for a in arcs[2:]:
            body += _enc_arc(a)
    return _enc_tlv(TAG_OID, body)


# variable-length base-128 with continuation-bit (high bit set on all but last byte)
def _enc_arc(v: int) -> bytes:

    if v == 0:
        return b"\x00"
    digits = []
    while v > 0:
        digits.append(v & 0x7F)
        v >>= 7
    out = bytearray()
    for i in range(len(digits) - 1, -1, -1):
        b = digits[i]
        if i > 0:
            b |= 0x80
        out.append(b)
    return bytes(out)


def enc_sequence(content: bytes) -> bytes:
    return _enc_tlv(TAG_SEQUENCE, content)


# ---- BER decoders ----------------------------------------------------------------------------------------

# parse the BER length field at offset; returns (length, bytes_consumed_total_including_tag_byte_already_at_offset)
# returns (None, 0) on malformed input
def _dec_length(data: bytes, offset: int) -> Tuple[Optional[int], int]:

    if offset >= len(data):
        return None, 0
    b = data[offset]
    if b < 128:
        return b, 1
    k = b & 0x7F
    if k == 0 or k > 4 or offset + 1 + k > len(data):
        return None, 0
    n = 0
    for i in range(k):
        n = (n << 8) | data[offset + 1 + i]
    return n, 1 + k


# parse a TLV header at offset; returns (tag, value_offset, value_length, total_size) or None
def _dec_tlv(data: bytes, offset: int) -> Optional[Tuple[int, int, int, int]]:

    if offset >= len(data):
        return None
    tag = data[offset]
    length, consumed = _dec_length(data, offset + 1)
    if length is None:
        return None
    value_offset = offset + 1 + consumed
    if value_offset + length > len(data):
        return None
    return tag, value_offset, length, (value_offset + length - offset)


# decode a signed integer body of given length at offset. seeds with -1 for negative values so the
# shift+or loop naturally produces a correctly-signed python int via the language's arbitrary-precision
# semantics — no post-mask required (an earlier version had one and double-negated already-signed values)
def _dec_integer(data: bytes, offset: int, length: int) -> int:

    if length == 0:
        return 0
    v = -1 if (data[offset] & 0x80) else 0
    for i in range(length):
        v = (v << 8) | data[offset + i]
    return v


# decode an OID from a value region into a list of arcs
def _dec_oid(data: bytes, offset: int, length: int) -> List[int]:

    if length == 0:
        return []
    arcs: List[int] = []
    cursor = offset
    end = offset + length

    # first byte unpacks into two arcs
    first, cursor = _dec_arc(data, cursor, end)
    if first is None:
        return []
    if first < 80:
        arcs.append(first // 40)
        arcs.append(first % 40)
    else:
        arcs.append(2)
        arcs.append(first - 80)

    while cursor < end:
        a, cursor = _dec_arc(data, cursor, end)
        if a is None:
            return arcs
        arcs.append(a)
    return arcs


def _dec_arc(data: bytes, cursor: int, end: int) -> Tuple[Optional[int], int]:

    v = 0
    consumed = 0
    while cursor < end:
        b = data[cursor]
        cursor += 1
        v = (v << 7) | (b & 0x7F)
        consumed += 1
        if not (b & 0x80):
            return v, cursor
        if consumed > 5:
            return None, cursor
    return None, cursor


# ---- MIB tree -------------------------------------------------------------------------------------------

# convert "1.3.6.1..." string -> tuple of ints; tuples are hashable and comparable lexicographically
def oid_str_to_tuple(s: str) -> Tuple[int, ...]:
    return tuple(int(x) for x in s.split("."))


def oid_tuple_to_str(arcs) -> str:
    return ".".join(str(a) for a in arcs)


# minimal MIB tree. each entry is an OID (as a tuple) mapped to a (type_tag, callable). the callable is
# evaluated at query time so values reflect current state (uptime ticks up, cpu varies). responses are
# returned to the agent which encodes them according to the type_tag
class MibTree:

    def __init__(self):

        self.entries: Dict[Tuple[int, ...], Tuple[int, Callable[[], object]]] = { } # oid -> (tag, resolver fn)

    # register one OID -> (type_tag, callable) entry. type_tag is one of TAG_OCTET_STRING / TAG_GAUGE32 /
    # TAG_TIME_TICKS / TAG_INTEGER. the callable is invoked at query time
    def set(self, oid: str, type_tag: int, resolver: Callable[[], object]) -> None:

        self.entries[oid_str_to_tuple(oid)] = (type_tag, resolver)

    # look up an exact OID; returns (tag, raw_python_value) or None
    def get(self, oid: Tuple[int, ...]) -> Optional[Tuple[int, object]]:

        rec = self.entries.get(oid)
        if rec is None:
            return None
        return rec[0], rec[1]()

    # GETNEXT: return the lexicographically smallest OID strictly greater than `oid` along with its value.
    # returns None when no such OID exists in the tree (the caller should respond with endOfMibView)
    def get_next(self, oid: Tuple[int, ...]) -> Optional[Tuple[Tuple[int, ...], int, object]]:

        candidates = [k for k in self.entries.keys() if k > oid]
        if not candidates:
            return None
        nxt = min(candidates)
        tag, fn = self.entries[nxt]
        return nxt, tag, fn()


# ---- SNMP agent ----------------------------------------------------------------------------------------

# encode one varbind: SEQUENCE { OID, value }. value type is dispatched on tag
def _enc_varbind(oid: Tuple[int, ...], tag: int, value: object) -> bytes:

    name = enc_oid(oid)
    if tag == TAG_OCTET_STRING:
        val = enc_octet_string(str(value))
    elif tag == TAG_INTEGER:
        val = enc_integer(int(value))
    elif tag == TAG_GAUGE32:
        val = enc_gauge32(int(value))
    elif tag == TAG_COUNTER32:
        val = enc_counter32(int(value))
    elif tag == TAG_TIME_TICKS:
        val = enc_time_ticks(int(value))
    elif tag == TAG_NULL:
        val = enc_null()
    elif tag in (TAG_NO_SUCH_OBJECT, TAG_NO_SUCH_INSTANCE, TAG_END_OF_MIB_VIEW):
        val = bytes([tag, 0])
    else:
        val = enc_null()
    return enc_sequence(name + val)


# raw-socket SNMP v2c agent. binds UDP/161, parses GetRequest / GetNextRequest, looks up each varbind's
# OID in the MIB tree, and replies with a Response message carrying the same request id. SET is rejected
# with notWritable; GetBulk is rejected with notImpl
class SnmpAgent:

    def __init__(self, mib: MibTree, port: int = 161, community: str = "public"):

        self.mib: MibTree = mib                          # MIB tree this agent serves
        self.port: int = port                            # udp port to bind; RFC default is 161
        self.community: str = community                  # expected community string; v1/v2c shared secret
        self.running: bool = False                       # whether the receive loop is active
        self.thread: Optional[threading.Thread] = None   # background receive worker
        self.sock: Optional[socket.socket] = None        # bound udp socket

        # counters surfaced via the simulator's existing telemetry; cheap visibility into the wire activity
        self.got_count: int = 0                          # total queries served (any pdu type)
        self.error_count: int = 0                        # malformed or unauthenticated requests dropped

    def start(self) -> None:

        if self.running: return
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind(("0.0.0.0", self.port))
        except PermissionError:
            print(f"[snmp] failed to bind udp:{self.port} (privileged port; need root or NET_BIND_SERVICE)")
            self.running = False
            self.sock.close()
            self.sock = None
            return
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def stop(self) -> None:

        if not self.running: return
        self.running = False
        try:
            if self.sock is not None: self.sock.close()
        except OSError:
            pass
        self.sock = None
        if self.thread is not None: self.thread.join(timeout=2.0)
        self.thread = None

    def _loop(self) -> None:

        assert self.sock is not None
        while self.running:
            try:
                data, peer = self.sock.recvfrom(4096)
            except OSError:
                if self.running:
                    self.error_count += 1
                continue

            response = self._handle(data)
            if response is None:
                self.error_count += 1
                continue
            try:
                self.sock.sendto(response, peer)
                self.got_count += 1
            except OSError:
                self.error_count += 1

    # parse one request and synthesize the response. returns the encoded reply bytes or None on a
    # malformed packet that we cannot turn into a coherent error response (we drop it instead)
    def _handle(self, data: bytes) -> Optional[bytes]:

        # outer SEQUENCE
        outer = _dec_tlv(data, 0)
        if outer is None or outer[0] != TAG_SEQUENCE:
            return None
        pos = outer[1]
        end = outer[1] + outer[2]

        # version INTEGER
        ver_tlv = _dec_tlv(data, pos)
        if ver_tlv is None or ver_tlv[0] != TAG_INTEGER:
            return None
        version = _dec_integer(data, ver_tlv[1], ver_tlv[2])
        pos += ver_tlv[3]

        # community OCTET STRING
        com_tlv = _dec_tlv(data, pos)
        if com_tlv is None or com_tlv[0] != TAG_OCTET_STRING:
            return None
        community = bytes(data[com_tlv[1]:com_tlv[1] + com_tlv[2]]).decode("utf-8", errors="replace")
        if community != self.community:
            return None  # silent drop; matches RFC 3416 guidance for community failures
        pos += com_tlv[3]

        # PDU
        pdu_tlv = _dec_tlv(data, pos)
        if pdu_tlv is None:
            return None
        pdu_tag = pdu_tlv[0]
        p_pos = pdu_tlv[1]
        p_end = pdu_tlv[1] + pdu_tlv[2]

        # request-id INTEGER
        rid_tlv = _dec_tlv(data, p_pos)
        if rid_tlv is None or rid_tlv[0] != TAG_INTEGER:
            return None
        request_id = _dec_integer(data, rid_tlv[1], rid_tlv[2])
        p_pos += rid_tlv[3]

        # error-status INTEGER, error-index INTEGER (ignored on requests)
        for _ in range(2):
            t = _dec_tlv(data, p_pos)
            if t is None:
                return None
            p_pos += t[3]

        # varbinds SEQUENCE OF SEQUENCE { OID, value }
        vbs_tlv = _dec_tlv(data, p_pos)
        if vbs_tlv is None or vbs_tlv[0] != TAG_SEQUENCE:
            return None

        query_oids: List[Tuple[int, ...]] = []
        vb_pos = vbs_tlv[1]
        vb_end = vbs_tlv[1] + vbs_tlv[2]
        while vb_pos < vb_end:
            vb = _dec_tlv(data, vb_pos)
            if vb is None or vb[0] != TAG_SEQUENCE:
                return None
            inner = vb[1]
            inner_end = vb[1] + vb[2]
            name_tlv = _dec_tlv(data, inner)
            if name_tlv is None or name_tlv[0] != TAG_OID:
                return None
            oid = _dec_oid(data, name_tlv[1], name_tlv[2])
            query_oids.append(tuple(oid))
            vb_pos += vb[3]

        # build the response varbinds based on PDU type
        response_vbs: bytes = b""
        for q_oid in query_oids:
            if pdu_tag == TAG_GET_REQUEST:
                res = self.mib.get(q_oid)
                if res is None:
                    response_vbs += _enc_varbind(q_oid, TAG_NO_SUCH_INSTANCE, None)
                else:
                    tag, value = res
                    response_vbs += _enc_varbind(q_oid, tag, value)
            elif pdu_tag == TAG_GET_NEXT_REQUEST:
                nxt = self.mib.get_next(q_oid)
                if nxt is None:
                    response_vbs += _enc_varbind(q_oid, TAG_END_OF_MIB_VIEW, None)
                else:
                    nxt_oid, nxt_tag, nxt_val = nxt
                    response_vbs += _enc_varbind(nxt_oid, nxt_tag, nxt_val)
            else:
                # GET_BULK / SET / anything else not implemented yet
                response_vbs += _enc_varbind(q_oid, TAG_NO_SUCH_OBJECT, None)

        # wrap into a Response PDU
        pdu_body = enc_integer(request_id) + enc_integer(0) + enc_integer(0) + enc_sequence(response_vbs)
        pdu = _enc_tlv(TAG_RESPONSE, pdu_body)

        # wrap the outer SEQUENCE { version, community, response-PDU }
        out = enc_integer(version) + enc_octet_string(self.community) + pdu
        return enc_sequence(out)


# ---- helpers a simulator uses to populate a baseline MIB ------------------------------------------------

# install the standard mib-II scalar OIDs every device serves, plus a small enterprise subtree for the
# vendor-specific gauges. enterprise number 99999 is unassigned and used here only for the demo zone
ENTERPRISE_BASE = "1.3.6.1.4.1.99999"


def install_baseline(mib: MibTree, hostname: str, vendor: str, descr: str, boot_time: float, get_cpu: Callable[[], float], get_mem: Callable[[], float]) -> None:

    mib.set("1.3.6.1.2.1.1.1.0", TAG_OCTET_STRING, lambda: descr)                                # sysDescr.0
    mib.set("1.3.6.1.2.1.1.3.0", TAG_TIME_TICKS,   lambda: int((time.time() - boot_time) * 100)) # sysUpTime.0
    mib.set("1.3.6.1.2.1.1.4.0", TAG_OCTET_STRING, lambda: "ops@node-monitor.local")             # sysContact.0
    mib.set("1.3.6.1.2.1.1.5.0", TAG_OCTET_STRING, lambda: hostname)                             # sysName.0
    mib.set("1.3.6.1.2.1.1.6.0", TAG_OCTET_STRING, lambda: "node-monitor demo zone")             # sysLocation.0

    mib.set(f"{ENTERPRISE_BASE}.1.0", TAG_OCTET_STRING, lambda: vendor)                # vendor tag
    mib.set(f"{ENTERPRISE_BASE}.2.0", TAG_GAUGE32,      lambda: max(0, min(100, int(get_cpu()))))
    mib.set(f"{ENTERPRISE_BASE}.3.0", TAG_GAUGE32,      lambda: max(0, min(100, int(get_mem()))))


# the SNMPv2-Trap PDU tag (context-specific constructed)
TAG_TRAP_V2 = 0xA7

# encode a SNMPv2-Trap message and unicast it to (host, port). per RFC 3416 4.2.6 a v2 trap PDU has
# the same shape as a Response and its first two varbinds are required: sysUpTime.0 and snmpTrapOID.0.
# event_oid is the OID identifying *what kind of event* this trap reports; extra_vbs adds context-specific
# varbinds in the (oid, type_tag, value) tuple shape
def send_trap(host: str, port: int, community: str, sys_uptime_ticks: int, event_oid: str, extra_vbs: list) -> bool:

    import random as _r

    # SNMPv2 mandates these two varbinds at the head of every notification PDU
    sys_uptime_oid = (1, 3, 6, 1, 2, 1, 1, 3, 0)
    snmp_trap_oid  = (1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0)

    head_vb1 = enc_sequence(enc_oid(sys_uptime_oid) + enc_time_ticks(int(sys_uptime_ticks)))
    head_vb2 = enc_sequence(enc_oid(snmp_trap_oid) + enc_oid(oid_str_to_tuple(event_oid)))

    extras = b""
    for oid_str, tag, value in extra_vbs:
        oid_tuple = oid_str_to_tuple(oid_str)
        name = enc_oid(oid_tuple)
        if tag == TAG_OCTET_STRING:
            val = enc_octet_string(str(value))
        elif tag == TAG_INTEGER:
            val = enc_integer(int(value))
        elif tag == TAG_GAUGE32:
            val = enc_gauge32(int(value))
        elif tag == TAG_COUNTER32:
            val = enc_counter32(int(value))
        elif tag == TAG_TIME_TICKS:
            val = enc_time_ticks(int(value))
        else:
            val = enc_null()
        extras += enc_sequence(name + val)

    vbs_seq = enc_sequence(head_vb1 + head_vb2 + extras)
    pdu_body = enc_integer(_r.getrandbits(31)) + enc_integer(0) + enc_integer(0) + vbs_seq
    pdu = _enc_tlv(TAG_TRAP_V2, pdu_body)
    msg = enc_sequence(enc_integer(1) + enc_octet_string(community) + pdu)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(msg, (host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


# install a minimal IF-MIB subset so the poller can demonstrate a real GETNEXT-driven table walk.
# columns implemented per RFC 2863: ifIndex (1), ifDescr (2), ifAdminStatus (7), ifOperStatus (8),
# ifInOctets (10), ifOutOctets (16). counters tick monotonically based on a per-interface baseline
def install_iftable(mib: MibTree, n_interfaces: int = 3) -> None:

    import random

    mib.set("1.3.6.1.2.1.2.1.0", TAG_INTEGER, lambda: n_interfaces)  # ifNumber.0

    # interface counters; simulated as a steady byte rate per interface so two consecutive walks see growth
    base_t = time.time()
    rates = [random.uniform(1_000_000, 50_000_000) for _ in range(n_interfaces)]  # bytes per second

    for i in range(1, n_interfaces + 1):
        idx = i
        descr = f"GigabitEthernet0/{i - 1}"
        rate = rates[i - 1]
        mib.set(f"1.3.6.1.2.1.2.2.1.1.{idx}",  TAG_INTEGER,      lambda x=idx: x)                                       # ifIndex
        mib.set(f"1.3.6.1.2.1.2.2.1.2.{idx}",  TAG_OCTET_STRING, lambda d=descr: d)                                     # ifDescr
        mib.set(f"1.3.6.1.2.1.2.2.1.7.{idx}",  TAG_INTEGER,      lambda: 1)                                              # ifAdminStatus (1=up)
        mib.set(f"1.3.6.1.2.1.2.2.1.8.{idx}",  TAG_INTEGER,      lambda: 1 if random.random() > 0.05 else 2)             # ifOperStatus (occasional flap)
        mib.set(f"1.3.6.1.2.1.2.2.1.10.{idx}", TAG_COUNTER32,    lambda r=rate: int(r * (time.time() - base_t)) & 0xFFFFFFFF)   # ifInOctets
        mib.set(f"1.3.6.1.2.1.2.2.1.16.{idx}", TAG_COUNTER32,    lambda r=rate: int(r * 0.85 * (time.time() - base_t)) & 0xFFFFFFFF) # ifOutOctets
