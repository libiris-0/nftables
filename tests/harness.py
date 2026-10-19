"""Shared fixture for the isolated test suites."""

import json
import os
import random
import select
import socket
import struct
import subprocess
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ETC = ROOT / 'etc'
CONF = ETC / 'nftables.conf.d'
FIXTURES = ROOT / 'tests/fixtures'


def defines(path):
    values = {}
    for line in path.read_text().splitlines():
        if not line.startswith('define '):
            continue
        name, _, value = line[len('define '):].partition(' = ')
        value = value.strip()
        if value.startswith('"'):
            values[name] = value.strip('"')
        elif value.startswith('0x') and '-' in value:
            low, high = value.split('-')
            values[name] = range(int(low, 0), int(high, 0) + 1)
        else:
            try:
                values[name] = int(value, 0)
            except ValueError:
                values[name] = value
    return values


D = defines(CONF / 'routing-defs.nft') | defines(CONF / 'divert.conf')
MASK = D['routing_mask']
PENDING = D['routing_pending']


def isolate():
    uid, gid = os.getuid(), os.getgid()
    os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNET)
    Path('/proc/self/setgroups').write_text('deny')
    Path('/proc/self/uid_map').write_text(f'0 {uid} 1')
    Path('/proc/self/gid_map').write_text(f'0 {gid} 1')


def local_cgroup():
    path = next(line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines()
                if line.startswith('0::'))
    return path.strip('/').partition('/')[0]


# Namespaces

class Netns:
    stack = []

    def __init__(self, name, fd):
        self.name, self.fd = name, fd

    @classmethod
    def current(cls, name):
        return cls(name, os.open('/proc/self/ns/net', os.O_RDONLY))

    @classmethod
    def new(cls, name):
        with HOST:
            os.unshare(os.CLONE_NEWNET)
            ns = cls.current(name)
        return ns

    @property
    def path(self):
        return f'/proc/{os.getpid()}/fd/{self.fd}'

    def __enter__(self):
        Netns.stack.append(os.open('/proc/self/ns/net', os.O_RDONLY))
        os.setns(self.fd, os.CLONE_NEWNET)
        return self

    def __exit__(self, *args):
        previous = Netns.stack.pop()
        os.setns(previous, os.CLONE_NEWNET)
        os.close(previous)

    def run(self, *args, input=None):
        with self:
            return run(*args, input=input)

    def ip(self, *args):
        return self.run('ip', *args)

    def sysctl(self, **values):
        with self:
            for key, value in values.items():
                Path('/proc/sys', key.replace('.', '/')).write_text(str(value))


HOST = None


def setup_host():
    global HOST
    HOST = Netns.current('host')
    HOST.ip('link', 'set', 'lo', 'up')
    return HOST


def peer(name):
    ns = Netns.new(name)
    ns.ip('link', 'set', 'lo', 'up')
    return ns


def run(*args, input=None):
    result = subprocess.run(args, input=input, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f'{" ".join(map(str, args))}: {result.stderr.strip()}')
    return result.stdout


def nft(text, include=None):
    args = ['nft'] + (['-I', str(include)] if include else []) + ['-f', '-']
    return run(*args, input=text)


def nft_json(*args):
    return json.loads(run('nft', '-j', *args))['nftables']


# Links and addresses

_mac = iter(range(1, 1 << 16))


def link(a, a_name, b, b_name, addresses):
    """Connect two namespaces with a veth pair.

    addresses maps 4 and 6 to (a_addr, b_addr, prefix). Neighbours are static,
    so neighbour discovery never depends on the policy under test.
    """
    macs = [f'02:00:00:00:{n >> 8:02x}:{n & 0xff:02x}' for n in (next(_mac), next(_mac))]
    a.ip('link', 'add', a_name, 'address', macs[0], 'type', 'veth',
         'peer', 'name', b_name, 'address', macs[1], 'netns', b.path)
    for ns, name in ((a, a_name), (b, b_name)):
        ns.ip('link', 'set', name, 'up')
    for v, (a_addr, b_addr, prefix) in addresses.items():
        nodad = ('nodad',) if v == 6 else ()
        for ns, name, addr, other, mac in ((a, a_name, a_addr, b_addr, macs[1]),
                                           (b, b_name, b_addr, a_addr, macs[0])):
            ns.ip(f'-{v}', 'addr', 'add', f'{addr}/{prefix}', 'dev', name, *nodad)
            ns.ip(f'-{v}', 'neigh', 'replace', other, 'lladdr', mac, 'dev', name, 'nud', 'permanent')


def add_address(ns, v, addr, dev='lo'):
    prefix = 32 if v == 4 else 128
    ns.ip(f'-{v}', 'addr', 'add', f'{addr}/{prefix}', 'dev', dev, *(('nodad',) if v == 6 else ()))


# Sockets

SOL_IPV6 = socket.IPPROTO_IPV6
IP_TRANSPARENT, IPV6_TRANSPARENT = 19, 75
IP_RECVORIGDSTADDR, IPV6_RECVORIGDSTADDR = 20, 74
IP_PKTINFO = 8


def family(addr):
    return socket.AF_INET6 if ':' in addr else socket.AF_INET


def open_socket(ns, addr, port, tcp=False, transparent=False, listen=False, info=False):
    with ns:
        s = socket.socket(family(addr), socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
    v6 = family(addr) == socket.AF_INET6
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if v6:
        s.setsockopt(SOL_IPV6, socket.IPV6_V6ONLY, 1)
    if transparent:
        s.setsockopt(SOL_IPV6 if v6 else socket.SOL_IP, IPV6_TRANSPARENT if v6 else IP_TRANSPARENT, 1)
        if not tcp:
            s.setsockopt(SOL_IPV6 if v6 else socket.SOL_IP,
                         IPV6_RECVORIGDSTADDR if v6 else IP_RECVORIGDSTADDR, 1)
    if info:
        if v6:
            s.setsockopt(SOL_IPV6, socket.IPV6_RECVPKTINFO, 1)
        else:
            s.setsockopt(socket.SOL_IP, IP_PKTINFO, 1)
    if not tcp:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind((addr, port))
    if listen:
        s.listen(16)
    s.setblocking(False)
    return s


def readable(s, timeout):
    return bool(select.select([s], [], [], timeout)[0])


def recv(s, timeout=1.0, ns=None):
    """Return (data, peer, info) or None. info holds the interface and original destination.

    Interface names are resolved in ns, the namespace that owns the socket.
    """
    if not readable(s, timeout):
        return None
    data, ancillary, _, peer = s.recvmsg(65535, 512)
    info = {}
    for level, kind, value in ancillary:
        if level == socket.SOL_IP and kind == IP_PKTINFO:
            info['iface'] = struct.unpack('I', value[:4])[0]
        elif level == SOL_IPV6 and kind == socket.IPV6_PKTINFO:
            info['iface'] = struct.unpack('I', value[16:20])[0]
        elif level == socket.SOL_IP and kind == IP_RECVORIGDSTADDR:
            info['origdst'] = (socket.inet_ntop(socket.AF_INET, value[4:8]),
                               struct.unpack('!H', value[2:4])[0])
        elif level == SOL_IPV6 and kind == IPV6_RECVORIGDSTADDR:
            info['origdst'] = (socket.inet_ntop(socket.AF_INET6, value[8:24]),
                               struct.unpack('!H', value[2:4])[0])
    if 'iface' in info and ns:
        with ns:
            info['iface'] = socket.if_indextoname(info['iface'])
    return data, peer[:2], info


def connect(s, addr, port, timeout=1.0):
    """Non-blocking TCP connect. Return None on success, or the errno."""
    err = s.connect_ex((addr, port))
    if err not in (0, 115):  # EINPROGRESS
        return err
    if not select.select([], [s], [], timeout)[1]:
        return 'timeout'
    return s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) or None


def accept(listener, timeout=1.0):
    if not readable(listener, timeout):
        return None
    conn, peer = listener.accept()
    conn.setblocking(False)
    return conn, peer[:2]


def stream_exchange(a, b, data, timeout=1.0):
    """Send data from a to b and return what b received."""
    a.sendall(data)
    received = b''
    deadline = time.monotonic() + timeout
    while len(received) < len(data):
        if not readable(b, max(0.0, deadline - time.monotonic())):
            break
        chunk = b.recv(65535)
        if not chunk:
            break
        received += chunk
    return received


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack(f'!{len(data) // 2}H', data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def send_icmp_echo(ns, src, dst, ident, payload):
    v6 = family(dst) == socket.AF_INET6
    with ns:
        s = socket.socket(family(dst), socket.SOCK_RAW,
                          socket.IPPROTO_ICMPV6 if v6 else socket.IPPROTO_ICMP)
    with s:
        s.bind((src, 0))
        header = struct.pack('!BBHHH', 128 if v6 else 8, 0, 0, ident, 1)
        message = header + payload
        if not v6:  # the kernel computes ICMPv6 checksums
            message = message[:2] + struct.pack('!H', checksum(message)) + message[4:]
        s.sendto(message, (dst, 0))


def send_bad_udp(ns, src, dst, sport, dport, payload):
    """Send UDP with a wrong checksum, which conntrack classifies as INVALID."""
    with ns:
        s = socket.socket(family(dst), socket.SOCK_RAW, socket.IPPROTO_UDP)
    with s:
        s.bind((src, 0))
        s.sendto(struct.pack('!HHHH', sport, dport, 8 + len(payload), 0x1234) + payload, (dst, 0))


def send_tcp_flags(ns, src, dst, sport, dport, flags):
    """Send one TCP segment with the given flags and a valid checksum."""
    v6 = family(dst) == socket.AF_INET6
    header = struct.pack('!HHIIBBHHH', sport, dport, 1, 0, 5 << 4, flags, 1024, 0, 0)
    a, b = (socket.inet_pton(family(dst), x) for x in (src, dst))
    pseudo = a + b + (struct.pack('!IxxxB', len(header), 6) if v6 else struct.pack('!xBH', 6, len(header)))
    header = header[:16] + struct.pack('!H', checksum(pseudo + header)) + header[18:]
    with ns:
        s = socket.socket(family(dst), socket.SOCK_RAW, socket.IPPROTO_TCP)
    with s:
        s.bind((src, 0))
        try:
            s.sendto(header, (dst, 0))
        except PermissionError:  # dropped in OUTPUT
            pass


def refused(s, timeout):
    """True when a connected UDP socket reports ICMP port unreachable."""
    try:
        recv(s, timeout)
    except ConnectionRefusedError:
        return True
    return False


# Probes
#
# Test UDP and ICMP probes carry their own injection request, so one ruleset
# serves every packet of a case:
#   bytes 0-3   mark to inject
#   bytes 4-7   sequence number
#   byte  8     1: preset ct mark from bytes 12-15
#   byte  9     index into the priority map, 0: keep
#   byte  10    1: notrack
#   bytes 16-19 test-specific value

PORTS = '40000-49999'
PRIORITIES = {1: 0x00000000, 2: 0xffffffff, 3: 0x00000800, 4: 0xa5a5a5a5}


def probe(seq, mark=0, ct=None, priority=0, notrack=False, extra=0):
    return struct.pack('!IIBBBBII', mark, seq, ct is not None, priority, notrack, 0,
                       ct or 0, extra)


PRIORITY_MAP = ', '.join(f'{k} : 0x{v:08x}' for k, v in PRIORITIES.items())
INJECT = f'''
 map priorities {{ typeof @th,136,8 : meta priority; elements = {{ {PRIORITY_MAP} }} }}
 chain inject {{
  meta mark set @th,64,32
  @th,128,8 1 ct mark set @th,160,32
  @th,136,8 != 0 meta priority set @th,136,8 map @priorities
 }}
'''
NOTRACK = '@th,144,8 1 notrack'
SEQ = '@th,96,32'

PROBE = f'meta l4proto udp udp dport {PORTS}'
ICMP_PROBE = f'icmp type echo-request icmp id {PORTS}'
ICMP6_PROBE = f'icmpv6 type echo-request icmpv6 id {PORTS}'


def observations(table, name):
    """Read a dynamic set keyed by sequence number into {seq: [values...]}."""
    rows = nft_json('list', 'set', 'inet', table, name)
    result = {}
    for row in rows:
        if 'set' not in row:
            continue
        for elem in row['set'].get('elem', []):
            value = elem['elem']['val'] if isinstance(elem, dict) and 'elem' in elem else elem
            parts = value['concat'] if isinstance(value, dict) and 'concat' in value else [value]
            result.setdefault(parts[0], []).append(tuple(parts[1:]) if len(parts) > 2 else parts[1])
    return result


def elements(table, name):
    rows = nft_json('list', 'set', 'inet', table, name)
    return {e for row in rows if 'set' in row for e in row['set'].get('elem', [])}


def counter(table, name):
    rows = nft_json('list', 'counter', 'inet', table, name)
    return next(row['counter']['packets'] for row in rows if 'counter' in row)


class Ports:
    def __init__(self, low=40000):
        self.next = low

    def __call__(self, count=1):
        first = self.next
        self.next += count
        return first if count == 1 else list(range(first, first + count))


# Sampling

class Sampler:
    def __init__(self, seed, per_segment):
        self.random = random.Random(seed)
        self.per_segment = per_segment
        self.log = {}

    def segment(self, name, low, high):
        inner = list(range(low + 1, high))
        values = [low, high] + self.random.sample(inner, min(self.per_segment, len(inner)))
        self.log[name] = values
        return values

    def bits(self, mask):
        return self.random.getrandbits(32) & mask


# Reporting

class Failure(AssertionError):
    pass


def expect(actual, expected, label):
    if actual != expected:
        raise Failure(f'{label}: expected {expected!r}, observed {actual!r}')


class Report:
    """Behaviour items and the cases that cover them.

    An item is covered when it has cases and all of them pass. Items that the
    contract leaves undefined or implementation defined are listed without cases.
    """

    def __init__(self, suite, items, not_asserted=()):
        self.suite = suite
        self.items = items
        self.not_asserted = not_asserted
        self.cases = []

    def case(self, name, items, function):
        for item in items:
            if item not in self.items:
                raise KeyError(f'{self.suite}: unknown item {item}')
        row = {'name': name, 'items': list(items)}
        try:
            detail = function()
            row['status'] = 'pass'
            if detail:
                row['detail'] = detail
        except Failure as exc:
            row.update(status='fail', error=str(exc))
        except Exception as exc:
            row.update(status='error', error=f'{type(exc).__name__}: {exc}',
                       traceback=traceback.format_exc())
        self.cases.append(row)
        if row['status'] != 'pass':
            print(f'{self.suite}: {row["status"]} {name}: {row["error"]}', flush=True)
            if 'traceback' in row:
                print(row['traceback'], end='', flush=True)

    def result(self, parameters=None):
        groups = {}
        for item, (group, text) in self.items.items():
            cases = [c for c in self.cases if item in c['items']]
            entry = groups.setdefault(group, {'covered': 0, 'total': 0, 'items': {}})
            covered = bool(cases) and all(c['status'] == 'pass' for c in cases)
            entry['items'][item] = {'text': text, 'covered': covered,
                                    'cases': [c['name'] for c in cases]}
            entry['total'] += 1
            entry['covered'] += covered
        counts = {s: sum(c['status'] == s for c in self.cases) for s in ('pass', 'fail', 'error')}
        return {'suite': self.suite, 'counts': counts, 'coverage': groups,
                'not_asserted': dict(self.not_asserted), 'parameters': parameters or {},
                'cases': self.cases}
