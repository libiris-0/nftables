"""integration: fw, routing and divert together, with the zone fixtures and routing examples."""

import json
import shutil
import tempfile
import time
from pathlib import Path

import harness as h
from harness import D, MASK, expect, Failure

PARAMETERS = json.loads((Path(__file__).with_name('parameters.json')).read_text())['integration']

ITEMS = {
    'external': ('integration', '外部入站的流量经分类、提交和交付到达监听 socket，持续双向通信'),
    'local': ('integration', '本机发出的选中流量交给监听 socket，每个报文只交付一次'),
    'mapping': ('integration', '映射变更后已有连接沿用选择，新连接按新映射处理'),
    'normal': ('integration', '未选中的 class、两级未命中、脏 priority、具体路由和显式普通选择走普通路径'),
    'zone': ('integration', 'WAN 发起的转发先被拒绝，追加许可后可达'),
    'failure': ('integration', '交付失败时原目标和普通本机服务都收不到，监听恢复后新连接可接收'),
    'dnat': ('integration', '端口转发到本机或 guest 的服务，转发须另加许可，许可后双向通信'),
    'service': ('integration', '直连本机服务按 zone 政策允许或拒绝，允许时双向通信'),
    'cgroup': ('integration', '本机输出未命中 cgroup 时走普通路径，外部入站不受 cgroup 集合限制'),
}

ADDR = {
    4: {'wan': ('10.40.1.1', '10.40.1.2', 24), 'guest': ('10.40.2.1', '10.40.2.2', 24),
        'selected': '198.51.100.2', 'unselected': '198.51.100.3', 'unmapped': '198.51.100.4',
        'unclassed': '198.51.100.5', 'any': '0.0.0.0'},
    6: {'wan': ('fd40:1::1', 'fd40:1::2', 64), 'guest': ('fd40:2::1', 'fd40:2::2', 64),
        'selected': '2001:db8:1::2', 'unselected': '2001:db8:1::3', 'unmapped': '2001:db8:1::4',
        'unclassed': '2001:db8:1::5', 'any': '::'},
}
REMOTES = ('selected', 'unselected', 'unmapped', 'unclassed')
COUNTRY, OTHER_COUNTRY, UNCLASSED_COUNTRY = 0x800, 0x801, 0x802
CLASS, OTHER_CLASS = 0x102, 0x103
PORT = D['tproxy_port']
WAN_UDP, GUEST_UDP = 31000, 53


class Fixture:
    def __init__(self):
        self.host = h.HOST
        self.wan, self.guest = h.peer('wan'), h.peer('guest')
        self.host.sysctl(**{'net.ipv4.ip_forward': 1, 'net.ipv6.conf.all.forwarding': 1})
        h.link(self.host, 'enwan', self.wan, 'wp0', {v: ADDR[v]['wan'] for v in (4, 6)})
        h.link(self.host, 'virbrguest', self.guest, 'gp0', {v: ADDR[v]['guest'] for v in (4, 6)})
        self.host.ip('link', 'add', D['routing_probe_interface'], 'type', 'dummy')
        self.host.ip('link', 'set', D['routing_probe_interface'], 'up')
        probe = f'{D["routing_probe"]:#x}/{MASK:#x}'
        divert = f'{D["routing_divert"]:#x}/{MASK:#x}'
        for v in (4, 6):
            a = ADDR[v]
            for name in REMOTES:
                h.add_address(self.wan, v, a[name])
            self.wan.ip(f'-{v}', 'route', 'add', 'default', 'via', a['wan'][0])
            self.guest.ip(f'-{v}', 'route', 'add', 'default', 'via', a['guest'][0])
            ip = lambda *args: self.host.ip(f'-{v}', *args)
            ip('route', 'add', 'default', 'via', D[f'routing_probe_nexthop{v}'], 'dev',
               D['routing_probe_interface'], 'onlink', 'table', '1000')
            ip('route', 'add', 'local', 'default', 'dev', 'lo', 'table', '3346')
            ip('route', 'add', 'default', 'via', a['wan'][1], 'table', 'default')
            ip('route', 'add', 'unreachable', 'default', 'metric', '4294967294', 'table', 'default')
            ip('rule', 'add', 'priority', '31000', 'fwmark', probe, 'lookup', 'main')
            ip('rule', 'add', 'priority', '31001', 'fwmark', probe, 'lookup', '1000')
            ip('rule', 'add', 'priority', '100', 'fwmark', divert, 'lookup', '3346')
            ip('rule', 'add', 'priority', '32000', 'lookup', 'main', 'suppress_prefixlength', '0')
            ip('rule', 'add', 'priority', '32001', 'lookup', 'default')
        self.scratch = Path(tempfile.mkdtemp(prefix='integration-'))
        root = self.scratch / 'nftables.conf.d'
        root.mkdir()
        for name in ('routing-defs.nft', 'fw.conf', 'routing.conf', 'divert.conf'):
            (root / name).symlink_to(h.CONF / name)
        for module, files in (('fw', {'10-wan.conf': h.FIXTURES / 'fw/10-wan.conf',
                                      '20-guest.conf': h.FIXTURES / 'fw/20-guest.conf'}),
                              ('routing', {'10-classify.conf': h.CONF / 'routing.conf.d/10-classify.conf.sample',
                                           '99-divert.conf': h.CONF / 'routing.conf.d/99-divert.conf.sample'}),
                              ('divert', {})):
            directory = root / f'{module}.conf.d'
            directory.mkdir()
            for name, path in files.items():
                shutil.copy(path, directory / name)
        # nft also resolves includes relative to the including file, so the entry lives in scratch.
        self.entry = self.scratch / 'nftables.conf'
        shutil.copy(h.ETC / 'nftables.conf', self.entry)
        self.test_policy = root / 'fw.conf.d/90-test.conf'
        self.client_ports, self.service_ports = h.Ports(40000), h.Ports(50000)

    def load(self, policy=''):
        """Load the full entry file, with an optional fw test policy."""
        self.test_policy.write_text(policy)
        h.run('nft', '-I', str(self.scratch), '-f', str(self.entry))
        maps = []
        for v in (4, 6):
            a = ADDR[v]
            host = ', '.join(f'{a[k][0]} : 0x{COUNTRY:03x}' for k in ('wan', 'guest'))
            maps.append(f'add element inet routing geo{v} {{ {a["selected"]} : 0x{COUNTRY:03x}, '
                        f'{a["unselected"]} : 0x{OTHER_COUNTRY:03x}, {a["unclassed"]} : 0x{UNCLASSED_COUNTRY:03x}, '
                        f'{a["guest"][1]} : 0x{COUNTRY:03x}, {host} }}')
        maps.append(f'add element inet routing geoclass {{ 0x{COUNTRY:03x} : 0x{CLASS:03x}, '
                    f'0x{OTHER_COUNTRY:03x} : 0x{OTHER_CLASS:03x} }}')
        maps.append(f'add element inet routing divert_classes {{ 0x{CLASS:03x} }}')
        maps.append('flush set inet routing divert_cgroupsv2')
        maps.append(f'add element inet routing divert_cgroupsv2 {{ "{h.local_cgroup()}" }}')
        h.nft('\n'.join(maps))

    def client(self, v, origin, tcp):
        a = ADDR[v]
        ns, addr = {'guest': (self.guest, a['guest'][1]), 'wan': (self.wan, a['wan'][1]),
                    'local': (self.host, a['guest'][0])}[origin]
        port = self.client_ports()
        return h.open_socket(ns, addr, port, tcp=tcp), (addr, port)

    def remote(self, v, name, tcp):
        port = self.service_ports()
        return h.open_socket(self.wan, ADDR[v][name], port, tcp=tcp, listen=tcp), (ADDR[v][name], port)

    def listener(self, v, tcp):
        return h.open_socket(self.host, ADDR[v]['any'], PORT, tcp=tcp, transparent=True, listen=tcp)


class Suite:
    def __init__(self):
        self.f = Fixture()
        self.report = h.Report('integration', ITEMS)
        self.positive = PARAMETERS['positive_wait_seconds']
        self.negative = PARAMETERS['negative_wait_seconds']

    def expect_diverted(self, v, origin, tcp, dest='selected', rounds=None):
        """A new flow reaches the listener with its original endpoints; return its client port."""
        f = self.f
        listener = f.listener(v, tcp)
        client, source = f.client(v, origin, tcp)
        sink, target = f.remote(v, dest, tcp)
        try:
            if tcp:
                expect(h.connect(client, *target), None, 'TCP connect')
                accepted = h.accept(listener, self.positive)
                if accepted is None:
                    raise Failure('listener did not accept')
                conn, peer = accepted
                expect(conn.getsockname()[:2], target, 'original destination')
                for round in range(rounds or PARAMETERS['rounds']):
                    up, down = f'up-{round}'.encode(), f'down-{round}'.encode()
                    expect(h.stream_exchange(client, conn, up), up, f'uplink {round}')
                    expect(h.stream_exchange(conn, client, down), down, f'downlink {round}')
                conn.close()
                expect(h.accept(sink, 0), None, 'original destination accepted')
            else:
                for round in range(rounds or PARAMETERS['rounds']):
                    client.sendto(f'up-{round}'.encode(), target)
                    got = h.recv(listener, self.positive)
                    if got is None:
                        raise Failure(f'listener did not receive datagram {round}')
                    expect(got[2].get('origdst'), target, 'original destination')
                    reply = h.open_socket(f.host, *target, transparent=True)
                    reply.connect(got[1])
                    reply.send(f'down-{round}'.encode())
                    reply.close()
                    back = h.recv(client, self.positive)
                    expect(back[:2] if back else None, (f'down-{round}'.encode(), target), f'reply {round}')
                    time.sleep(PARAMETERS['udp_interval_seconds'] if round == 0 else 0)
                expect(h.recv(sink, 0), None, 'original destination received')
            peer = peer if tcp else got[1]
            expect(peer, source, 'client endpoint')
            return source[1]
        finally:
            for s in (listener, client, sink):
                s.close()

    def expect_direct(self, v, origin, tcp, dest):
        """A new flow reaches the original destination and not the listener."""
        f = self.f
        listener = f.listener(v, tcp)
        client, source = f.client(v, origin, tcp)
        sink, target = f.remote(v, dest, tcp)
        try:
            if tcp:
                expect(h.connect(client, *target), None, 'TCP connect')
                expect(h.accept(sink, self.positive) is not None, True, 'original destination accepted')
                expect(h.accept(listener, 0), None, 'listener accepted')
            else:
                client.sendto(b'direct', target)
                got = h.recv(sink, self.positive)
                expect(got[0] if got else None, b'direct', 'original destination received')
                expect(h.recv(listener, 0), None, 'listener received')
        finally:
            for s in (listener, client, sink):
                s.close()

    def expect_served(self, client, server, target, tcp, allowed):
        """The client reaches the service at target and receives its reply, or is rejected."""
        if tcp:
            expect(h.connect(client, *target), None if allowed else 111, 'TCP connect')
            accepted = h.accept(server, self.positive if allowed else 0)
            expect(accepted is not None, allowed, 'service accepted')
            if accepted:
                conn = accepted[0]
                try:
                    expect(h.stream_exchange(client, conn, b'request'), b'request', 'request')
                    expect(h.stream_exchange(conn, client, b'reply'), b'reply', 'reply')
                finally:
                    conn.close()
        else:
            client.connect(target)
            client.send(b'request')
            if allowed:
                got = h.recv(server, self.positive)
                expect(got[0] if got else None, b'request', 'service received')
                server.sendto(b'reply', got[1])
                back = h.recv(client, self.positive)
                expect(back[:2] if back else None, (b'reply', target), 'reply')
            else:
                expect(h.refused(client, self.positive), True, 'UDP rejected')
                expect(h.recv(server, 0), None, 'service received')

    def external(self, v, tcp):
        self.f.load()
        self.expect_diverted(v, 'guest', tcp)

    def local(self, v, tcp):
        self.f.load()
        self.expect_diverted(v, 'local', tcp)

    def traversal(self, v):
        """Each datagram of a diverted local flow reaches the listener exactly once."""
        f = self.f
        f.load()
        client, _ = f.client(v, 'local', False)
        sink, target = f.remote(v, 'selected', False)
        listener = f.listener(v, False)
        try:
            for round in range(PARAMETERS['rounds']):
                data = f'once-{round}'.encode()
                client.sendto(data, target)
                got = h.recv(listener, self.positive)
                expect(got[0] if got else None, data, f'datagram {round}')
            expect(h.recv(listener, self.negative), None, 'duplicate delivery')
        finally:
            for s in (client, sink, listener):
                s.close()

    def mapping(self, v, origin, tcp):
        f = self.f
        f.load()
        listener = f.listener(v, tcp)
        client, source = f.client(v, origin, tcp)
        sink, target = f.remote(v, 'selected', tcp)
        conn = None
        try:
            if tcp:
                expect(h.connect(client, *target), None, 'TCP connect')
                accepted = h.accept(listener, self.positive)
                if accepted is None:
                    raise Failure('listener did not accept before the change')
                conn = accepted[0]
                exchange = lambda data: (h.stream_exchange(client, conn, data) == data and
                                         h.stream_exchange(conn, client, data) == data)
            else:
                def exchange(data):
                    client.sendto(data, target)
                    got = h.recv(listener, self.positive)
                    return got is not None and got[0] == data
            expect(exchange(b'before'), True, 'diverted before the change')
            h.nft(f'flush map inet routing geoclass\nadd element inet routing geoclass '
                  f'{{ 0x{COUNTRY:03x} : 0x{OTHER_CLASS:03x} }}')
            expect(exchange(b'after'), True, 'existing flow keeps its selection')
            expect(h.accept(sink, 0) if tcp else h.recv(sink, 0), None, 'existing flow reached the destination')
        finally:
            for s in (conn, listener, client, sink):
                if s:
                    s.close()
        self.expect_direct(v, origin, tcp, 'selected')

    def normal(self, v, tcp):
        f = self.f
        f.load()
        for dest in ('unselected', 'unmapped', 'unclassed'):
            self.expect_direct(v, 'guest', tcp, dest)
        # A dirty priority must not survive into the class lookup.
        f.load('add rule inet fw mangle_prerouting iifname virbrguest meta priority set 0x800\n')
        self.expect_direct(v, 'guest', tcp, 'unmapped')
        f.load(f'add rule inet fw mangle_prerouting iifname virbrguest meta mark set {D["routing_normal"]:#x}\n')
        self.expect_direct(v, 'guest', tcp, 'selected')
        f.load()
        f.host.ip(f'-{v}', 'route', 'add', ADDR[v]['selected'], 'via', ADDR[v]['wan'][1])
        try:
            self.expect_direct(v, 'guest', tcp, 'selected')
        finally:
            f.host.ip(f'-{v}', 'route', 'del', ADDR[v]['selected'])

    def zone(self, v):
        f = self.f
        a = ADDR[v]
        client, _ = f.client(v, 'wan', False)
        server = h.open_socket(f.guest, a['guest'][1], f.service_ports())
        target = (a['guest'][1], server.getsockname()[1])
        try:
            f.load()
            client.connect(target)
            client.send(b'denied')
            expect(h.refused(client, self.positive), True, 'WAN-initiated forward is rejected')
            expect(h.recv(server, 0), None, 'guest received a rejected datagram')
            f.load(f'insert rule inet fw forward iifname enwan oifname virbrguest udp dport {target[1]} accept\n')
            client.send(b'allowed')
            got = h.recv(server, self.positive)
            expect(got[0] if got else None, b'allowed', 'forward with permission')
        finally:
            client.close()
            server.close()

    def failure(self, v, tcp):
        f = self.f
        f.load()
        client, _ = f.client(v, 'guest', tcp)
        sink, target = f.remote(v, 'selected', tcp)
        ordinary = h.open_socket(f.host, ADDR[v]['any'], target[1], tcp=tcp, listen=tcp)
        try:
            if tcp:
                expect(h.connect(client, *target, timeout=self.negative), 'timeout', 'TCP connect')
                expect((h.accept(sink, 0), h.accept(ordinary, 0)), (None, None), 'accepted elsewhere')
            else:
                client.connect(target)
                client.send(b'lost')
                expect(h.recv(sink, self.negative), None, 'original destination received')
                expect(h.recv(ordinary, 0), None, 'ordinary local service received')
                expect(h.refused(client, 0), False, 'client received an ICMP error')
        finally:
            for s in (client, sink, ordinary):
                s.close()
        self.expect_diverted(v, 'guest', tcp, rounds=1)

    def dnat(self, v, forwarded, tcp):
        """A port forward reaches the service behind it; forwarding needs its own permission."""
        f = self.f
        a = ADDR[v]
        family = 'ip' if v == 4 else 'ip6'
        proto = 'tcp' if tcp else 'udp'
        target_ns, target = (f.guest, a['guest'][1]) if forwarded else (f.host, a['wan'][0])
        address = target if v == 4 else f'[{target}]'
        grant = 'insert rule inet fw forward iifname enwan ct status dnat accept\n'
        for permitted in ((False, True) if forwarded else (True,)):
            server = h.open_socket(target_ns, target, f.service_ports(), tcp=tcp, listen=tcp)
            public = f.service_ports()
            translate = (f'add rule inet fw dstnat iifname enwan {proto} dport {public} '
                         f'dnat {family} to {address}:{server.getsockname()[1]}\n')
            client, _ = f.client(v, 'wan', tcp)
            try:
                f.load(translate + (grant if permitted else ''))
                self.expect_served(client, server, (a['wan'][0], public), tcp, permitted)
            finally:
                server.close()
                client.close()

    def service(self, v, origin, tcp, allowed):
        f = self.f
        f.load()
        a = ADDR[v]
        host = a['wan' if origin == 'wan' else 'guest'][0]
        port = 22 if tcp and allowed else (WAN_UDP if origin == 'wan' else GUEST_UDP) if allowed \
            else f.service_ports()
        server = h.open_socket(f.host, host, port, tcp=tcp, listen=tcp)
        client, _ = f.client(v, origin, tcp)
        try:
            self.expect_served(client, server, (host, port), tcp, allowed)
        finally:
            for s in (server, client):
                s.close()

    def cgroup(self, v, tcp):
        f = self.f
        f.load()
        h.nft('flush set inet routing divert_cgroupsv2')
        self.expect_direct(v, 'local', tcp, 'selected')
        self.expect_diverted(v, 'guest', tcp, rounds=1)

    def run(self):
        r = self.report
        for v in (4, 6):
            for tcp in (False, True):
                proto = 'tcp' if tcp else 'udp'
                r.case(f'v{v}/{proto}/external', ['external'], lambda: self.external(v, tcp))
                r.case(f'v{v}/{proto}/local', ['local'], lambda: self.local(v, tcp))
                r.case(f'v{v}/{proto}/normal', ['normal'], lambda: self.normal(v, tcp))
                r.case(f'v{v}/{proto}/failure', ['failure'], lambda: self.failure(v, tcp))
                r.case(f'v{v}/{proto}/cgroup', ['cgroup'], lambda: self.cgroup(v, tcp))
                for origin in ('guest', 'local'):
                    r.case(f'v{v}/{proto}/{origin}-mapping', ['mapping'], lambda: self.mapping(v, origin, tcp))
                for forwarded in (False, True):
                    r.case(f'v{v}/{proto}/dnat-{"forward" if forwarded else "local"}', ['dnat'],
                           lambda: self.dnat(v, forwarded, tcp))
                for origin in ('wan', 'guest'):
                    for allowed in (True, False):
                        r.case(f'v{v}/{proto}/{origin}-service-{"allow" if allowed else "deny"}', ['service'],
                               lambda: self.service(v, origin, tcp, allowed))
            r.case(f'v{v}/traversal', ['local'], lambda: self.traversal(v))
            r.case(f'v{v}/zone', ['zone'], lambda: self.zone(v))
        return r.result(PARAMETERS)


def run():
    return Suite().run()
