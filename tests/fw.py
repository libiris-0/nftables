"""fw: SPEC 2, 5.1 and 5.2, and the zone example."""

import json
import shutil
import tempfile
import time
from pathlib import Path

import harness as h
from harness import expect, Failure

PARAMETERS = json.loads((Path(__file__).with_name('parameters.json')).read_text())['fw']

ITEMS = {
    '2.1/order': ('core', '同一 hook 中，报文调整链先于过滤链'),
    '2.1/route': ('core', 'mangle_output 修改 mark 后重新选路'),
    '2.2/lo': ('core', 'lo 放行，优先于连接状态和 drop-in'),
    '2.2/invalid': ('core', 'INVALID 丢弃，优先于透明 socket 和 drop-in 的放行'),
    '2.2/state': ('core', 'ESTABLISHED 和 RELATED 放行，优先于 drop-in 的丢弃'),
    '2.2/transparent': ('core', 'INPUT 匹配透明 socket 时放行，优先于 drop-in 的丢弃'),
    '2.2/dropin': ('core', 'drop-in 的判定生效'),
    '2.2/default': ('core', '其余报文丢弃'),
    '2.2/dnat': ('core', 'DNAT 不构成转发许可，DNAT 到本机的接收由 drop-in 授权'),
    '2.3': ('core', 'handle_reject 对 TCP 返回 reset，对其余协议返回 port-unreachable'),
    '5.1': ('interface', '目录中的 *.conf 按文件名顺序追加，其他文件不加载'),
    '5.2': ('interface', '2.1 中的每条链都能挂载规则，规则所见的端点符合挂载位置'),
    'zone': ('example', '10-zone：zone 接口的入站放行 DNAT 目标和 SSH，其余拒绝，发出放行'),
}

ADDR = {
    4: {'wan': ('10.30.1.1', '10.30.1.2', 24), 'lan': ('10.30.2.1', '10.30.2.2', 24),
        'shared': '198.51.100.9', 'loopback': '127.0.0.1'},
    6: {'wan': ('fd30:1::1', 'fd30:1::2', 64), 'lan': ('fd30:2::1', 'fd30:2::2', 64),
        'shared': '2001:db8:9::9', 'loopback': '::1'},
}

HOOKS = ('input', 'forward', 'output')
SYN_FIN = 0x03
REROUTE_MARK = 0x55
EXAMPLE = h.CONF / 'fw.conf.d/10-zone.conf.sample'

WITNESS = 'table inet witness {\n' + ''.join(f'''
 set seen_{hook} {{ typeof th sport . ct state; flags dynamic; }}
 set passed_{hook} {{ typeof th sport; flags dynamic; }}
 chain before_{hook} {{
  type filter hook {hook} priority filter - 1;
  meta l4proto {{ tcp, udp }} th sport {h.PORTS} update @seen_{hook} {{ th sport . ct state }}
 }}
 chain after_{hook} {{
  type filter hook {hook} priority filter + 1;
  meta l4proto {{ tcp, udp }} th sport {h.PORTS} update @passed_{hook} {{ th sport }}
 }}
''' for hook in HOOKS) + '}\n'


class Fixture:
    def __init__(self):
        self.host = h.HOST
        self.wan, self.lan = h.peer('wan'), h.peer('lan')
        self.host.sysctl(**{'net.ipv4.ip_forward': 1, 'net.ipv6.conf.all.forwarding': 1})
        h.link(self.host, 'enwan', self.wan, 'wp0', {v: ADDR[v]['wan'] for v in (4, 6)})
        h.link(self.host, 'lan0', self.lan, 'lp0', {v: ADDR[v]['lan'] for v in (4, 6)})
        for v in (4, 6):
            a = ADDR[v]
            for ns, name in ((self.wan, 'wan'), (self.lan, 'lan')):
                ns.ip(f'-{v}', 'route', 'add', 'default', 'via', a[name][0])
                h.add_address(ns, v, a['shared'])
            self.host.ip(f'-{v}', 'route', 'add', a['shared'], 'via', a['wan'][1])
            self.host.ip(f'-{v}', 'route', 'add', a['shared'], 'via', a['lan'][1], 'table', '100')
            self.host.ip(f'-{v}', 'rule', 'add', 'priority', '100', 'fwmark', f'{REROUTE_MARK:#x}',
                         'lookup', '100')
        self.scratch = Path(tempfile.mkdtemp(prefix='fw-'))
        self.dropins = self.scratch / 'nftables.conf.d/fw.conf.d'
        self.dropins.mkdir(parents=True)
        self.entry = self.scratch / 'entry.nft'
        self.entry.write_text(f'include "{h.CONF}/fw.conf"\n')
        h.nft(WITNESS)
        self.ports = h.Ports()

    def load(self, dropins=None, files=None):
        shutil.rmtree(self.dropins)
        self.dropins.mkdir()
        for name, text in (dropins or {}).items():
            (self.dropins / name).write_text(text)
        for name, path in (files or {}).items():
            shutil.copy(path, self.dropins / name)
        h.run('nft', '-I', str(self.scratch), '-f', str(self.entry))

    def endpoints(self, v, hook, reverse=False):
        """(sender ns, src, receiver ns, dst) for traffic through hook."""
        a = ADDR[v]
        pairs = {'input': (self.wan, a['wan'][1], self.host, a['wan'][0]),
                 'forward': (self.wan, a['wan'][1], self.lan, a['lan'][1]),
                 'output': (self.host, a['wan'][0], self.wan, a['wan'][1]),
                 'lo': (self.host, a['loopback'], self.host, a['loopback'])}
        return pairs[hook]

    def flow(self, v, hook, tcp=False, transparent=False):
        return Flow(self, *self.endpoints(v, hook), tcp, transparent)

    def seen(self, hook):
        return h.observations('witness', f'seen_{hook}'), h.elements('witness', f'passed_{hook}')


class Flow:
    def __init__(self, f, sender, src, receiver, dst, tcp=False, transparent=False):
        self.f, self.tcp = f, tcp
        self.sender, self.src, self.receiver, self.dst = sender, src, receiver, dst
        self.sport, self.dport = f.ports(), f.ports()
        self.a = h.open_socket(sender, src, self.sport, tcp=tcp)
        self.b = h.open_socket(receiver, dst, self.dport, tcp=tcp, listen=tcp, transparent=transparent)

    def send(self, data=b'x', reverse=False, timeout=None):
        """Send one UDP datagram; return whether it was delivered."""
        a, b, addr = (self.b, self.a, (self.src, self.sport)) if reverse else (self.a, self.b, (self.dst, self.dport))
        if not send(a, data, addr):
            return False
        got = h.recv(b, timeout or PARAMETERS['positive_wait_seconds'])
        return got is not None and got[0] == data

    def match(self):
        return f'meta l4proto {"tcp" if self.tcp else "udp"} th dport {self.dport}'

    def close(self):
        self.a.close()
        self.b.close()


def send(s, data, addr):
    """Send a datagram; False when OUTPUT drops it, which the kernel reports as EPERM."""
    try:
        s.sendto(data, addr)
    except PermissionError:
        return False
    return True


def chain_rules(chain, *rules):
    return ''.join(f'add rule inet fw {chain} {rule}\n' for rule in rules)


class Suite:
    def __init__(self):
        self.f = Fixture()
        self.report = h.Report('fw', ITEMS)
        self.negative = PARAMETERS['negative_wait_seconds']

    def default(self, v, hook):
        f = self.f
        f.load()
        flow = f.flow(v, hook)
        try:
            expect(flow.send(timeout=self.negative), False, f'{hook} delivery without permission')
        finally:
            flow.close()
        seen, passed = f.seen(hook)
        expect('new' in seen.get(flow.sport, []), True, f'{hook} saw the packet')
        expect(flow.sport in passed, False, f'{hook} passed the packet')

    def dropin(self, v, hook):
        f = self.f
        for verdict, delivered in (('accept', True), ('drop', False)):
            flow = f.flow(v, hook)
            f.load({'50-test.conf': chain_rules(hook, f'{flow.match()} {verdict}')})
            try:
                expect(flow.send(timeout=None if delivered else self.negative), delivered,
                       f'{hook} drop-in {verdict}')
            finally:
                flow.close()

    def loopback(self, v):
        f = self.f
        f.load({'50-test.conf': chain_rules('input', 'drop') + chain_rules('output', 'drop')})
        flow = f.flow(v, 'lo')
        try:
            expect(flow.send(), True, 'lo delivery with drop-in drop')
            sport, dport = f.ports(), f.ports()
            addr = ADDR[v]['loopback']
            h.send_tcp_flags(f.host, addr, addr, sport, dport, SYN_FIN)
        finally:
            flow.close()
        seen, passed = f.seen('input')
        expect('invalid' in seen.get(sport, []), True, 'invalid segment on lo reached input')
        expect(sport in passed, True, 'invalid segment on lo passed input')

    def invalid(self, v, hook):
        f = self.f
        f.load({'50-test.conf': chain_rules(hook, 'accept')})
        sender, src, receiver, dst = f.endpoints(v, hook)
        sport, dport = f.ports(), f.ports()
        # INPUT: the target is a transparent socket, so INVALID must win over 2.2's socket row.
        listener = h.open_socket(receiver, dst, dport, tcp=True, listen=True,
                                 transparent=hook == 'input')
        try:
            h.send_tcp_flags(sender, src, dst, sport, dport, SYN_FIN)
            time.sleep(0.05)
        finally:
            listener.close()
        seen, passed = f.seen(hook)
        expect('invalid' in seen.get(sport, []), True, f'{hook} saw an INVALID segment')
        expect(sport in passed, False, f'{hook} passed an INVALID segment')

    def state(self, v, hook):
        """The reply direction of an allowed flow passes hook although a drop-in drops it."""
        f = self.f
        a = ADDR[v]
        # Endpoints of flows whose reply direction crosses hook, and the chain the request crosses.
        initiator, request_chain = {'input': ((f.host, a['wan'][0], f.wan, a['wan'][1]), 'output'),
                                    'forward': ((f.lan, a['lan'][1], f.wan, a['wan'][1]), 'forward'),
                                    'output': ((f.wan, a['wan'][1], f.host, a['wan'][0]), 'input')}[hook]
        flow, related = Flow(f, *initiator), Flow(f, *initiator)
        ports = f'{{ {flow.dport}, {related.dport} }}'
        inbound = 'iifname lan0 ' if hook == 'forward' else ''
        f.load({'50-test.conf': chain_rules(request_chain, f'{inbound}meta l4proto udp th dport {ports} accept') +
                chain_rules(hook, 'drop')})
        try:
            expect(flow.send(), True, 'request')
            expect(flow.send(reverse=True), True, f'ESTABLISHED reply through {hook}')
            related.b.close()
            related.a.connect((related.dst, related.dport))
            related.a.send(b'closed')
            expect(h.refused(related.a, PARAMETERS['positive_wait_seconds']), True,
                   f'RELATED ICMP error through {hook}')
        finally:
            flow.close()
            related.a.close()
        seen, _ = f.seen(hook)
        expect('established' in seen.get(flow.dport, []), True, f'{hook} saw the ESTABLISHED reply')

    def transparent(self, v):
        f = self.f
        f.load({'50-test.conf': chain_rules('input', 'drop')})
        for transparent in (True, False):
            flow = f.flow(v, 'input', transparent=transparent)
            try:
                expect(flow.send(timeout=None if transparent else self.negative), transparent,
                       f'delivery to a {"transparent" if transparent else "plain"} socket')
            finally:
                flow.close()

    def dnat(self, v):
        f = self.f
        a = ADDR[v]
        family = 'ip' if v == 4 else 'ip6'
        brackets = (lambda x: x) if v == 4 else (lambda x: f'[{x}]')
        for local in (False, True):
            target_ns, target = (f.host, a['wan'][0]) if local else (f.lan, a['lan'][1])
            client = h.open_socket(f.wan, a['wan'][1], f.ports())
            server_port, public_port = f.ports(), f.ports()
            server = h.open_socket(target_ns, target, server_port)
            translate = chain_rules('dstnat', f'iifname enwan meta l4proto udp th dport {public_port} '
                                              f'dnat {family} to {brackets(target)}:{server_port}')
            grant = chain_rules('input' if local else 'forward', 'ct status dnat accept')
            try:
                for permitted in (False, True):
                    f.load({'50-test.conf': translate + (grant if permitted else '')})
                    data = f'dnat-{local}-{permitted}'.encode()
                    client.sendto(data, (a['wan'][0], public_port))
                    got = h.recv(server, PARAMETERS['positive_wait_seconds'] if permitted else self.negative)
                    expect(got[0] if got else None, data if permitted else None,
                           f'{"local" if local else "forwarded"} DNAT, permission {permitted}')
            finally:
                client.close()
                server.close()

    def reject(self, v):
        """Services listen on the target ports, so only handle_reject produces the responses."""
        f = self.f
        a = ADDR[v]
        positive = PARAMETERS['positive_wait_seconds']
        for rejected in (True, False):
            f.load({'50-test.conf': chain_rules('input', 'goto handle_reject' if rejected else 'accept')})
            port = f.ports()
            service = h.open_socket(f.host, a['wan'][0], port, tcp=True, listen=True)
            server = h.open_socket(f.host, a['wan'][0], port)
            tcp = h.open_socket(f.wan, a['wan'][1], f.ports(), tcp=True)
            udp = h.open_socket(f.wan, a['wan'][1], f.ports())
            try:
                expect(h.connect(tcp, a['wan'][0], port), 111 if rejected else None, f'TCP, rejected {rejected}')
                expect(h.accept(service, 0 if rejected else positive) is not None, not rejected,
                       f'TCP service accepted, rejected {rejected}')
                udp.connect((a['wan'][0], port))
                udp.send(b'reject')
                if rejected:
                    expect(h.refused(udp, positive), True, 'UDP port-unreachable')
                    expect(h.recv(server, 0), None, 'UDP service received a rejected datagram')
                else:
                    got = h.recv(server, positive)
                    expect(got[0] if got else None, b'reject', 'UDP service received')
            finally:
                for s in (service, server, tcp, udp):
                    s.close()

    def order(self, v):
        """A mangle chain marks a probe and the filter chain of the same hook sees the mark."""
        f = self.f
        paths = {'prerouting': 'input', 'input': 'input', 'forward': 'forward',
                 'output': 'output', 'postrouting': 'output'}
        flows = {hook: f.flow(v, path) for hook, path in paths.items()}
        text = 'table inet fw {\n' + ''.join(
            f' set test_{hook} {{ typeof th dport; flags dynamic; }}\n' for hook in paths) + '}\n'
        for hook, flow in flows.items():
            text += chain_rules(f'mangle_{hook}', f'{flow.match()} meta mark set 0x5a')
            text += chain_rules(hook, f'{flow.match()} meta mark 0x5a update @test_{hook} {{ th dport }}')
        for chain in HOOKS:
            ports = ', '.join(str(flows[hook].dport) for hook, path in paths.items() if path == chain)
            text += chain_rules(chain, f'meta l4proto udp th dport {{ {ports} }} accept')
        f.load({'50-test.conf': text})
        try:
            for hook, flow in flows.items():
                expect(flow.send(), True, f'{hook} delivery')
                expect(flow.dport in h.elements('fw', f'test_{hook}'), True,
                       f'{hook} filter chain saw the mangle mark')
        finally:
            for flow in flows.values():
                flow.close()

    def reroute(self, v):
        f = self.f
        a = ADDR[v]
        results = {}
        for marked in (False, True):
            port = f.ports()
            receivers = {name: h.open_socket(ns, a['shared'], port) for name, ns in
                         (('wan', f.wan), ('lan', f.lan))}
            sender = h.open_socket(f.host, '::' if v == 6 else '0.0.0.0', f.ports())
            rules = chain_rules('output', f'meta l4proto udp th dport {port} accept')
            if marked:
                rules += chain_rules('mangle_output', f'meta l4proto udp th dport {port} '
                                                       f'meta mark set {REROUTE_MARK:#x}')
            f.load({'50-test.conf': rules})
            try:
                sender.sendto(b'route', (a['shared'], port))
                results[marked] = [name for name, s in receivers.items() if h.recv(s, self.negative)]
            finally:
                sender.close()
                for s in receivers.values():
                    s.close()
        expect(results, {False: ['wan'], True: ['lan']}, 'receiver with and without the mangle mark')

    def snat(self, v):
        f = self.f
        a = ADDR[v]
        flow = Flow(f, f.wan, a['wan'][1], f.lan, a['lan'][1])
        f.load({'50-test.conf': chain_rules('forward', f'{flow.match()} accept') +
                chain_rules('srcnat', f'oifname lan0 {flow.match()} masquerade')})
        try:
            flow.a.sendto(b'snat', (flow.dst, flow.dport))
            got = h.recv(flow.b)
            expect(got[1][0] if got else None, a['lan'][0], 'source after masquerade')
        finally:
            flow.close()

    def files(self, v):
        f = self.f
        for first, second, delivered in (('10-mark.conf', '20-accept.conf', True),
                                         ('20-mark.conf', '10-accept.conf', False)):
            flow = f.flow(v, 'input')
            f.load({first: chain_rules('input', f'{flow.match()} meta mark set 0x77'),
                    second: chain_rules('input', f'{flow.match()} meta mark 0x77 accept'),
                    '30-accept.conf.sample': chain_rules('input', 'accept'),
                    '40-accept.txt': chain_rules('input', 'accept')})
            try:
                expect(flow.send(timeout=None if delivered else self.negative), delivered,
                       f'{first} before {second}')
            finally:
                flow.close()

    def zone(self, v):
        f = self.f
        a = ADDR[v]
        family = 'ip' if v == 4 else 'ip6'
        service_port, public_port = f.ports(), f.ports()
        host = a['lan'][0]
        target = host if v == 4 else f'[{host}]'
        f.load({'90-test-dnat.conf': chain_rules('dstnat', f'iifname lan0 meta l4proto udp th dport '
                                                           f'{public_port} dnat {family} to {target}:{service_port}')},
               {'10-zone.conf': EXAMPLE})
        sockets = []
        try:
            ssh = h.open_socket(f.host, host, 22, tcp=True, listen=True)
            other = h.open_socket(f.host, host, f.ports(), tcp=True, listen=True)
            service = h.open_socket(f.host, host, service_port)
            sockets += [ssh, other, service]
            client = h.open_socket(f.lan, a['lan'][1], f.ports(), tcp=True)
            sockets.append(client)
            expect(h.connect(client, host, 22), None, 'SSH from the zone')
            client = h.open_socket(f.lan, a['lan'][1], f.ports(), tcp=True)
            sockets.append(client)
            expect(h.connect(client, host, other.getsockname()[1]), 111, 'other TCP is rejected')
            udp = h.open_socket(f.lan, a['lan'][1], f.ports())
            sockets.append(udp)
            udp.connect((host, f.ports()))
            udp.send(b'x')
            expect(h.refused(udp, PARAMETERS['positive_wait_seconds']), True, 'other UDP is rejected')
            dnat = h.open_socket(f.lan, a['lan'][1], f.ports())
            sockets.append(dnat)
            dnat.sendto(b'dnat', (host, public_port))
            got = h.recv(service)
            expect(got[0] if got else None, b'dnat', 'DNAT target is accepted')
            wan = h.open_socket(f.wan, a['wan'][1], f.ports(), tcp=True)
            sockets.append(wan)
            expect(h.connect(wan, a['wan'][0], 22, timeout=self.negative), 'timeout',
                   'SSH outside the zone is dropped')
            for name, ns, peer, delivered in (('zone', f.lan, a['lan'][1], True),
                                              ('wan', f.wan, a['wan'][1], False)):
                sink = h.open_socket(ns, peer, f.ports())
                sockets.append(sink)
                out = h.open_socket(f.host, '::' if v == 6 else '0.0.0.0', f.ports())
                sockets.append(out)
                send(out, b'out', (peer, sink.getsockname()[1]))
                wait = PARAMETERS['positive_wait_seconds'] if delivered else self.negative
                expect(h.recv(sink, wait) is not None, delivered, f'output to {name}')
        finally:
            for s in sockets:
                s.close()

    def run(self):
        r = self.report
        for v in (4, 6):
            for hook in HOOKS:
                r.case(f'v{v}/{hook}/default', ['2.2/default'], lambda: self.default(v, hook))
                r.case(f'v{v}/{hook}/dropin', ['2.2/dropin', '5.2'], lambda: self.dropin(v, hook))
                r.case(f'v{v}/{hook}/invalid', ['2.2/invalid'], lambda: self.invalid(v, hook))
                r.case(f'v{v}/{hook}/state', ['2.2/state'], lambda: self.state(v, hook))
            r.case(f'v{v}/lo', ['2.2/lo'], lambda: self.loopback(v))
            r.case(f'v{v}/transparent', ['2.2/transparent'], lambda: self.transparent(v))
            r.case(f'v{v}/dnat', ['2.2/dnat', '5.2'], lambda: self.dnat(v))
            r.case(f'v{v}/reject', ['2.3', '2.2/dropin'], lambda: self.reject(v))
            r.case(f'v{v}/order', ['2.1/order', '5.2'], lambda: self.order(v))
            r.case(f'v{v}/reroute', ['2.1/route'], lambda: self.reroute(v))
            r.case(f'v{v}/snat', ['5.2'], lambda: self.snat(v))
            r.case(f'v{v}/files', ['5.1'], lambda: self.files(v))
            r.case(f'v{v}/zone', ['zone'], lambda: self.zone(v))
        return r.result(PARAMETERS)


def run():
    return Suite().run()
