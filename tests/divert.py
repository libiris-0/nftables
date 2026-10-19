"""divert: SPEC 4, 5.1 and 5.4, and the observe example."""

import json
import shutil
import tempfile
import time
from pathlib import Path

import harness as h
from harness import D, MASK, expect, Failure

PARAMETERS = json.loads((Path(__file__).with_name('parameters.json')).read_text())['divert']

ITEMS = {
    '4.1/protocol': ('core', '非 TCP/UDP 报文等同于 divert 不存在'),
    '4.1/id': ('core', '路由字段不等于 routing_divert 时等同于 divert 不存在'),
    '4.2/tcp': ('core', '只有监听 socket 时，TCP 连接建立并持续双向传输'),
    '4.2/udp': ('core', '只有监听 socket 时，UDP 首包、连续、间隔后和非 NEW 报文均交付'),
    '4.2/preserve': ('core', '交付保留原始端点、载荷和报文 mark'),
    '4.2/drop': ('core', '监听 socket 和其他透明 socket 都不存在时丢弃，不直达，也不交给普通本机服务'),
    '4.2/recovery': ('core', '监听恢复后，新连接交给监听 socket'),
    '5.1': ('interface', '目录中的 *.conf 加载，其他文件不加载'),
    '5.4/deliver': ('interface', '追加到 divert_deliver 的规则只对选中的报文执行'),
    '5.4/hook': ('interface', '独立 hook 链能看到选中的报文'),
    '5.4/verdict': ('interface', '丢弃的报文不因 drop-in 的判定而交付'),
    'observe': ('example', '10-observe：只对选中的报文计数'),
}

NOT_ASSERTED = {'4.2/other-socket': '监听 socket 以外还有其他透明 socket 时的接收者'}

ADDR = {
    4: {'inlet': ('10.20.1.1', '10.20.1.2', 24), 'outlet': ('10.20.2.1', '10.20.2.2', 24),
        'target': '198.51.100.2', 'any': '0.0.0.0'},
    6: {'inlet': ('fd20:1::1', 'fd20:1::2', 64), 'outlet': ('fd20:2::1', 'fd20:2::2', 64),
        'target': '2001:db8:1::2', 'any': '::'},
}

DIVERT, PORT = D['routing_divert'], D['tproxy_port']
OTHER_BITS = 0xffffffff & ~MASK
CLIENT_PORTS = '40000-44999'
EXAMPLE = h.CONF / 'divert.conf.d/10-observe.conf.sample'

WITNESS = f'''table inet witness {{
 map marks {{ typeof th sport : meta mark; }}
 set before {{ typeof th sport . meta mark; flags dynamic; }}
 set after {{ typeof th sport . meta mark; flags dynamic; }}
 set delivered {{ typeof th sport . meta mark; flags dynamic; }}
 set states {{ typeof th sport . ct state; flags dynamic; }}
 set icmp_after {{ typeof {h.SEQ}; flags dynamic; }}
{h.INJECT}
 chain mark_out {{
  type route hook output priority mangle;
  meta l4proto {{ tcp, udp }} th sport {CLIENT_PORTS} meta mark set th sport map @marks
 }}
 chain mark_pre {{
  type filter hook prerouting priority dstnat + 49;
  meta l4proto {{ tcp, udp }} th sport {CLIENT_PORTS} jump record_before
  iif lo return
  {h.ICMP_PROBE} jump inject
  {h.ICMP6_PROBE} jump inject
 }}
 chain record_before {{
  iif != lo meta mark set th sport map @marks
  update @before {{ th sport . meta mark }}
  update @states {{ th sport . ct state }}
 }}
 chain observe_after {{
  type filter hook prerouting priority dstnat + 61;
  meta l4proto {{ tcp, udp }} th sport {CLIENT_PORTS} update @after {{ th sport . meta mark }}
  {h.ICMP_PROBE} update @icmp_after {{ {h.SEQ} }}
  {h.ICMP6_PROBE} update @icmp_after {{ {h.SEQ} }}
 }}
 chain observe_input {{
  type filter hook input priority filter;
  meta l4proto {{ tcp, udp }} th sport {CLIENT_PORTS} update @delivered {{ th sport . meta mark }}
 }}
}}
'''


class Fixture:
    def __init__(self):
        self.host = h.HOST
        self.client, self.target = h.peer('client'), h.peer('target')
        self.host.sysctl(**{'net.ipv4.ip_forward': 1, 'net.ipv6.conf.all.forwarding': 1})
        h.link(self.host, 'inlet', self.client, 'cp0', {v: ADDR[v]['inlet'] for v in (4, 6)})
        h.link(self.host, 'outlet', self.target, 'tp0', {v: ADDR[v]['outlet'] for v in (4, 6)})
        for v in (4, 6):
            a = ADDR[v]
            h.add_address(self.target, v, a['target'])
            self.client.ip(f'-{v}', 'route', 'add', 'default', 'via', a['inlet'][0])
            self.target.ip(f'-{v}', 'route', 'add', 'default', 'via', a['outlet'][0])
            self.host.ip(f'-{v}', 'route', 'add', a['target'], 'via', a['outlet'][1])
            self.host.ip(f'-{v}', 'route', 'add', 'local', 'default', 'dev', 'lo', 'table', '3346')
            self.host.ip(f'-{v}', 'rule', 'add', 'priority', '100', 'fwmark',
                         f'{DIVERT:#x}/{MASK:#x}', 'lookup', '3346')
        self.leak_visible = False
        self.scratch = Path(tempfile.mkdtemp(prefix='divert-'))
        self.dropins = self.scratch / 'nftables.conf.d/divert.conf.d'
        self.dropins.mkdir(parents=True)
        self.entry = self.scratch / 'entry.nft'
        self.entry.write_text(f'include "{h.CONF}/routing-defs.nft"\ninclude "{h.CONF}/divert.conf"\n')
        h.nft(WITNESS)
        self.ports = h.Ports(40000)
        self.service_ports = h.Ports(50000)
        self.seq = 0
        self.sampler = h.Sampler(PARAMETERS['seed'], PARAMETERS['samples_per_segment'])
        self.loaded = False

    def load(self, dropins=None, files=None):
        shutil.rmtree(self.dropins)
        self.dropins.mkdir()
        for name, text in (dropins or {}).items():
            (self.dropins / name).write_text(text)
        for name, path in (files or {}).items():
            shutil.copy(path, self.dropins / name)
        h.run('nft', '-I', str(self.scratch), '-f', str(self.entry))
        self.loaded = True

    def unload(self):
        if self.loaded:
            h.nft('destroy table inet divert')
        self.loaded = False

    def leak(self, visible):
        """Route divert-marked traffic via main, so packets that escape divert reach the target."""
        if visible != self.leak_visible:
            for v in (4, 6):
                self.host.ip(f'-{v}', 'rule', 'add' if visible else 'del', 'priority', '90', 'lookup', 'main')
        self.leak_visible = visible

    def listener(self, v, tcp, transparent=True):
        return h.open_socket(self.host, ADDR[v]['any'], PORT, tcp=tcp, transparent=transparent,
                             listen=tcp)

    def flow(self, v, origin, tcp, mark, dest='target'):
        return Flow(self, v, origin, tcp, mark, dest)

    def read(self):
        return {name: h.observations('witness', name) for name in ('before', 'after', 'delivered', 'states')}


class Flow:
    def __init__(self, f, v, origin, tcp, mark, dest):
        a = ADDR[v]
        self.f, self.v, self.tcp, self.mark = f, v, tcp, mark
        self.sport, self.dport = f.ports(), f.service_ports()
        self.ns, self.src = (f.client, a['inlet'][1]) if origin == 'external' else (f.host, a['inlet'][0])
        self.dst = a['target'] if dest == 'target' else a['outlet'][0]
        h.nft(f'add element inet witness marks {{ {self.sport} : 0x{mark:08x} }}')
        self.s = h.open_socket(self.ns, self.src, self.sport, tcp=tcp)
        self.sink = h.open_socket(f.target if dest == 'target' else f.host, self.dst if dest == 'target'
                                  else a['any'], self.dport, tcp=tcp, listen=tcp)

    def close(self):
        self.s.close()
        self.sink.close()


class Suite:
    def __init__(self):
        self.f = Fixture()
        self.report = h.Report('divert', ITEMS, NOT_ASSERTED)

    # 4.2

    def tcp_success(self, v, origin):
        f = self.f
        f.load()
        f.leak(False)
        listener = f.listener(v, True)
        mark = f.sampler.bits(OTHER_BITS) | DIVERT
        flow = f.flow(v, origin, True, mark)
        try:
            expect(h.connect(flow.s, flow.dst, flow.dport), None, 'TCP connect')
            accepted = h.accept(listener)
            if accepted is None:
                raise Failure('listener did not accept')
            conn, peer = accepted
            expect(peer, (flow.src, flow.sport), 'client endpoint')
            expect(conn.getsockname()[:2], (flow.dst, flow.dport), 'original destination')
            for round in range(PARAMETERS['tcp_rounds']):
                up, down = f'up-{round}'.encode() * 64, f'down-{round}'.encode() * 64
                expect(h.stream_exchange(flow.s, conn, up), up, f'uplink round {round}')
                expect(h.stream_exchange(conn, flow.s, down), down, f'downlink round {round}')
            conn.close()
            expect(h.accept(flow.sink, 0), None, 'target accepted a connection')
        finally:
            flow.close()
            listener.close()
        expect(set(f.read()['delivered'].get(flow.sport, [])), {mark}, 'mark at delivery')

    def udp_success(self, v, origin):
        f = self.f
        f.load()
        f.leak(False)
        listener = f.listener(v, False)
        mark = f.sampler.bits(OTHER_BITS) | DIVERT
        flow = f.flow(v, origin, False, mark)
        try:
            def uplink(label):
                data = f'{label}-{flow.sport}'.encode()
                flow.s.sendto(data, (flow.dst, flow.dport))
                got = h.recv(listener)
                if got is None:
                    raise Failure(f'{label}: listener did not receive')
                expect(got[:2], (data, (flow.src, flow.sport)), f'{label}: payload and source')
                expect(got[2].get('origdst'), (flow.dst, flow.dport), f'{label}: original destination')

            uplink('first')
            uplink('consecutive')
            time.sleep(PARAMETERS['udp_interval_seconds'])
            uplink('interval')
            reply = h.open_socket(f.host, flow.dst, flow.dport, transparent=True)
            reply.connect((flow.src, flow.sport))
            reply.send(b'reply')
            got = h.recv(flow.s)
            expect(got[:2] if got else None, (b'reply', (flow.dst, flow.dport)), 'reply from original destination')
            reply.close()
            uplink('established')
            uplink('established-again')
            expect(h.recv(flow.sink, 0), None, 'target received')
        finally:
            flow.close()
            listener.close()
        seen = f.read()
        expect('established' in seen['states'].get(flow.sport, []), True, 'a non-NEW uplink was tested')
        expect(set(seen['delivered'].get(flow.sport, [])), {mark}, 'mark at delivery')

    def drop(self, v, origin, tcp, case):
        """case: 'none' (no socket), 'plain' (non-transparent socket on the port), 'service'."""
        f = self.f
        f.load()
        f.leak(origin == 'external' and case != 'service')
        decoy = f.listener(v, tcp, transparent=False) if case == 'plain' else None
        mark = f.sampler.bits(OTHER_BITS) | DIVERT
        flow = f.flow(v, origin, tcp, mark, 'local' if case == 'service' else 'target')
        try:
            self.expect_dropped(flow, decoy)
        finally:
            flow.close()
            if decoy:
                decoy.close()
        expect(flow.sport in f.read()['after'], False, 'packet passed divert')

    def expect_dropped(self, flow, decoy=None):
        wait = PARAMETERS['negative_wait_seconds']
        if flow.tcp:
            expect(h.connect(flow.s, flow.dst, flow.dport, timeout=wait), 'timeout', 'TCP connect')
            expect(h.accept(flow.sink, 0), None, 'sink accepted a connection')
            if decoy:
                expect(h.accept(decoy, 0), None, 'non-transparent listener accepted')
        else:
            flow.s.connect((flow.dst, flow.dport))
            flow.s.send(b'dropped')
            expect(h.recv(flow.sink, wait), None, 'sink received')
            if decoy:
                expect(h.recv(decoy, 0), None, 'non-transparent listener received')
            try:
                expect(h.recv(flow.s, 0), None, 'client received a response')
            except ConnectionRefusedError:
                raise Failure('client received an ICMP error')

    def recovery(self, v, origin, tcp):
        f = self.f
        f.load()
        f.leak(origin == 'external')
        mark = f.sampler.bits(OTHER_BITS) | DIVERT
        failed = f.flow(v, origin, tcp, mark)
        try:
            self.expect_dropped(failed)
        finally:
            failed.close()
        f.leak(False)
        listener = f.listener(v, tcp)
        flow = f.flow(v, origin, tcp, mark)
        try:
            if tcp:
                expect(h.connect(flow.s, flow.dst, flow.dport), None, 'TCP connect after recovery')
                expect(h.accept(listener) is not None, True, 'listener accepted after recovery')
            else:
                flow.s.sendto(b'recovered', (flow.dst, flow.dport))
                got = h.recv(listener)
                expect(got[0] if got else None, b'recovered', 'listener received after recovery')
        finally:
            flow.close()
            listener.close()

    # 4.1

    def outcome(self, v, mark, loaded):
        """Observable result of one UDP probe from the client toward the target."""
        f = self.f
        f.load() if loaded else f.unload()
        flow = f.flow(v, 'external', False, mark)
        try:
            flow.s.sendto(b'probe', (flow.dst, flow.dport))
            got = h.recv(flow.sink, PARAMETERS['negative_wait_seconds'])
            return (got[0], got[1][0]) if got else None
        finally:
            flow.close()

    def other_ids(self, v):
        f = self.f
        f.leak(False)
        values = f.sampler.segment(f'below-{v}', 0x000, DIVERT - 1) + \
            f.sampler.segment(f'above-{v}', DIVERT + 1, MASK)
        for value in values:
            mark = f.sampler.bits(OTHER_BITS) | value
            with_divert = self.outcome(v, mark, True)
            without = self.outcome(v, mark, False)
            if with_divert is None:
                raise Failure(f'ID {value:#05x} did not reach the target')
            expect(with_divert, without, f'ID {value:#05x} with and without divert')
        return {'ids': values}

    def protocol(self, v):
        f = self.f
        f.leak(False)
        a = ADDR[v]
        outcomes = []
        for loaded in (True, False):
            f.load() if loaded else f.unload()
            f.seq += 1
            seq, ident = f.seq, f.ports()
            h.send_icmp_echo(f.client, a['inlet'][1], a['target'], ident,
                             h.probe(seq, f.sampler.bits(OTHER_BITS) | DIVERT))
            time.sleep(0.05)
            outcomes.append(seq in h.elements('witness', 'icmp_after'))
        expect(outcomes, [True, True], 'ICMP passes divert with and without the module')

    # 5.1, 5.4

    def deliver_rules(self):
        f = self.f
        f.leak(False)
        table = '''table inet divert {
 set test_seen { typeof th sport; flags dynamic; }
 set test_hook_seen { typeof th sport; flags dynamic; }
 chain test_hook {
  type filter hook prerouting priority dstnat + 55;
  meta l4proto { tcp, udp } update @test_hook_seen { th sport }
 }
}
'''
        f.load({'50-test.conf': table + 'add rule inet divert divert_deliver meta l4proto { tcp, udp } '
                                        'update @test_seen { th sport }\n',
                '60-ignored.conf.sample': 'add rule inet divert divert_deliver drop\n'})
        listener = {v: f.listener(v, False) for v in (4, 6)}
        selected, other = [], []
        try:
            for v in (4, 6):
                for mark, group in ((DIVERT, selected), (0x001, other), (0x081, other)):
                    flow = f.flow(v, 'external', False, f.sampler.bits(OTHER_BITS) | mark)
                    flow.s.sendto(b'x', (flow.dst, flow.dport))
                    target = listener[v] if mark == DIVERT else flow.sink
                    if h.recv(target) is None:
                        raise Failure(f'mark {mark:#05x} was not delivered')
                    group.append(flow.sport)
                    flow.close()
        finally:
            for s in listener.values():
                s.close()

        seen, hooked = h.elements('divert', 'test_seen'), h.elements('divert', 'test_hook_seen')
        for port in selected:
            expect(port in seen, True, f'selected port {port} in divert_deliver')
            expect(port in hooked, True, f'selected port {port} in the hook chain')
        for port in other:
            expect(port in seen, False, f'unselected port {port} in divert_deliver')

    def verdict(self, v, tcp):
        f = self.f
        f.load({'50-test.conf': '''table inet divert {
 chain test_accept {
  type filter hook prerouting priority dstnat + 55;
  accept
 }
}
add rule inet divert divert_deliver accept
'''})
        f.leak(True)
        flow = f.flow(v, 'external', tcp, f.sampler.bits(OTHER_BITS) | DIVERT)
        try:
            self.expect_dropped(flow)
        finally:
            flow.close()

    def observe(self):
        f = self.f
        f.leak(False)
        f.load(files={'10-observe.conf': EXAMPLE})
        listener = {v: f.listener(v, False) for v in (4, 6)}
        selected = 0
        try:
            for v in (4, 6):
                for mark in (DIVERT, DIVERT, 0x001, 0x7ff):
                    flow = f.flow(v, 'external', False, f.sampler.bits(OTHER_BITS) | mark)
                    flow.s.sendto(b'x', (flow.dst, flow.dport))
                    if h.recv(listener[v] if mark == DIVERT else flow.sink) is None:
                        raise Failure(f'mark {mark:#05x} was not delivered')
                    selected += mark == DIVERT
                    flow.close()
        finally:
            for s in listener.values():
                s.close()
        rows = h.nft_json('list', 'chain', 'inet', 'divert', 'divert_deliver')
        counters = [e['counter']['packets'] for row in rows if 'rule' in row
                    for e in row['rule']['expr'] if 'counter' in e]
        expect(counters, [selected], 'observe counter')

    def run(self):
        r = self.report
        for v in (4, 6):
            for origin in ('external', 'local'):
                r.case(f'v{v}/{origin}/tcp', ['4.2/tcp', '4.2/preserve'], lambda: self.tcp_success(v, origin))
                r.case(f'v{v}/{origin}/udp', ['4.2/udp', '4.2/preserve'], lambda: self.udp_success(v, origin))
                for tcp in (False, True):
                    proto = 'tcp' if tcp else 'udp'
                    for case in ('none', 'plain', 'service'):
                        r.case(f'v{v}/{origin}/{proto}/drop-{case}', ['4.2/drop'],
                               lambda: self.drop(v, origin, tcp, case))
                    r.case(f'v{v}/{origin}/{proto}/recovery', ['4.2/recovery'],
                           lambda: self.recovery(v, origin, tcp))
            r.case(f'v{v}/other-ids', ['4.1/id'], lambda: self.other_ids(v))
            r.case(f'v{v}/icmp', ['4.1/protocol'], lambda: self.protocol(v))
            for tcp in (False, True):
                r.case(f'v{v}/{"tcp" if tcp else "udp"}/dropin-verdict', ['5.4/verdict'],
                       lambda: self.verdict(v, tcp))
        r.case('dropin/deliver', ['5.1', '5.4/deliver', '5.4/hook'], self.deliver_rules)
        r.case('example/observe', ['observe'], self.observe)
        return r.result({**PARAMETERS, 'samples': self.f.sampler.log})


def run():
    return Suite().run()
