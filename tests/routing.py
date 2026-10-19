"""routing: SPEC 1, 3, 5.1 and 5.3, and the routing examples."""

import json
import shutil
import tempfile
import time
from pathlib import Path

import harness as h
from harness import D, MASK, expect, Failure

PARAMETERS = json.loads((Path(__file__).with_name('parameters.json')).read_text())['routing']

ITEMS = {
    '1.1': ('core', 'mark 的其余位不影响 routing 的行为，并保持不变'),
    '1.3': ('core', 'priority 的入口值不影响 routing 的行为'),
    '3.1/untracked': ('core', '无 conntrack 上下文时，等同于 routing 不存在'),
    '3.1/invalid': ('core', 'INVALID 时，等同于 routing 不存在'),
    '3.1/type': ('core', '目的地址类型不是 local 或 unicast 时，等同于 routing 不存在'),
    '3.3/explicit': ('core', '入口值 E 输出 E，并成为当前方向的选择'),
    '3.3/existing': ('core', '入口值为 0 且已有选择 S 时输出 S'),
    '3.3/decision': ('core', '入口值为 0 且无选择时输出决策结果 D'),
    '3.3/directions': ('core', 'original 和 reply 方向分别记住选择'),
    '3.3/persistence': ('core', '路由表和 RPDB 的变化不改变选择，出口随系统路由改变'),
    '3.3/expiry': ('core', '连接状态失效后，新连接从空选择开始'),
    '3.4/class': ('core', '探测回退规则之前的 RPDB 规则选出路由时为 specific，否则为 gateway'),
    '3.4/result': ('core', '有提交时 D 为提交值，无提交时为 routing_normal'),
    '5.1': ('interface', '目录中的 *.conf 按文件名顺序追加，其他文件不加载'),
    '5.3/called': ('interface', 'routing_select 只在路由字段为 pending 时调用'),
    '5.3/intermediate': ('interface', 'drop-in 之间通过路由字段传递中间值'),
    '5.3/override': ('interface', '后执行的提交覆盖先执行的提交'),
    '5.3/opposite': ('interface', '提交可以写入对侧方向，包括已有显式选择的方向'),
    '5.3/hook': ('interface', '独立 hook 链的提交生效，并会遇到前提不成立的报文'),
    'contract/classify': ('example', '10-classify 的输出满足 5.3 的约束'),
    'contract/policy': ('example', '50-policy 的输出满足 5.3 的约束'),
    'contract/divert': ('example', '99-divert 的输出满足 5.3 的约束'),
    'classify': ('example', '10-classify：gateway 流量映射为 class，未命中时保持入口值'),
    'policy': ('example', '50-policy：目的网段命中的 original TCP/UDP 提交 0x081'),
    'divert': ('example', '99-divert：class 命中的 original TCP/UDP 提交 routing_divert'),
}

NOT_ASSERTED = {
    '3.1/undefined': '入口路由字段在 0x080-0xfff 内',
    '3.1/related': 'RELATED',
    '3.4/no-route': '无可用路由时的分类',
    '1.3/exit': 'priority 的出口值',
}

ADDR = {
    4: {'inlet': ('10.10.1.1', '10.10.1.2', 24), 'wan': ('10.10.2.1', '10.10.2.2', 24),
        'alt': ('10.10.3.1', '10.10.3.2', 24), 'remote': '198.51.100.2', 'other': '203.0.113.2',
        'multicast': '239.1.1.1', 'broadcast': '10.10.1.255',
        'blackhole': '192.0.2.10', 'unreachable': '192.0.2.11', 'prohibit': '192.0.2.12'},
    6: {'inlet': ('fd10:1::1', 'fd10:1::2', 64), 'wan': ('fd10:2::1', 'fd10:2::2', 64),
        'alt': ('fd10:3::1', 'fd10:3::2', 64), 'remote': '2001:db8:1::2', 'other': '2001:db8:2::2',
        'multicast': 'ff0e::1',
        'blackhole': '2001:db8:ff::10', 'unreachable': '2001:db8:ff::11', 'prohibit': '2001:db8:ff::12'},
}

SPECIFIC, GATEWAY = D['routing_specific'], D['routing_gateway']
NORMAL, DIVERT = D['routing_normal'], D['routing_divert']
# Test policy commits that reveal the classification.
SEEN_SPECIFIC, SEEN_GATEWAY = 0x0f0, 0x0f1
OTHER_BITS = 0xffffffff & ~MASK
ORIGINAL, REPLY = D['routing_original_mask'], D['routing_reply_mask']
SHIFT = D['routing_reply_shift']
EXAMPLES = h.CONF / 'routing.conf.d'


def commit(value, direction='current'):
    """nft rules that commit value; current means the direction of the packet."""
    original = f'ct mark set ct mark & $routing_original_clear_mask | 0x{value:03x}'
    reply = f'ct mark set ct mark & $routing_reply_clear_mask | 0x{value:03x} << $routing_reply_shift'
    if direction == 'current':
        return [f'ct direction original {original}', f'ct direction reply {reply}']
    return [original if direction == 'original' else reply]


def policy(name, rules, sets=''):
    body = '\n'.join(f'  {rule}' for rule in rules)
    return (f'table inet routing {{\n{sets} chain {name} {{\n{body}\n }}\n}}\n'
            f'add rule inet routing routing_select jump {name}\n')


CLASSIFIER = policy('test_classifier', [
    f'mark & $routing_mask $routing_specific {rule}' for rule in commit(SEEN_SPECIFIC)] + [
    f'mark & $routing_mask $routing_gateway {rule}' for rule in commit(SEEN_GATEWAY)])

# Sets the pending value from the probe so examples see a chosen input.
INPUT = '''table inet routing {
 set test_pre { typeof @th,96,32 . meta mark . ct mark; flags dynamic; }
 chain test_input {
  @th,192,32 != 0 meta mark set meta mark & $routing_clear_mask | @th,192,32
  meta l4proto { udp, icmp, ipv6-icmp } update @test_pre { @th,96,32 . meta mark . ct mark }
 }
}
add rule inet routing routing_select jump test_input
'''

WITNESS = f'''table inet witness {{
 set input {{ typeof {h.SEQ} . meta mark . fib daddr type; flags dynamic; }}
 set mid {{ typeof {h.SEQ} . meta mark . ct mark; flags dynamic; }}
 set output {{ typeof {h.SEQ} . meta mark; flags dynamic; }}
{h.INJECT}
 chain probe_in {{
  jump inject
  update @input {{ {h.SEQ} . meta mark . fib daddr type }}
 }}
 chain raw_pre {{ type filter hook prerouting priority raw; {h.PROBE} {h.NOTRACK}; }}
 chain raw_out {{ type filter hook output priority raw; {h.PROBE} {h.NOTRACK}; }}
 chain pre_in {{
  type filter hook prerouting priority dstnat + 24;
  iif lo return
  {h.PROBE} jump probe_in
  {h.ICMP_PROBE} jump probe_in
  {h.ICMP6_PROBE} jump probe_in
 }}
 chain out_in {{
  type filter hook output priority dstnat + 24;
  {h.PROBE} jump probe_in
 }}
 chain pre_mid {{
  type filter hook prerouting priority dstnat + 28;
  iif lo return
  {h.PROBE} update @mid {{ {h.SEQ} . meta mark . ct mark }}
  {h.ICMP_PROBE} update @mid {{ {h.SEQ} . meta mark . ct mark }}
  {h.ICMP6_PROBE} update @mid {{ {h.SEQ} . meta mark . ct mark }}
 }}
 chain out_mid {{
  type filter hook output priority dstnat + 28;
  {h.PROBE} update @mid {{ {h.SEQ} . meta mark . ct mark }}
 }}
 chain pre_out {{
  type filter hook prerouting priority dstnat + 48;
  iif lo return
  {h.PROBE} update @output {{ {h.SEQ} . meta mark }}
  {h.ICMP_PROBE} update @output {{ {h.SEQ} . meta mark }}
  {h.ICMP6_PROBE} update @output {{ {h.SEQ} . meta mark }}
 }}
 chain out_out {{
  type filter hook output priority dstnat + 48;
  {h.PROBE} update @output {{ {h.SEQ} . meta mark }}
 }}
}}
'''


class Fixture:
    def __init__(self):
        self.host = h.HOST
        self.client, self.remote = h.peer('client'), h.peer('remote')
        self.host.sysctl(**{'net.ipv4.ip_forward': 1, 'net.ipv6.conf.all.forwarding': 1})
        for name, peer, peer_name in (('inlet', self.client, 'ip0'), ('wan', self.remote, 'wp0'),
                                      ('alt', self.remote, 'ap0')):
            h.link(self.host, name, peer, peer_name, {v: ADDR[v][name] for v in (4, 6)})
        self.host.ip('link', 'add', D['routing_probe_interface'], 'type', 'dummy')
        self.host.ip('link', 'set', D['routing_probe_interface'], 'up')
        probe = f'{D["routing_probe"]:#x}/{MASK:#x}'
        for v in (4, 6):
            a = ADDR[v]
            for name in ('remote', 'other'):
                h.add_address(self.remote, v, a[name])
            self.client.ip(f'-{v}', 'route', 'add', 'default', 'via', a['inlet'][0])
            self.remote.ip(f'-{v}', 'route', 'add', 'default', 'via', a['wan'][0])
            nexthop = D[f'routing_probe_nexthop{v}']
            self.host.ip(f'-{v}', 'route', 'add', 'default', 'via', nexthop, 'dev',
                         D['routing_probe_interface'], 'onlink', 'table', '1000')
            # IPv4 keeps its default route in main and suppresses it for probes.
            suppress = ('suppress_prefixlength', '0') if v == 4 else ()
            self.host.ip(f'-{v}', 'route', 'add', 'default', 'via', a['wan'][1],
                         *(() if v == 4 else ('table', 'default')))
            self.host.ip(f'-{v}', 'rule', 'add', 'priority', '31000', 'fwmark', probe, 'lookup', 'main', *suppress)
            self.host.ip(f'-{v}', 'rule', 'add', 'priority', '31001', 'fwmark', probe, 'lookup', '1000')
            if v == 6:
                self.host.ip(f'-{v}', 'rule', 'add', 'priority', '32767', 'lookup', 'default')
            for kind in ('blackhole', 'unreachable', 'prohibit'):
                self.host.ip(f'-{v}', 'route', 'add', kind, a[kind])
        self.scratch = Path(tempfile.mkdtemp(prefix='routing-'))
        self.dropins = self.scratch / 'nftables.conf.d/routing.conf.d'
        self.dropins.mkdir(parents=True)
        self.entry = self.scratch / 'entry.nft'
        self.entry.write_text(f'include "{h.CONF}/routing-defs.nft"\ninclude "{h.CONF}/routing.conf"\n')
        h.nft(WITNESS)
        self.ports = h.Ports()
        self.seq = 0
        self.sampler = h.Sampler(PARAMETERS['seed'], PARAMETERS['samples_per_segment'])

    def load(self, dropins=None, files=None):
        shutil.rmtree(self.dropins)
        self.dropins.mkdir()
        for name, text in (dropins or {}).items():
            (self.dropins / name).write_text(text)
        for name, path in (files or {}).items():
            shutil.copy(path, self.dropins / name)
        h.run('nft', '-I', str(self.scratch), '-f', str(self.entry))

    def flow(self, v, origin='external', dest='remote'):
        a = ADDR[v]
        sender, src = (self.client, a['inlet'][1]) if origin == 'external' else (self.host, a['inlet'][0])
        if dest == 'local':
            receiver, dst = self.host, a['inlet'][0] if origin == 'external' else a['wan'][0]
        else:
            receiver, dst = self.remote, a[dest]
        return Flow(self, sender, src, receiver, dst)

    def next_seq(self):
        self.seq += 1
        return self.seq

    def read(self):
        return Observed(h.observations('witness', 'input'), h.observations('witness', 'mid'),
                        h.observations('witness', 'output'))

    def bits(self):
        return self.sampler.bits(OTHER_BITS)

    def route(self, v, dest, via=None):
        """Install or remove a main-table route for dest."""
        a = ADDR[v]
        target = a[dest]
        if self.host.ip(f'-{v}', 'route', 'show', 'table', 'main', 'exact', target).strip():
            self.host.ip(f'-{v}', 'route', 'del', target)
        if via:
            self.host.ip(f'-{v}', 'route', 'add', target, 'via', a[via][1])


class Observed:
    def __init__(self, input, mid, output):
        self.input, self.mid, self.output = input, mid, output

    def one(self, table, seq):
        rows = table.get(seq, [])
        if len(rows) != 1:
            raise Failure(f'probe {seq}: expected one observation, got {rows}')
        return rows[0]

    def out(self, seq):
        return self.one(self.output, seq)

    def type(self, seq):
        return self.one(self.input, seq)[1]


class Flow:
    def __init__(self, f, sender, src, receiver, dst):
        self.f = f
        self.sport, self.dport = f.ports(2)
        self.src, self.dst = src, dst
        self.sender, self.receiver = sender, receiver
        self.a = h.open_socket(sender, src, self.sport, info=True)
        self.b = h.open_socket(receiver, dst, self.dport, info=True)

    def send(self, mark=0, reverse=False, deliver=True, **kwargs):
        seq = self.f.next_seq()
        data = h.probe(seq, mark, **kwargs)
        a, b, ns, dst, port = (self.b, self.a, self.sender, self.src, self.sport) if reverse else \
            (self.a, self.b, self.receiver, self.dst, self.dport)
        a.sendto(data, (dst, port))
        if deliver:
            got = h.recv(b, ns=ns)
            if got is None or got[0] != data:
                raise Failure(f'probe {seq} was not delivered')
            self.last = got
        return seq

    def close(self):
        self.a.close()
        self.b.close()


class Suite:
    def __init__(self):
        self.f = Fixture()
        self.report = h.Report('routing', ITEMS, NOT_ASSERTED)

    def expect_out(self, seen, seq, mark, field, label):
        expect(seen.out(seq), (mark & OTHER_BITS) | field, label)

    # 3.3

    def explicit(self, v, origin):
        f = self.f
        f.load({'50-test.conf': CLASSIFIER})
        values = f.sampler.segment(f'explicit-low-{v}-{origin}', 0x001, 0x03f) + \
            f.sampler.segment(f'explicit-high-{v}-{origin}', 0x040, 0x07f)
        checks = []
        for e in values:
            other = 0x001 + (e % 0x07e)
            flow = f.flow(v, origin)
            plan = [(e, False, e), (0, False, e), (other, False, other), (0, False, other),
                    (0, True, SEEN_SPECIFIC), (0, True, SEEN_SPECIFIC), (e, True, e), (0, True, e),
                    (0, False, other)]
            for value, reverse, field in plan:
                mark = f.bits() | value
                checks.append((flow.send(mark, reverse), mark, field))
            flow.close()
        seen = f.read()
        for seq, mark, field in checks:
            self.expect_out(seen, seq, mark, field, f'probe {seq}')
        return {'values': values}

    def decision(self, v, origin):
        f = self.f
        f.load()
        flow = f.flow(v, origin)
        plain = [(flow.send(m := f.bits()), m, NORMAL), (flow.send(m := f.bits()), m, NORMAL)]
        flow.close()
        submitted = f.sampler.segment(f'submitted-{v}-{origin}', 0x080, 0x0ff)
        checks = []
        for value in submitted:
            f.load({'50-test.conf': policy('test_submit', [
                f'mark & $routing_mask $routing_gateway {rule}' for rule in commit(value)])})
            flow = f.flow(v, origin)
            for _ in range(2):
                mark = f.bits()
                checks.append((flow.send(mark), mark, value))
            flow.close()
        seen = f.read()
        for seq, mark, field in plain + checks:
            self.expect_out(seen, seq, mark, field, f'probe {seq}')
        return {'submitted': submitted}

    def persistence(self, v, origin):
        f = self.f
        f.load({'50-test.conf': CLASSIFIER})
        flow = f.flow(v, origin)
        checks = [(flow.send(m := f.bits()), m, SEEN_GATEWAY)]
        expect(flow.last[2]['iface'], 'wp0', 'egress before route change')
        try:
            f.route(v, 'remote', via='alt')
            checks.append((flow.send(m := f.bits()), m, SEEN_GATEWAY))
            expect(flow.last[2]['iface'], 'ap0', 'egress follows the new route')
            f.host.ip(f'-{v}', 'rule', 'add', 'priority', '100', 'lookup', 'main')
            checks.append((flow.send(m := f.bits()), m, SEEN_GATEWAY))
            fresh = f.flow(v, origin)
            checks.append((fresh.send(m := f.bits()), m, SEEN_SPECIFIC))
            fresh.close()
        finally:
            f.host.ip(f'-{v}', 'rule', 'del', 'priority', '100')
            f.route(v, 'remote')
            flow.close()
        seen = f.read()
        for seq, mark, field in checks:
            self.expect_out(seen, seq, mark, field, f'probe {seq}')

    def expiry(self, v):
        f = self.f
        f.load({'50-test.conf': CLASSIFIER})
        keys = ('net.netfilter.nf_conntrack_udp_timeout', 'net.netfilter.nf_conntrack_udp_timeout_stream')
        saved = {k: Path('/proc/sys', k.replace('.', '/')).read_text().strip() for k in keys}
        flow = f.flow(v)
        try:
            f.host.sysctl(**{k: 1 for k in keys})
            checks = [(flow.send(m := f.bits()), m, SEEN_GATEWAY)]
            f.route(v, 'remote', via='wan')
            checks.append((flow.send(m := f.bits()), m, SEEN_GATEWAY))
            time.sleep(PARAMETERS['expiry_wait_seconds'])
            checks.append((flow.send(m := f.bits()), m, SEEN_SPECIFIC))
        finally:
            f.host.sysctl(**saved)
            f.route(v, 'remote')
            flow.close()
        seen = f.read()
        for seq, mark, field in checks:
            self.expect_out(seen, seq, mark, field, f'probe {seq}')

    # 1.1, 1.3

    def other_bits(self, v):
        f = self.f
        f.load({'50-test.conf': CLASSIFIER})
        checks = []
        for bits in (0, OTHER_BITS, f.bits(), f.bits()):
            flow = f.flow(v)
            checks += [(flow.send(bits), bits, SEEN_GATEWAY), (flow.send(bits | 0x033), bits, 0x033),
                       (flow.send(bits), bits, 0x033), (flow.send(bits, reverse=True), bits, SEEN_SPECIFIC)]
            flow.close()
        seen = f.read()
        for seq, mark, field in checks:
            self.expect_out(seen, seq, mark, field, f'probe {seq}')

    def priority(self, v, origin):
        f = self.f
        f.load({'50-test.conf': CLASSIFIER})
        checks = []
        for index in h.PRIORITIES:
            flow = f.flow(v, origin)
            checks += [(flow.send(m := f.bits(), priority=index), m, SEEN_GATEWAY),
                       (flow.send(m := f.bits(), priority=index), m, SEEN_GATEWAY)]
            flow.close()
        seen = f.read()
        for seq, mark, field in checks:
            self.expect_out(seen, seq, mark, field, f'probe {seq}')

    # 3.1

    def untracked(self, v, origin):
        f = self.f
        f.load({'50-test.conf': CLASSIFIER})
        flow = f.flow(v, origin)
        checks = []
        for value in (0x000, 0x033, 0x07f):
            mark = f.bits() | value
            checks.append((flow.send(mark, notrack=True), mark, value))
        control = f.flow(v, origin)
        checks.append((control.send(m := f.bits()), m, SEEN_GATEWAY))
        flow.close()
        control.close()
        seen = f.read()
        for seq, mark, field in checks:
            self.expect_out(seen, seq, mark, field, f'probe {seq}')

    def invalid(self, v):
        f = self.f
        f.load({'50-test.conf': CLASSIFIER})
        a = ADDR[v]
        checks = []
        for value in (0x000, 0x033):
            mark = f.bits() | value
            seq = f.next_seq()
            sport, dport = f.ports(2)
            h.send_bad_udp(f.client, a['inlet'][1], a['remote'], sport, dport, h.probe(seq, mark))
            checks.append((seq, mark, value))
        time.sleep(0.05)
        seen = f.read()
        for seq, mark, field in checks:
            self.expect_out(seen, seq, mark, field, f'probe {seq}')

    def types(self, v):
        f = self.f
        f.load({'50-test.conf': CLASSIFIER})
        a = ADDR[v]
        targets = [('external', 'multicast'), ('local', 'multicast')]
        targets += [('external', k) for k in ('broadcast', 'blackhole', 'unreachable', 'prohibit') if k in a]
        sent = []
        for origin, kind in targets:
            src = a['inlet'][1] if origin == 'external' else a['inlet'][0]
            ns = f.client if origin == 'external' else f.host
            s = h.open_socket(ns, src, f.ports())
            for value in (0x000, 0x033):
                mark = f.bits() | value
                seq = f.next_seq()
                s.sendto(h.probe(seq, mark), (a[kind], f.ports()))
                sent.append((kind, seq, mark, value))
            s.close()
        time.sleep(0.05)
        seen = f.read()
        bypassed = 0
        for kind, seq, mark, value in sent:
            kind_seen = seen.type(seq)
            if kind_seen in ('local', 'unicast'):
                continue
            bypassed += 1
            self.expect_out(seen, seq, mark, value, f'{kind} probe {seq} ({kind_seen})')
        if not bypassed:
            raise Failure('no probe had a non-unicast destination type')
        return {'types': sorted({(k, seen.type(s)) for k, s, _, _ in sent})}

    # 3.4

    def classes(self, v, origin):
        f = self.f
        f.load({'50-test.conf': CLASSIFIER})
        checks = []
        for dest, field in (('remote', SEEN_GATEWAY), ('local', SEEN_SPECIFIC)):
            flow = f.flow(v, origin, dest)
            checks.append((flow.send(m := f.bits()), m, field))
            flow.close()
        try:
            f.route(v, 'other', via='wan')
            flow = f.flow(v, origin, 'other')
            checks.append((flow.send(m := f.bits()), m, SEEN_SPECIFIC))
            flow.close()
        finally:
            f.route(v, 'other')
        # A deployer rule ahead of the probe rules decides the class; without a route it falls through.
        a = ADDR[v]
        src = a['inlet'][1] if origin == 'external' else a['inlet'][0]
        f.host.ip(f'-{v}', 'route', 'add', a['other'], 'via', a['wan'][1], 'table', '200')
        f.host.ip(f'-{v}', 'rule', 'add', 'priority', '500', 'from', src, 'lookup', '200')
        try:
            for dest, field in (('other', SEEN_SPECIFIC), ('remote', SEEN_GATEWAY)):
                flow = f.flow(v, origin, dest)
                checks.append((flow.send(m := f.bits()), m, field))
                flow.close()
        finally:
            f.host.ip(f'-{v}', 'rule', 'del', 'priority', '500')
            f.host.ip(f'-{v}', 'route', 'flush', 'table', '200')
        seen = f.read()
        for seq, mark, field in checks:
            self.expect_out(seen, seq, mark, field, f'probe {seq}')

    # 5.1, 5.3

    def order(self):
        f = self.f
        mark_step = policy('test_a', ['mark & $routing_mask $routing_gateway '
                                      'meta mark set meta mark & $routing_clear_mask | 0x200'])
        submit_step = policy('test_b', [f'mark & $routing_mask 0x200 {r}' for r in commit(0x0aa)])
        ignored = policy('test_c', [f'mark & $routing_mask $routing_gateway {r}' for r in commit(0x0bb)])
        checks = []
        for dropins, field in (({'10-a.conf': mark_step, '20-b.conf': submit_step}, 0x0aa),
                               ({'10-b.conf': submit_step, '20-a.conf': mark_step}, NORMAL)):
            dropins['30-c.conf.sample'] = ignored
            dropins['40-c.txt'] = ignored
            f.load(dropins)
            for v in (4, 6):
                flow = f.flow(v)
                checks.append((flow.send(m := f.bits()), m, field))
                flow.close()
        seen = f.read()
        for seq, mark, field in checks:
            self.expect_out(seen, seq, mark, field, f'probe {seq}')

    def called(self):
        f = self.f
        f.load({'50-test.conf': policy('test_calls', ['update @calls { @th,96,32 }'] + [
            f'mark & $routing_mask $routing_gateway {r}' for r in commit(SEEN_GATEWAY)] + [
            f'mark & $routing_mask $routing_specific {r}' for r in commit(SEEN_SPECIFIC)],
            sets=' set calls { typeof @th,96,32; flags dynamic; }\n')})
        expected = {}
        for v in (4, 6):
            for origin in ('external', 'local'):
                flow = f.flow(v, origin)
                for reverse, call in ((False, True), (False, False), (True, True), (True, False)):
                    expected[flow.send(f.bits(), reverse)] = call
                flow.close()
                flow = f.flow(v, origin)
                for value in (0x011, 0x000):
                    expected[flow.send(f.bits() | value)] = False
                expected[flow.send(f.bits(), notrack=True)] = False
                flow.close()
        calls = h.elements('routing', 'calls')
        for seq, call in expected.items():
            expect(seq in calls, call, f'probe {seq} policy call')

    def override(self):
        f = self.f
        f.load({'10-a.conf': policy('test_a', [f'mark & $routing_mask $routing_gateway {r}' for r in commit(0x0a1)]),
                '20-b.conf': policy('test_b', [f'mark & $routing_mask $routing_gateway {r}' for r in commit(0x0a2)])})
        checks = []
        for v in (4, 6):
            flow = f.flow(v)
            checks += [(flow.send(m := f.bits()), m, 0x0a2), (flow.send(m := f.bits()), m, 0x0a2)]
            flow.close()
        seen = f.read()
        for seq, mark, field in checks:
            self.expect_out(seen, seq, mark, field, f'probe {seq}')

    def opposite(self):
        f = self.f
        rules = []
        rules += [f'ct direction original {r}' for r in commit(0x0c1, 'original') + commit(0x0c2, 'reply')]
        rules += [f'ct direction reply {r}' for r in commit(0x0c3, 'original') + commit(0x0c4, 'reply')]
        f.load({'50-test.conf': policy('test_opposite', rules)})
        checks = []
        for v in (4, 6):
            for origin in ('external', 'local'):
                flow = f.flow(v, origin)
                checks += [(flow.send(m := f.bits()), m, 0x0c1),
                           (flow.send(m := f.bits(), reverse=True), m, 0x0c2)]
                flow.close()
                flow = f.flow(v, origin)
                checks += [(flow.send(m := f.bits() | 0x011), m, 0x011),
                           (flow.send(m := f.bits(), reverse=True), m, 0x0c4),
                           (flow.send(m := f.bits()), m, 0x0c3)]
                flow.close()
        seen = f.read()
        for seq, mark, field in checks:
            self.expect_out(seen, seq, mark, field, f'probe {seq}')

    def hook(self):
        f = self.f
        rules = [f'mark & $routing_mask $routing_gateway {r}' for r in commit(0x0d1)]
        rules.append('mark & $routing_mask < 0x100 update @outside { @th,96,32 }')
        chains = ''.join(f''' chain test_{hook} {{
  type filter hook {hook} priority dstnat + {priority};
  meta l4proto udp udp dport {h.PORTS} jump test_body
 }}
''' for hook, priority in (('prerouting', 28), ('output', 46)))
        body = '\n'.join(f'  {r}' for r in rules)
        f.load({'50-test.conf': f'''table inet routing {{
 set outside {{ typeof @th,96,32; flags dynamic; }}
 chain test_body {{
{body}
 }}
{chains}}}
'''})
        checks, outside = [], []
        for v in (4, 6):
            for origin in ('external', 'local'):
                flow = f.flow(v, origin)
                checks.append((flow.send(m := f.bits()), m, 0x0d1))
                outside.append(flow.send(f.bits()))
                flow.close()
                flow = f.flow(v, origin)
                outside.append(flow.send(f.bits() | 0x022))
                flow.close()
        seen = f.read()
        for seq, mark, field in checks:
            self.expect_out(seen, seq, mark, field, f'probe {seq}')
        recorded = h.elements('routing', 'outside')
        for seq in outside:
            expect(seq in recorded, True, f'probe {seq} reached the hook chain')

    # Examples

    def contract(self, example):
        f = self.f
        name = {'classify': '10-classify.conf.sample', 'policy': '50-policy.conf.sample',
                'divert': '99-divert.conf.sample'}[example]
        f.load({'00-input.conf': INPUT}, {name.removesuffix('.sample'): EXAMPLES / name})
        if example == 'classify':
            for v in (4, 6):
                h.nft(f'add element inet routing geo{v} {{ {ADDR[v]["remote"]} : 0x800 }}')
            h.nft('add element inet routing geoclass { 0x800 : 0x102 }')
        if example == 'divert':
            h.nft(f'add element inet routing divert_classes {{ 0x102, 0x200-0x2ff }}\n'
                  f'flush set inet routing divert_cgroupsv2\n'
                  f'add element inet routing divert_cgroupsv2 {{ "{h.local_cgroup()}" }}')
        inputs = [0, SPECIFIC, GATEWAY, 0x102, 0x103, D['routing_probe'], 0x800, 0xfff, 0x250] + \
            f.sampler.segment(f'contract-{example}', 0x100, 0xfff)
        sent = []
        for v in (4, 6):
            for origin in ('external', 'local'):
                for value in inputs:
                    opposite = f.sampler.random.choice([0, 0x080, 0x0ab, 0x0ff])
                    flow = f.flow(v, origin)
                    preset = f.sampler.bits(0xffff0000) | (opposite << SHIFT)
                    sent.append(flow.send(f.bits(), ct=preset, extra=value))
                    explicit = f.sampler.random.choice([0x001, 0x055, 0x07f])
                    flow.send(f.bits() | explicit)
                    preset = f.sampler.bits(0xffff0000) | explicit
                    sent.append(flow.send(f.bits(), reverse=True, ct=preset, extra=value))
                    flow.close()
        before = h.observations('routing', 'test_pre')
        seen = f.read()
        for seq in sent:
            pre_mark, pre_ct = seen.one(before, seq)
            post_mark, post_ct = seen.one(seen.mid, seq)
            errors = violations(pre_mark, pre_ct, post_mark, post_ct)
            if errors:
                raise Failure(f'probe {seq}: {errors} before={pre_mark:#x}/{pre_ct:#x} '
                              f'after={post_mark:#x}/{post_ct:#x}')
        return {'inputs': inputs}

    def classify(self):
        f = self.f
        f.load(files={'10-classify.conf': EXAMPLES / '10-classify.conf.sample'})
        for v in (4, 6):
            a = ADDR[v]
            h.nft(f'add element inet routing geo{v} {{ {a["remote"]} : 0x800, {a["other"]} : 0x801, '
                  f'{a["inlet"][0]} : 0x800, {a["wan"][0]} : 0x800 }}')
        # 0x000 is not a country; an address lookup miss must not reach geoclass.
        h.nft('add element inet routing geoclass { 0x000 : 0x103, 0x800 : 0x102 }')
        checks = []
        for v in (4, 6):
            for origin in ('external', 'local'):
                cases = [('remote', 0, 0x102), ('remote', 2, 0x102), ('remote', 4, 0x102),
                         ('other', 0, GATEWAY), ('local', 0, SPECIFIC)]
                for dest, priority, field in cases:
                    flow = f.flow(v, origin, dest)
                    checks.append((flow.send(m := f.bits(), priority=priority), m, field))
                    flow.close()
                h.nft(f'delete element inet routing geo{v} {{ {ADDR[v]["remote"]} }}')
                flow = f.flow(v, origin)
                checks.append((flow.send(m := f.bits()), m, GATEWAY))
                flow.close()
                h.nft(f'add element inet routing geo{v} {{ {ADDR[v]["remote"]} : 0x800 }}')
        seen = f.read()
        for seq, mark, field in checks:
            expect(seen.one(seen.mid, seq)[0], (mark & OTHER_BITS) | field, f'probe {seq} class')
            self.expect_out(seen, seq, mark, NORMAL, f'probe {seq}')

    def policy_example(self):
        f = self.f
        f.load(files={'50-policy.conf': EXAMPLES / '50-policy.conf.sample'})
        checks = []
        for v in (4, 6):
            for origin in ('external', 'local'):
                for dest, field in (('remote', 0x081 if v == 4 else NORMAL), ('other', NORMAL),
                                    ('local', NORMAL)):
                    flow = f.flow(v, origin, dest)
                    checks.append((flow.send(m := f.bits()), m, field))
                    flow.close()
        icmp = []
        for v in (4, 6):
            seq = f.next_seq()
            h.send_icmp_echo(f.client, ADDR[v]['inlet'][1], ADDR[v]['remote'], f.ports(), h.probe(seq, 0))
            icmp.append(seq)
        time.sleep(0.05)
        seen = f.read()
        for seq, mark, field in checks:
            self.expect_out(seen, seq, mark, field, f'probe {seq}')
        for seq in icmp:
            self.expect_out(seen, seq, 0, NORMAL, f'ICMP probe {seq}')

    def divert(self):
        f = self.f
        f.load({'00-input.conf': INPUT}, {'99-divert.conf': EXAMPLES / '99-divert.conf.sample'})
        h.nft('add element inet routing divert_classes { 0x102 }')

        def cgroup(member):
            h.nft('flush set inet routing divert_cgroupsv2' +
                  (f'\nadd element inet routing divert_cgroupsv2 {{ "{h.local_cgroup()}" }}' if member else ''))

        checks = []
        for v in (4, 6):
            for member in (True, False):
                cgroup(member)
                for origin in ('external', 'local'):
                    selected = origin == 'external' or member
                    for value, field in ((0x102, DIVERT if selected else NORMAL), (0x103, NORMAL)):
                        flow = f.flow(v, origin)
                        checks.append((flow.send(m := f.bits(), extra=value), m, field))
                        flow.close()
                    flow = f.flow(v, origin)
                    checks.append((flow.send(m := f.bits() | 0x011), m, 0x011))
                    checks.append((flow.send(m := f.bits(), reverse=True, extra=0x102), m, NORMAL))
                    flow.close()
        icmp = []
        for v in (4, 6):
            seq = f.next_seq()
            h.send_icmp_echo(f.client, ADDR[v]['inlet'][1], ADDR[v]['remote'], f.ports(),
                             h.probe(seq, 0, extra=0x102))
            icmp.append(seq)
        time.sleep(0.05)
        seen = f.read()
        for seq, mark, field in checks:
            self.expect_out(seen, seq, mark, field, f'probe {seq}')
        for seq in icmp:
            self.expect_out(seen, seq, 0, NORMAL, f'ICMP probe {seq}')

    def run(self):
        r = self.report
        for v in (4, 6):
            for origin in ('external', 'local'):
                r.case(f'v{v}/{origin}/explicit', ['3.3/explicit', '3.3/existing', '3.3/directions'],
                       lambda: self.explicit(v, origin))
                r.case(f'v{v}/{origin}/decision', ['3.3/decision', '3.3/existing', '3.4/result'],
                       lambda: self.decision(v, origin))
                r.case(f'v{v}/{origin}/persistence', ['3.3/persistence'], lambda: self.persistence(v, origin))
                r.case(f'v{v}/{origin}/priority', ['1.3'], lambda: self.priority(v, origin))
                r.case(f'v{v}/{origin}/untracked', ['3.1/untracked'], lambda: self.untracked(v, origin))
                r.case(f'v{v}/{origin}/classes', ['3.4/class'], lambda: self.classes(v, origin))
            r.case(f'v{v}/expiry', ['3.3/expiry'], lambda: self.expiry(v))
            r.case(f'v{v}/other-bits', ['1.1'], lambda: self.other_bits(v))
            r.case(f'v{v}/invalid', ['3.1/invalid'], lambda: self.invalid(v))
            r.case(f'v{v}/types', ['3.1/type'], lambda: self.types(v))
        r.case('dropin/order', ['5.1', '5.3/intermediate'], self.order)
        r.case('dropin/called', ['5.3/called'], self.called)
        r.case('dropin/override', ['5.3/override'], self.override)
        r.case('dropin/opposite', ['5.3/opposite'], self.opposite)
        r.case('dropin/hook', ['5.3/hook'], self.hook)
        for example in ('classify', 'policy', 'divert'):
            r.case(f'contract/{example}', [f'contract/{example}'], lambda: self.contract(example))
        r.case('example/classify', ['classify'], self.classify)
        r.case('example/policy', ['policy'], self.policy_example)
        r.case('example/divert', ['divert'], self.divert)
        return r.result({**PARAMETERS, 'samples': self.f.sampler.log})


def violations(before_mark, before_ct, after_mark, after_ct):
    """Check one drop-in invocation against the SPEC 5.3 table."""
    errors = []
    if after_mark & MASK not in h.PENDING:
        errors.append('mark.range')
    if before_mark & OTHER_BITS != after_mark & OTHER_BITS:
        errors.append('mark.other-bits')
    for name, mask, shift in (('original', ORIGINAL, 0), ('reply', REPLY, SHIFT)):
        before, after = (before_ct & mask) >> shift, (after_ct & mask) >> shift
        if after != before and not 0x080 <= after <= 0x0ff:
            errors.append(f'ct.{name}')
    if before_ct & ~(ORIGINAL | REPLY) != after_ct & ~(ORIGINAL | REPLY):
        errors.append('ct.other-bits')
    return errors


def run():
    return Suite().run()
