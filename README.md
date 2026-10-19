# nftables

模块化的 nftables 网关配置，分为三个模块：

- **fw**：访问控制、NAT 和报文调整。
- **routing**：为连接的每个方向选择路由 ID，交给 RPDB 选择路由表。
- **divert**：把选中的 TCP/UDP 交给本机的监听程序，例如检查程序或代理程序。

典型用途是出口网关：子网和本机发往默认路由的流量中，按目的地选出一部分交给本机程序处理，其余流量正常转发。

## 文档

- [SPEC.md](SPEC.md)：行为规范，包括三个模块的契约、drop-in 挂载接口和部署前提。
- [tests/README.md](tests/README.md)：测试的运行方式和覆盖范围。

## 目录

`etc/` 下的文件按部署路径排列，对应 `/etc` 下的同名位置：

```text
etc/
  nftables.conf                       入口，加载常量和各模块
  nftables.conf.d/
    routing-defs.nft                  路由字段、路由 ID 和探测参数
    fw.conf, fw.conf.d/               fw 模块及其 drop-in 目录
    routing.conf, routing.conf.d/     routing 模块及其 drop-in 目录
    divert.conf, divert.conf.d/       divert 模块及其 drop-in 目录
  systemd/network/                    探测、RPDB 和默认路由分表的 networkd 配置
tests/                                测试
```

## 工作方式

### 默认行为

不启用任何 drop-in 时：

- fw 丢弃未经许可的本机接收、转发和本机发出。经过 lo 的报文、ESTABLISHED 和 RELATED 连接，以及交给透明 socket 的报文除外。
- routing 为所有连接选择普通路由 `0x001`，结果与没有 routing 时相同。

### 路由选择

routing 用报文 mark 的低 12 位传递路由 ID。连接的 original 和 reply 方向各有一个选择，保存在 ct mark 中。处理过程如下：

1. 一个方向的首个报文到达时，routing 先探测目的端并分类。local 表、main 表，或优先级在探测回退规则之前的 RPDB 规则选出了路由时，分类为 specific，否则为 gateway。
2. drop-in 在 `routing_select` 中按分类、地址等条件为连接提交路由 ID。
3. 没有提交时，选择普通路由 `0x001`。
4. 选择写入 ct mark，并恢复到报文 mark，RPDB 按 mark 选择路由表。
5. 同一方向的后续报文直接沿用已保存的选择，不再探测，也不再调用 drop-in。

routing 位于 fw 的 DNAT 之后，所以按转换后的目的端选择。

### 交给监听程序

路由 ID 为 `0x080`（`routing_divert`）的报文按 RPDB 规则查表 3346。这张表只有一条指向 lo 的 local 默认路由，所以报文进入本机。divert 用 TPROXY 把报文交给 `tproxy_port` 上的监听 socket。交付失败时丢弃，不会退回直达，也不会交给普通本机服务。

本机发出的流量被选中后经 lo 回注，在 PREROUTING 中走同一条交付路径。

## 部署

### 文件

将 `etc/` 下的文件复制到 `/etc` 的同名位置。入口文件默认加载三个模块。不需要某个模块时，删除或重命名它的 `.conf` 文件。routing 和 divert 都依赖 `routing-defs.nft`。

检查配置：

```sh
sudo nft -c -f /etc/nftables.conf
```

在仓库目录中，可以在临时的 namespace 里检查：

```sh
unshare -rn nft -I etc -c -f etc/nftables.conf
```

### 路由

`etc/systemd/network/` 提供 systemd-networkd 的配置：

| 文件 | 内容 |
| --- | --- |
| `00-loopback.network` | RPDB 规则、表 3346 的 local 默认路由，以及 default 表的 unreachable 兜底路由 |
| `10-rtprobe.netdev`、`10-rtprobe.network` | dummy 接口 `rtprobe`，以及表 1000 中经 `rtprobe` 的默认路由 |
| `wan.network.d/10-default-route.conf.sample` | 把 DHCPv4 网关和 RA 默认网关安装到 default 表 |

RPDB 规则如下：

| 优先级 | 匹配 | 查询 | 用途 |
| --- | --- | --- | --- |
| 100 | `0x080/0xfff` | 表 3346 | 把选中的流量交给本机 |
| 31000 | `0x7ff/0xfff` | main | 探测 |
| 31001 | `0x7ff/0xfff` | 表 1000 | 探测回退 |
| 32000 | 全部 | main，抑制默认路由 | 普通查询 |
| 32001 | 全部 | default | 普通查询 |

`0x001` 和 `0x080` 以外的路由 ID 没有现成的 RPDB 规则和路由表，需要另外配置。添加规则时：

- 优先级 100 的规则为 `0x080` 选出路由，排在它之后的规则改变不了交给 divert 的路由。
- 排在探测回退规则之前、又能匹配探测报文的规则会影响分类：它为目的端选出路由时，该目的端分类为 specific。不限定 fwmark 的规则，以及掩码不覆盖完整路由字段的 fwmark 规则，都可能匹配探测报文，例如 `fwmark 0x1/0x1` 匹配 `0x7ff`。按完整路由字段匹配 fwmark 的规则不会匹配探测报文。

部署前提：**默认路由不放在 main 表中**，静态默认路由也一样，都放在 default 表。

- 探测按「main 表中没有路由」识别 gateway 流量。main 表中有默认路由时，所有目的端都会分类为 specific。
- IPv6 的 nft FIB 查询不遵守 `suppress_prefixlength`，所以 RPDB 规则无法在探测中抑制 main 表的默认路由。

`wan.network.d/` 只是示例目录名。使用时，改成实际 WAN 接口的基础 `.network` 文件名加 `.d`，再去掉 `.sample` 后缀。

已知限制：

- RIO 中的 `::/0` 和 DHCP option 121 中的默认路由仍会进入 main 表，不受支持。这两类来源中的具体路由不受影响。
- `RouteDenyList=::/0` 会同时过滤具体的 RIO，所以示例没有使用它。
- networkd 重启时会清除动态配置，直到重新收到 RA 或 DHCP 回复。

### 常量对应

以下值在 nftables 和 networkd 中必须一致：

| 用途 | nftables 定义 | networkd 中的值 |
| --- | --- | --- |
| 路由字段 | `routing_mask` | `0xfff` |
| 探测 | `routing_probe` | `0x7ff/0xfff` |
| 交给 divert | `routing_divert` | `0x080/0xfff` |
| 探测接口 | `routing_probe_interface` | `rtprobe` |
| IPv4 探测下一跳 | `routing_probe_nexthop4` | `192.0.2.254` |
| IPv6 探测下一跳 | `routing_probe_nexthop6` | `2001:db8:ffff::fe` |

探测下一跳只用于识别探测回退，不能与实际网络中的地址重叠。

### 监听程序

- 在 `tproxy_port`（默认 3346）上监听，并设置 `IP_TRANSPARENT` 或 `IPV6_TRANSPARENT`。
- 绑定通配地址。交付地址是报文入接口的地址。本机发出的流量经 lo 到达，交付地址为环回地址。绑定具体地址时，只能收到从拥有该地址的接口进入的流量。
- TCP 连接的原目的端用 `getsockname()` 取得。UDP 报文的原目的端由 `IP_RECVORIGDSTADDR` 或 `IPV6_RECVORIGDSTADDR` 给出。
- UDP 回复用透明 socket 从原目的端发出。如果这个 socket 绑定了原目的端并连接了客户端，在它关闭之前，后续上行可能交给它，而不交给监听 socket。程序需要同时处理两个 socket 的接收队列。

### 加载与重载

检查通过后加载：

```sh
sudo nft -f /etc/nftables.conf
```

每个模块加载时重建自己的表。重载后，map 和集合恢复为配置文件中的内容，外部加载的数据需要重新填充。已有连接沿用 ct mark 中保存的选择，新连接按新的政策决策。

## 示例

可选政策以 `.sample` 放在对应的 drop-in 目录中，去掉后缀即启用：

| 文件 | 内容 |
| --- | --- |
| `fw.conf.d/10-zone.conf.sample` | zone 示例：接口 `lan0` 的入站放行 DNAT 目标和 SSH，其余拒绝，发出放行 |
| `routing.conf.d/10-classify.conf.sample` | 对 gateway 流量做两级映射：目的地址 → country → class |
| `routing.conf.d/50-policy.conf.sample` | 为发往 `198.51.100.0/24` 的 gateway 流量选择路由 `0x081` |
| `routing.conf.d/99-divert.conf.sample` | class 在 `divert_classes` 中的 original 方向 TCP/UDP 提交 `routing_divert` |
| `divert.conf.d/10-observe.conf.sample` | 统计选中的报文数 |

`routing_select` 中的执行顺序按文件名排列：先分类，再提交路由 ID，最后选出交给 divert 的流量。

### 分类与交给监听程序

`10-classify` 使用三张 map：

| map | 类型 | 内容 |
| --- | --- | --- |
| `geo4` | `ipv4_addr : classid` | IPv4 地址 → country |
| `geo6` | `ipv6_addr : classid` | IPv6 地址 → country |
| `geoclass` | `classid : classid` | country → class |

country 占 `0x800-0xfff`，class 占 `0x102-0x7fe`。映射在 `meta priority` 中进行，命中 class 后写入路由字段。三张 map 的内容可以用 [nftables-geoip](https://github.com/libiris-0/nftables-geoip) 生成。

`99-divert` 使用两个集合：

- `divert_classes`：要交给监听程序的 class，类型为 `mark`。
- `divert_cgroupsv2`：本机发出的流量中，只有这些第 1 层 cgroup 中的进程发出的流量才交给监听程序。示例为 `user.slice`，不包含 `system.slice` 中系统服务发出的流量。外部入站的流量不受这个集合限制。

## 编写 drop-in

drop-in 在对应模块的表中定义自己的链，再向公共链追加规则。挂载点和约束见 SPEC 第 5 章。

routing 的 drop-in 示例，为发往 `198.51.100.0/24` 的 gateway 流量选择 `0x081`：

```nft
table inet routing {
	chain routing_select_example {
		mark & $routing_mask != $routing_gateway return

		ct direction original meta l4proto { tcp, udp } ip daddr 198.51.100.0/24 ct mark set ct mark & $routing_original_clear_mask | 0x081
	}
}

add rule inet routing routing_select jump routing_select_example
```

提交选择时只改动当前方向的 ct mark 字段。original 方向用 `routing_original_clear_mask` 清除旧值。reply 方向用 `routing_reply_clear_mask` 清除旧值，写入的值左移 `routing_reply_shift`。

OUTPUT 中改变 mark 会触发重新选路，routing 提交选择时也是如此。重新选路后，同一 hook 中后续链看到的 `meta oif` 和 `oifname` 仍是初始路由的出接口，POSTROUTING 中的链看到的是实际出接口。例如，本机流量被选中交给 divert 后，fw 的 `output` 链看到的是初始路由的出接口。

## 测试

```sh
python3 -I tests/run.py
```

测试在非特权的 user/network namespace 中运行，不改动宿主网络。详见 [tests/README.md](tests/README.md)。

## 许可

[MIT](LICENSE)
