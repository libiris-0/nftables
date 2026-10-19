# 行为规范

本文定义 fw、routing 和 divert 三个模块的可观察行为，以及 drop-in 的挂载接口。常量见 `etc/nftables.conf.d/routing-defs.nft`。

## 0. 模块

| 模块 | 职责 |
| --- | --- |
| fw | 访问控制、NAT 和报文调整 |
| routing | 为连接的每个方向确定路由 ID |
| divert | 把路由 ID 为 `routing_divert` 的 TCP/UDP 交给本机的监听 socket |

- 路由 ID 不构成通信许可。
- 每个模块独占一张 `inet` 表，加载时重建。
- 模块的执行顺序由 hook 优先级确定，与 include 次序无关。

| 优先级 | PREROUTING | OUTPUT |
| --- | --- | --- |
| `mangle` | fw 报文调整 | fw 报文调整 |
| `dstnat` | fw DNAT | — |
| `dstnat + 25` 至 `dstnat + 47` | routing | routing |
| `dstnat + 50` 至 `dstnat + 60` | divert | — |
| `filter` | fw 过滤 | fw 过滤 |

INPUT、FORWARD 和 POSTROUTING 只有 fw。

## 1. 字段

### 1.1 mark 与 ct mark

| 字段 | 位置 | 内容 |
| --- | --- | --- |
| 路由字段 | `mark & routing_mask`，第 0 至 11 位 | 路由 ID 或 routing 内部的中间值 |
| original 字段 | `ct mark & routing_original_mask`，第 0 至 7 位 | original 方向的选择 |
| reply 字段 | `(ct mark & routing_reply_mask) >> routing_reply_shift`，第 8 至 15 位 | reply 方向的选择 |

routing 和 divert 保持报文和 CT 中的其余位不变。

### 1.2 路由 ID

| 值 | 名称 | 含义 |
| --- | --- | --- |
| `0x000` | `routing_unassigned` | 无选择 |
| `0x001` | `routing_normal` | 普通选择，由系统 RPDB 和路由表处理 |
| `0x002-0x07f` | — | 外部指定的选择 |
| `0x080-0x0ff` | — | drop-in 提交的选择 |
| `0x080` | `routing_divert` | 交给 divert |
| `0x100-0xfff` | `routing_pending` | routing 内部的中间值 |

- 选择的取值范围为 `0x001-0x0ff`。
- `0x001` 以外的选择须有对应的 RPDB 规则和路由表。
- pending 范围内，`routing_specific`（`0x100`）和 `routing_gateway`（`0x101`）是分类结果，见 3.4。
- `routing_probe`（`0x7ff`）是探测指令。drop-in 阶段可以把它当作普通的 pending 值使用。

### 1.3 priority 寄存器

对 routing 和每个 drop-in，`meta priority` 是易失性寄存器：入口值任意，出口值不作保证。

## 2. fw

### 2.1 入口链

| hook | 报文调整链 | 过滤链 | NAT 链 |
| --- | --- | --- | --- |
| PREROUTING | `mangle_prerouting` | `prerouting` | `dstnat` |
| INPUT | `mangle_input` | `input` | — |
| FORWARD | `mangle_forward` | `forward` | — |
| OUTPUT | `mangle_output` | `output` | — |
| POSTROUTING | `mangle_postrouting` | `postrouting` | `srcnat` |

- 同一 hook 中，报文调整链先于过滤链。
- `mangle_output` 是 route 类型的链。
- `input`、`forward` 和 `output` 分别执行本机接收、转发和本机发出的访问控制，见 2.2。
- 透明 socket 指设置了 `IP_TRANSPARENT` 或 `IPV6_TRANSPARENT` 选项的 socket。
- hook、链类型、NAT、连接状态和透明 socket 匹配采用 Linux nftables 的语义。

### 2.2 访问控制

INPUT、FORWARD 和 OUTPUT 的过滤结果由下表首个满足的条件决定：

| 条件 | 结果 |
| --- | --- |
| INPUT 入接口或 OUTPUT 出接口为 lo | 放行 |
| INVALID | 丢弃 |
| ESTABLISHED 或 RELATED | 放行 |
| INPUT 匹配透明 socket | 放行 |
| drop-in 作出判定 | drop-in 的判定：放行、丢弃或 `handle_reject` |
| 其余 | 丢弃 |

- 透明 socket 构成本机接收授权。
- DNAT 到本机的接收授权由 drop-in 提供。
- DNAT 不构成转发许可。

### 2.3 拒绝处理

`handle_reject` 的响应：

| 协议 | 响应 |
| --- | --- |
| TCP | reset |
| 其余 | 对应地址族的 ICMP port-unreachable |

## 3. routing

本章的输入和输出均指路由字段。mark 的其余位不影响 routing 的行为，并保持不变。

### 3.1 适用范围

| 条件 | 行为 |
| --- | --- |
| **入口路由字段在 `0x080-0xfff` 内** | **未定义，优先于以下各行** |
| 无有效的 conntrack 上下文 | 等同于 routing 不存在 |
| 目的地址类型不是 `local` 或 `unicast` | 等同于 routing 不存在 |
| RELATED | 实现定义 |
| 其余 | 见 3.2 至 3.4 |

### 3.2 观测

- 可观测量为报文的路由字段。`ct mark` 是隐藏状态，选择是否被记住由后续报文的输出验证。
- 连接的 original 和 reply 方向各有一个选择，初始为空。

### 3.3 输入与输出

记号：`E` 为非零的入口值，`S` 为当前方向已有的选择，`D` 为决策结果，见 3.4。

| 入口值 | 当前方向的选择 | 输出 | 之后的选择 |
| --- | --- | --- | --- |
| `E` | 任意 | `E` | `E` |
| `0x000` | `S` | `S` | `S` |
| `0x000` | 空 | `D` | `D` |

不变量：

- 选择随连接状态存续，只在显式入口或 drop-in 提交时改变。路由表和 RPDB 的变化不改变选择。
- 连接状态失效后，同端点的新连接从空选择开始。
- 选择只确定路由 ID，出接口和下一跳由系统路由决定。

### 3.4 决策

当前方向的目的端分为两类，探测回退规则见第 6 章：

| 分类 | 条件 |
| --- | --- |
| specific | local 表、main 表，或优先级排在探测回退规则之前的 RPDB 规则为目的端选出了路由 |
| gateway | 以上都没有为目的端选出路由 |

无可用路由时，分类不作保证。

决策结果 `D` 为 drop-in 对当前方向提交的值，范围为 `0x080-0x0ff`。无提交时，`D` 为 `routing_normal`。

## 4. divert

### 4.1 适用范围

| 条件 | 行为 |
| --- | --- |
| 协议为 TCP 或 UDP，且路由字段等于 `routing_divert` | 见 4.2 |
| 其余 | 等同于 divert 不存在 |

### 4.2 交付

记号：

- 监听 socket：端口 `tproxy_port` 上绑定通配地址的透明 socket，包括它接受的 TCP 连接。
- 其他透明 socket：监听 socket 以外、与报文原始端点匹配的透明 socket，例如绑定原目的端并连接客户端的 UDP socket。

| 监听 socket | 其他透明 socket | 结果 |
| --- | --- | --- |
| 存在 | 不存在 | 交给监听 socket |
| 任意 | 存在 | 交给监听 socket 或其他透明 socket 之一，由实现定义 |
| 不存在 | 不存在 | 丢弃 |

- TCP 连接可以建立，并持续双向传输。
- UDP 的首包、连续报文、间隔后的报文和非 NEW 报文均交付。
- 交付保留原始端点、载荷和报文 `mark`。

本节所说的交付，指报文选中了接收 socket。

## 5. Drop-in 接口

### 5.1 加载

- 每个模块加载同名 drop-in 目录 `<模块>.conf.d/` 下的 `*.conf`。
- 同一条链中，追加规则的顺序与文件名顺序一致。
- 不同 hook 链之间的顺序由优先级确定。

### 5.2 fw

- drop-in 向 2.1 中的链追加规则，输入为挂载位置的报文和连接状态。规则所见的端点和执行顺序由挂载位置确定。
- 访问控制的动作为放行、丢弃或调用 `handle_reject`。

### 5.3 routing

| 挂载点 | 位置 |
| --- | --- |
| `routing_select` | routing 调用的公共链 |
| 独立 hook 链 | PREROUTING 或 OUTPUT，优先级 `dstnat + 28` 至 `dstnat + 46` |

输入前提：路由字段在 `0x100-0xfff` 内。routing 只在前提成立时调用 `routing_select`，独立 hook 链则会遇到前提不成立的报文。

| 字段 | 合法变化 |
| --- | --- |
| 路由字段 | 结束时在 `0x100-0xfff` 内 |
| original 字段 | 保持原值，或写入 `0x080-0x0ff` |
| reply 字段 | 保持原值，或写入 `0x080-0x0ff` |

- 报文和 CT 中的非路由位保持不变。
- 路由字段可以在 drop-in 之间传递中间值。
- 提交可以写入任一方向，包括已有显式选择的方向。后执行的提交覆盖先执行的提交。
- 前提不成立时调用 drop-in，或输出违反约束时，routing 的行为未定义。

### 5.4 divert

| 挂载点 | 位置 |
| --- | --- |
| `divert_deliver` | divert 的公共链 |
| 独立 hook 链 | PREROUTING，优先级 `dstnat + 51` 至 `dstnat + 59` |

- 追加到 `divert_deliver` 的规则只对路由字段等于 `routing_divert` 的报文执行。
- drop-in 不改变路由字段。
- 4.2 中丢弃的报文不因 drop-in 的判定而交付。

## 6. 部署前提

3.4 的分类和第 4 章的交付以下列 RPDB 条件成立为前提：

- 存在探测回退规则。它匹配 `routing_probe`，所查询的表为任意目的端提供经 `routing_probe_interface` 到 `routing_probe_nexthop4` 或 `routing_probe_nexthop6` 的路由。
- 路由字段为 `routing_probe` 时，local 表和 main 表排在探测回退规则之前查询。
- 路由字段为 `routing_divert` 时，RPDB 选出进入本机的路由。
- `routing_probe_interface`、`routing_probe_nexthop4` 和 `routing_probe_nexthop6` 不用于其他路由。

条件不成立时，分类和交付不作保证。
