# 测试

```sh
python3 -I tests/run.py
python3 -I tests/run.py routing divert
python3 -I tests/run.py --output /path/to/new/directory
```

不指定套件时运行全部四套。各套件并行运行。每个套件在自己的 user/network namespace 中配置网络和收发报文，宿主的规则、路由和 sysctl 保持不变。

## 依赖

- Linux，允许非特权 user namespace，cgroup v2。
- Python 3.14，只用标准库。
- `nft` 和 `ip`。

`kernel.apparmor_restrict_unprivileged_userns` 为 1 时，AppArmor 会限制非特权 user namespace，例如 Ubuntu 24.04 的默认配置。这时需要先执行：

```sh
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

完整流程见 [.github/workflows/test.yml](../.github/workflows/test.yml)。

## 套件

| 套件 | 加载 | 内容 |
| --- | --- | --- |
| `fw` | fw 核心，以及测试政策或 `10-zone` 示例 | SPEC 2、5.1 和 5.2 |
| `routing` | routing 核心，以及测试政策或 routing 示例 | SPEC 1、3、5.1 和 5.3 |
| `divert` | divert 核心，以及测试政策或 `10-observe` 示例 | SPEC 4、5.1 和 5.4 |
| `integration` | 完整的入口文件、`fixtures/fw/` 中的 zone 政策，以及 routing 的 `10-classify` 和 `99-divert` 示例 | 模块组合后的端到端场景 |

前三套是单元测试，`integration` 是组合测试。

## 覆盖

每套测试都有一份行为清单，清单项按 SPEC 章节编号，分为三组：核心行为、挂载接口和示例政策。`integration` 的清单项是组合场景。

- 每项行为同时验证生效条件，以及旁路或拒绝条件。
- 一项行为关联的用例全部通过，才计为覆盖。
- SPEC 中未定义和实现定义的行为不作断言，单独列在结果的 `not_asserted` 中。
- 示例政策的预期取自示例文件开头的注释。

## 结果

结果默认写入新建的临时目录，也可以用 `--output` 指定一个新目录。每个套件写一个 `<套件>.json`：

| 字段 | 内容 |
| --- | --- |
| `counts` | `pass`、`fail` 和 `error` 的用例数 |
| `coverage` | 每组行为的覆盖数和各项关联的用例 |
| `not_asserted` | 不作断言的行为 |
| `parameters` | 本次使用的参数和采样值 |
| `cases` | 每个用例的状态和失败信息 |

`fail` 表示观测结果与预期不符，`error` 表示测试环境或工具出错。有 `fail` 或 `error` 时，运行器以非零状态退出。

## 参数

`parameters.json` 按套件保存随机种子、每段采样数和等待时间。采样在每段取两个端点，再无重复地随机取若干内部值，结果中记录本次的采样值。

## 观测方式

- 被测主机和各对端位于不同的 network namespace，用 veth 连接。邻居表项是静态的，所以邻居发现不受被测政策影响。
- 测试单独建一张 `witness` 表，在被测模块前后挂观测链，优先级按 SPEC 的相对值写，例如 `dstnat + 24` 和 `dstnat + 48`。
- routing 的 UDP 和 ICMP 测试报文在载荷中携带要注入的 mark、ct mark 和 priority，以及序号。观测链按序号记录各阶段的值，一个用例结束后统一读取。
- 测试政策和示例通过临时目录中的 drop-in 加载，加载时用 `-I` 指定这个目录。仓库 `etc/` 中已启用的 drop-in 不会被加载。
