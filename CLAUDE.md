# nftables

模块化的 nftables 网关配置，分为三个模块：

- fw：访问控制、NAT 和报文调整。
- routing：为连接的每个方向确定路由 ID，交给 RPDB 选择路由表。
- divert：把选中的 TCP/UDP 交给本机的监听程序。

## 规则

- **SPEC.md 是行为的唯一依据。** 修改可观察行为时，先改 SPEC，再改配置和测试。SPEC 用声明式写法，只写定义、规则和不变量，不写实现过程和原因。
- **网络操作只在测试创建的临时 user/network namespace 中进行。** 不修改宿主的规则、RPDB、路由和 sysctl，不重启服务。
- **本机报文因 routing 的输出经 lo 回注时，实现须保持原选择。** SPEC 未定义这类入口，这是实现的要求，不写进 SPEC。
- **上游已保证的条件不重复检查。** 未定义的输入不加防御规则。提前放行或丢弃须有语义上的理由，不能只以快路径解释。
- 本仓库只含框架和 `.sample` 示例，生产 drop-in 由其他仓库管理。
- nft 表达式只加必要的括号，mark 常量用十六进制。
- 文档用中文，配置和代码中的注释及标识符用英文。中文排版遵循[《中文文案排版指北》](https://github.com/sparanoid/chinese-copywriting-guidelines)。

## 测试

测试的组织和覆盖方式见 `tests/README.md`。`parameters.json` 不做校验。

## 命令

```sh
unshare -rn nft -I etc -c -f etc/nftables.conf
python3 -I tests/run.py
python3 -I tests/run.py routing divert
```
