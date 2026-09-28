# eBPF WireGuard 策略路由与分流分发器

基于 eBPF（`cgroup/connect` + `cgroup/sendmsg`）与 Linux 策略路由（`ip rule`）的高性能分流方案。

旨在彻底解决传统 `nftables` / `iptables` 在路由后打 Mark 导致本地 Socket 无法选用 WireGuard 接口源 IP（被迫使用 Masquerade / SNAT）的问题。

---

## 核心特性

- **原生免 Masquerade**：在应用层 `connect()` 触发内核路由查表**之前**设置 Socket Mark，使内核首次寻址时直接从 `wg0` 接口挑选 IPv6 / IPv4 本地源地址绑定，彻底免去 SNAT。
- **UDP / QUIC 首包精准绑定（可选 `--oif`）**：在无连接 UDP（`sendmsg`/`sendto`）场景下，支持自动识别并注入出接口（如 `wg0`）的源 IP，解决 Linux 内核 UDP 首包路由时序问题，彻底告别 UDP/QUIC 首包源 IP 选错或泄漏。
- **双栈安全与 IPv4 映射支持**：内核 eBPF 原生识别 Dual-Stack Socket 的 IPv4-mapped IPv6 地址（`::ffff:0:0/96`），自动解包对齐 IPv4 白名单规则，并在发包时精准注入 IPv4 映射源 IP，彻底杜绝双栈应用程序访问本地或局域网服务时的连接异常与地址污染。
- **纯 C 原生实现**：零 Python 依赖，单二进制文件直接运行，极速启动与热更新。
- **兼容 nftables 规则语法**：原生解析 `var.nft` 格式规则文件，支持 `define FWMARK`、`define IPV4_ELEMENTS`、`define IPV6_ELEMENTS`，支持任意行长度与宽松格式（如带空格的 IP 范围），严格防御 CIDR 尾部脏字符。
- **原生支持 IP Range 范围分解与 CIDR 规范化**：C 语言位运算内置 Range 分解算法，自动将 `1.0.1.0-1.0.3.255` 等范围转换为最精简的不重叠 CIDR，并自动规范主机位掩码与内存去重后写入内核 `LPM_TRIE`。
- **动态防路由死锁（Anti-Loopback）**：针对 WireGuard 服务端 Endpoint（IP:Port）进行精准识别并强制直连放行，支持命令行热修改与一键禁用（`del-endpoint` 或 `set-endpoint none`）。
- **双模全覆盖（本机 + 局域网透明网关）**：
  - **本机流量**：基于 `cgroup/connect` + `sendmsg` 提前绑定 `wg0` 源 IP，彻底免去本地 Masquerade。
  - **转发流量**：支持挂载 eBPF **TC Ingress** 钩子至局域网网卡（支持多网卡绑定与 `add-if`/`del-if` 热插拔），原生兼容标准（0x8100, 0x88A8）与多厂商 QinQ 双层 VLAN 封装（0x9100, 0x9200, 0x9300）及非 VLAN 极速短路优化，在内核路由查表前提前打标，使局域网转发流量同样享用底层的统一 LPM 白名单。
- **零停机无感原子热更新**：支持实时更新规则或 Endpoint，先就地增量写入内核 Map 并通过单遍扫描安全剪枝过期条目，彻底消除迭代器失效与二次遍历性能损耗，绝不出现白名单清空窗口期，保障网络会话零中断。

---

## 目录结构

```text
├── bpf/
│   └── local_router.bpf.c    # eBPF 内核态源码 (cgroup/connect{4,6}, sendmsg{4,6}, tc_router_ingress)
├── include/
│   └── router_common.h       # 内核态与用户态共享类型与常量头文件
├── src/
│   └── router_ctl.c          # 纯 C 用户态控制器源码 (解析 nft、操作 BPF Map、管理 cgroup/TC)
├── tests/
│   └── test_router_ctl.c     # 完整单元测试套件
├── build/                    # 编译产物输出目录 (由 Makefile 统一生成)
│   ├── vmlinux.h             # 由 bpftool 自动生成的内核 BTF 头文件
│   ├── local_router.bpf.o    # BPF 目标文件
│   ├── local_router.skel.h   # bpftool 自动生成的 BPF Skeleton 头文件
│   └── router_ctl            # 最终生成的控制器二进制文件
├── Makefile                  # 构建与测试脚本
├── router-ctl.sh             # Shell 启动与管理脚本
└── var.nft                   # nftables 格式分流规则文件
```

---

## 环境要求

- **Linux 内核**：>= 5.8（推荐 6.x 或更新，支持 `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` 下的 `bpf_setsockopt`）
- **Cgroup**：启用了 cgroup v2 并挂载在 `/sys/fs/cgroup`
- **BPF 文件系统**：挂载在 `/sys/fs/bpf`
- **依赖软件包**：
  - `clang`, `llvm`, `gcc`, `make`
  - `bpftool`
  - `libbpf`, `libelf`, `zlib`

---

## 快速使用

### 1. 配置 Linux 策略路由（ip rule）

根据你的 `var.nft` 中的 `FWMARK`（例如 `0x3000` / `12288`），配置路由表（如 table 100）：

```bash
# IPv4 策略路由 (fwmark + 可选源 IP 双保险)
sudo ip rule add fwmark 0x3000 table 100
sudo ip rule add from <WG_IPV4>/32 table 100      # 配合 --oif 注入，保障 UDP 首包即刻生效
sudo ip route add default dev wg0 table 100

# IPv6 策略路由 (fwmark + 可选源 IP 双保险)
sudo ip -6 rule add fwmark 0x3000 table 100
sudo ip -6 rule add from <WG_IPV6>/128 table 100  # 配合 --oif 注入，保障 UDP 首包即刻生效
sudo ip -6 route add default dev wg0 table 100
```

### 2. 编译项目

```bash
make
```

### 3. 启动并加载规则

#### 仅本机分流（默认模式）：
```bash
sudo ./router-ctl.sh start \
    --cgroup-path /sys/fs/cgroup \
    --wg-endpoint 198.51.100.1:51820 \
    --oif wg0 \
    --rule-file var.nft
```

#### 本机 + 局域网透明网关分流（支持多网卡 TC Ingress）：
```bash
sudo ./router-ctl.sh start \
    --cgroup-path /sys/fs/cgroup \
    --wg-endpoint 198.51.100.1:51820 \
    --rule-file var.nft \
    --oif wg0 \
    --lan-if eth1,eth2    # 支持逗号分隔或多次使用 --lan-if
```

> [!TIP]
> 当作为局域网网关转发时，请确保开启了内核转发：
> `sudo sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1`
> 并在 nftables 中仅为转发流量添加一条 Masquerade（本机流量依然零 SNAT）：
> `nft add rule inet nat postrouting oifname "wg*" masquerade`

参数说明：
- `--cgroup-path <path>`：cgroup v2 挂载路径（默认 `/sys/fs/cgroup`）。
- `--pin-dir <path>`：（可选）BPF 对象持久化 Pin 目录（默认 `/sys/fs/bpf/wg_routing`）。
- `--oif <iface>`：（可选）分流目标出接口（Outbound Interface，如 `wg0`），自动提取其源 IP 注入本地 UDP 发包；不指定则为纯 FWMARK 模式。
- `--lan-if <iface>`：（可选）绑定局域网网卡启用 TC Ingress 分流，支持重复或逗号分隔（如 `eth1,eth2` 或 `eth1`）。
- `--wg-endpoint <IP[:Port]>`：WireGuard 服务端地址（防死锁回环）。
  - 支持带端口：如 `198.51.100.1:51820` 或 `[2001:db8::1]:51820`（仅匹配指定端口）。
  - **支持不带端口**：如 `198.51.100.1` 或 `2001:db8::1`（匹配该 IP 的所有端口全部放行直连）。
- `--rule-file <path>`：nftables 规则文件（如 `var.nft`）。
- `--fwmark <mark>`：（可选）覆盖规则文件中的 FWMARK（如 `0x3000`）。

### 4. 查看运行状态

```bash
sudo ./router-ctl.sh status
```

输出示例：
```text
[+] eBPF Router Status:
  Pinned Directory: /sys/fs/bpf/wg_routing
  LAN Interfaces (TC Ingress Forwarding):
    - eth1        : [ACTIVE] (ifindex 2, TC ingress filter active)
    - eth2        : [ACTIVE] (ifindex 3, TC ingress filter active)
  Enabled: true, FWMARK: 0x3000 (12288)
  UDP Injected Egress IPs (oif): IPv4=10.0.0.2, IPv6=fd00::2
  WireGuard Endpoint: 198.51.100.1:51820
  Bypass IPv4 CIDRs in kernel map: 18
  Bypass IPv6 CIDRs in kernel map: 11
```

### 5. 动态热重载规则（无感原子更新）

当修改了 `var.nft` 文件后，直接执行热重载（无需重启 eBPF，原子增量写入，绝不出现白名单清空窗口期）：

```bash
sudo ./router-ctl.sh reload --rule-file var.nft
```

如果仅需动态切换或移除 WireGuard Endpoint（如 DDNS 变更或临时关闭直连放行）：

```bash
# 动态更新 Endpoint（支持带端口或不带端口）
sudo ./router-ctl.sh set-endpoint 203.0.113.88:51820

# 动态移除/禁用 Endpoint 放行规则（支持两种等效写法）
sudo ./router-ctl.sh del-endpoint
sudo ./router-ctl.sh set-endpoint none
```

### 6. 动态管理分流出接口（oif）

运行时无需重启或重新加载规则文件，可秒级热指定、切换或移除分流出接口：

```bash
# 动态设置/切换出接口（自动读取并注入其 IPv4/IPv6）
sudo ./router-ctl.sh set-oif wg0
# 动态移除出接口（清空源 IP 注入，安全回退到纯 fwmark 模式）
sudo ./router-ctl.sh del-oif
```

### 7. 动态管理局域网转发网卡（add-if / del-if）

无需重启路由器，支持热插拔网卡或动态将局域网接口纳入/移出 TC Ingress 分流：

```bash
# 动态添加一个或多个局域网网卡（支持逗号分隔）
sudo ./router-ctl.sh add-if eth3
sudo ./router-ctl.sh add-if eth4,eth5

# 动态移出网卡并卸载 TC Ingress 过滤器
sudo ./router-ctl.sh del-if eth3
```

### 8. 停止并清理

```bash
sudo ./router-ctl.sh stop
```

---

## 验证与测试

### 1. 验证本地 IPv6 源地址是否正确选为 `wg0`（免 Masquerade）

在终端 1 启动抓包：
```bash
sudo tcpdump -i wg0 -nn -p -v
```

在终端 2 发起网络请求：
```bash
curl -6 https://api64.ipify.org
```

**观察要点**：
- 抓包显示的源 IP（Source IP）应当直接为 `wg0` 接口配置的 IPv6 地址，**绝不是** `wlan0` 的物理网卡地址。
- 此时 WireGuard 网卡不需要配置任何 `masquerade` / SNAT 规则即可正常建立连接并双向收发包。

### 2. 验证直连白名单（Bypass）

尝试访问 `var.nft` 中定义的 IP 或网段（如 `127.0.0.0/8`, `192.168.0.0/16` 或范围 `1.0.1.0-1.0.3.255` 内的 IP）：
- 数据包不会被打上 Mark 及源地址不是 `wg0` 的 ip 地址，依然走系统主路由表（从物理网卡发出）。

---

## 规则文件格式说明（`var.nft`）

直接使用标准 nftables 格式即可：

```nft
#!/usr/bin/nft -f

# 定义分流 FWMARK
define FWMARK = 0x00003000

# 也可以在文件中直接定义 Endpoint (可选)
# define WG_ENDPOINT = "198.51.100.1:51820"

# IPv4 直连白名单（支持 CIDR 以及 IP Range 范围）
define IPV4_ELEMENTS = {
    8.128.0.0/11,
    10.0.0.0/8,
    192.168.0.0/16,
    1.0.1.0-1.0.3.255,                 # 自动分解为 CIDR
    223.255.236.0-223.255.239.255,     # 自动分解为 CIDR
}

# IPv6 直连白名单（支持 CIDR）
define IPV6_ELEMENTS = {
    ::/8,
    fc00::/7,
    fe80::/10,
    2001:db8::/32,
}
```
