# eBPF WireGuard 策略路由与分流分发器

基于 eBPF（`cgroup/connect` + `cgroup/sendmsg`）与 Linux 策略路由（`ip rule`）的高性能分流方案。

旨在彻底解决传统 `nftables` / `iptables` 在路由后打 Mark 导致本地 Socket 无法选用 WireGuard 接口源 IP（被迫使用 Masquerade / SNAT）的问题。

---

## 核心特性

- **原生免 Masquerade**：在应用层 `connect()` 触发内核路由查表**之前**设置 Socket Mark，使内核首次寻址时直接从 `wg0` 接口挑选 IPv6 / IPv4 本地源地址绑定，彻底免去 SNAT。
- **纯 C 原生实现**：零 Python 依赖，单二进制文件直接运行，极速启动与热更新。
- **兼容 nftables 规则语法**：原生解析 `var.nft` 格式规则文件，支持 `define FWMARK`、`define IPV4_ELEMENTS`、`define IPV6_ELEMENTS`。
- **原生支持 IP Range 范围分解**：C 语言位运算内置 Range 分解算法，自动将 `1.0.1.0-1.0.3.255` 等范围转换为最精简的不重叠 CIDR 并写入内核 `LPM_TRIE`。
- **动态防路由死锁（Anti-Loopback）**：针对 WireGuard 服务端 Endpoint（IP:Port）进行精准识别并强制直连放行，支持命令行热修改。
- **零停机热更新**：支持实时更新规则或 Endpoint，秒级热写入内核 Map，无需重新挂载或重启 eBPF 程序。

---

## 目录结构

```text
├── bpf/
│   └── local_router.bpf.c    # eBPF 内核态源码 (cgroup/connect{4,6}, sendmsg{4,6})
├── src/
│   └── router_ctl.c          # 纯 C 用户态控制器源码 (解析 nft、操作 BPF Map)
├── build/                    # 编译产物输出目录 (由 Makefile 统一生成)
│   ├── vmlinux.h             # 由 bpftool 自动生成的内核 BTF 头文件
│   ├── local_router.bpf.o    # BPF 目标文件
│   ├── local_router.skel.h   # bpftool 自动生成的 BPF Skeleton 头文件
│   └── router_ctl            # 最终生成的控制器二进制文件
├── Makefile                  # 构建脚本
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
# IPv4 策略路由
sudo ip rule add fwmark 0x3000 table 100
sudo ip route add default dev wg0 table 100

# IPv6 策略路由
sudo ip -6 rule add fwmark 0x3000 table 100
sudo ip -6 route add default dev wg0 table 100
```

### 2. 编译项目

```bash
make
```

### 3. 启动并加载规则

```bash
sudo ./router-ctl.sh start \
    --cgroup-path /sys/fs/cgroup \
    --wg-endpoint 198.51.100.1:51820 \
    --rule-file var.nft
```

参数说明：
- `--cgroup-path <path>`：cgroup v2 挂载路径（默认 `/sys/fs/cgroup`）。
- `--wg-endpoint <IP:Port>`：WireGuard 远端服务端地址与端口（防死锁回环，必填或在 nft 文件中定义）。
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
  Enabled: true, FWMARK: 0x3000 (12288)
  WireGuard Endpoint: 198.51.100.1:51820
  Bypass IPv4 CIDRs in kernel map: 18
  Bypass IPv6 CIDRs in kernel map: 11
```

### 5. 动态热重载规则

当修改了 `var.nft` 文件后，直接执行热重载（无需重启 eBPF）：

```bash
sudo ./router-ctl.sh reload --rule-file var.nft
```

如果仅需动态切换 WireGuard Endpoint（如 DDNS 变更）：

```bash
sudo ./router-ctl.sh set-endpoint 203.0.113.88:51820
```

### 6. 停止并清理

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
- 数据包不会被打上 Mark，依然走系统主路由表（从物理网卡发出）。

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
