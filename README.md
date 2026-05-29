# 局域网 IP 扫描器 v3.0 / LAN Scanner

一键扫描局域网内所有在线设备、设备类型和**操作系统**。GUI 图形界面，零依赖。

## 快速开始

### 方式一：直接运行 EXE（推荐，无需安装 Python）

下载 `dist_v30/局域网扫描器V30.exe`，双击运行即可。

> 仅 11.8 MB，拷贝到任意 Windows 电脑上都能直接使用。

### 方式二：Python 源码运行

```bash
cd v30
python lan_scanner.py
```

> 依赖：Python 3.7+，仅使用标准库（tkinter），无需 pip 安装任何包。

## 功能特性

| 功能 | 说明 |
|------|------|
| 网络接口自动检测 | 自动列出本机所有网卡，一键选择 |
| 双模式探测 | ICMP Ping + TCP 多端口，穿透防火墙 |
| MAC 厂商识别 | 内置 200+ 厂商 OUI 库 |
| 设备类型分类 | 路由器 / 手机 / 电脑 / 打印机 / 摄像头 / 物联网... |
| **操作系统识别** | Windows / Linux / macOS / Android / 网络设备 |
| IP 占用图 | 左下角色块可视化，一眼看出哪些 IP 被占用 |
| 右键菜单 | 复制 IP、复制 MAC、Ping 设备、查看详情 |
| CSV 导出 | 扫描结果一键导出 |
| 实时刷新 | 扫描同时实时显示发现的设备 |

## 界面说明

![](C:\Users\鸿\Desktop\bb37709155ae8b71636342599d68cf15.png)



**IP 占用图图例：**

| 颜色 | 含义 |
|------|------|
| 🟢 绿色 | 已使用（设备在线） |
| ⚪ 灰色 | 未使用 |
| 🔵 蓝色 | 本机 |
| 🟠 橙色 | 网关 |

## 项目结构

```
├── dist_v30/              # 打包好的 EXE（可直接分发）
│   └── 局域网扫描器V30.exe
├── v30/                   # GUI 版源码
│   ├── lan_scanner.py     # 主程序（GUI + CLI 双模式）
│   ├── run.bat            # 一键启动脚本
│   └── start_gui.vbs      # 无窗口静默启动
├── v20/                   # CLI 命令行版
│   └── index.html
├── 扫描同网段ip.rar        # 打包工具
├── 扫描同网段其他设备.rar
└── 使用方法.txt
```

## 命令行模式

V30 也完全兼容 V20 的命令行用法：

```bash
# 列出所有网卡
python lan_scanner.py -l

# 扫描第 1 个网卡
python lan_scanner.py -i 1

# 扫描指定网段
python lan_scanner.py -n 192.168.1.0/24

# 自动导出 CSV
python lan_scanner.py -i 1 -e

# 查看完整帮助
python lan_scanner.py -h
```

## 自行打包

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name "局域网扫描器V30" v30/lan_scanner.py
```
