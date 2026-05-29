#!/usr/bin/env python3
"""局域网 IP 扫描器 v2.0 —— 扫描并列出同一网段内的所有在线设备。"""

import argparse
import ipaddress
import os
import platform
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

IS_WINDOWS = platform.system().lower() == "windows"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

if IS_WINDOWS:
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass

# ── 数据模型 ──────────────────────────────────────────

@dataclass
class Device:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    dev_type: str = ""

    @property
    def vendor_display(self) -> str:
        v = self.vendor
        t = self.dev_type
        return f"{v} / {t}" if t else v or "-"

    def __str__(self):
        parts = [f"  {self.ip:<16}"]
        if self.mac:
            parts.append(f"  {self.mac:<18}")
        if self.hostname:
            parts.append(f"  {self.hostname}")
        return "".join(parts)

# ── 网络工具 ──────────────────────────────────────────

def _get_windows_cp() -> int:
    """获取 Windows 系统 ANSI 代码页 (中文=936, 英文=1252)。

    使用 GetACP() 而非 GetConsoleOutputCP(), 因为 ipconfig/route/arp/nbtstat
    等命令输出使用系统 ANSI 编码, 不受 chcp 影响。
    """
    import ctypes
    try:
        return ctypes.windll.kernel32.GetACP()
    except Exception:
        return 936


def _parse_ipconfig_windows():
    """解析 Windows ipconfig 输出 (语言/编码无关), 返回 (iface_name, ip, network_str) 列表。"""
    import re
    networks = []

    oem_cp = _get_windows_cp()

    try:
        output = subprocess.check_output(
            ["ipconfig"],
            timeout=5,
            creationflags=CREATE_NO_WINDOW,
        ).decode(f"cp{oem_cp}", errors="ignore")
    except Exception:
        return networks

    current_iface = ""
    current_ip = ""
    current_mask = ""
    saw_ipv4 = False

    for line in output.splitlines():
        # 适配器行: 无缩进且以 ':' 结尾 (所有语言版本的 ipconfig 都遵循此格式)
        if not line.startswith((' ', '\t')) and line.rstrip().endswith(':'):
            if current_ip and current_mask:
                try:
                    net = ipaddress.IPv4Network(f"{current_ip}/{current_mask}", strict=False)
                    networks.append((current_iface, current_ip, str(net)))
                except Exception:
                    pass
            current_iface = line.rstrip().rstrip(':').strip()
            current_ip = ""
            current_mask = ""
            saw_ipv4 = False
            continue

        if "IPv4" in line:
            if ":" in line:
                current_ip = line.split(":")[-1].strip()
            saw_ipv4 = True

        elif saw_ipv4 and ":" in line:
            value = line.split(":")[-1].strip()
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
                octets = value.split('.')
                if octets[0] in ('255', '0', '128', '192', '224', '240', '248', '252', '254'):
                    current_mask = value
                    saw_ipv4 = False

    # 最后一个适配器
    if current_ip and current_mask:
        try:
            net = ipaddress.IPv4Network(f"{current_ip}/{current_mask}", strict=False)
            networks.append((current_iface, current_ip, str(net)))
        except Exception:
            pass

    return networks


def _parse_ip_linux():
    """解析 Linux ip addr 输出。"""
    import re
    networks = []
    try:
        output = subprocess.check_output(["ip", "-4", "addr"], timeout=5).decode("utf-8", errors="ignore")
    except Exception:
        try:
            output = subprocess.check_output(["ifconfig"], timeout=5).decode("utf-8", errors="ignore")
        except Exception:
            return networks

    current_iface = ""
    for line in output.splitlines():
        # 接口行: "2: eth0: <...>"
        m = re.match(r'^\d+:\s+(\S+):', line)
        if m:
            current_iface = m.group(1)
        # IP 行: "    inet 192.168.1.100/24 ..."
        if "inet " in line:
            parts = line.strip().split()
            for p in parts:
                if "/" in p and "." in p:
                    try:
                        net = ipaddress.IPv4Network(p, strict=False)
                        ip_str = p.split("/")[0]
                        networks.append((current_iface, ip_str, str(net)))
                    except Exception:
                        pass
    return networks


MAX_SCAN_HOSTS = 1024  # /22 及更大的网段跳过


def get_local_networks():
    """获取本机所有 IPv4 局域网段 (跳过 VPN /8 /16 等超大网段和回环地址)。"""
    networks = []

    # 方法1: netifaces 库
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            for addr in addrs.get(netifaces.AF_INET, []):
                ip = addr["addr"]
                mask = addr["netmask"]
                if not ip.startswith("127."):
                    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                    if net.num_addresses <= MAX_SCAN_HOSTS:
                        networks.append((iface, ip, str(net)))
        if networks:
            return networks
    except ImportError:
        pass

    # 方法2: ipconfig / ip 命令
    if IS_WINDOWS:
        raw = _parse_ipconfig_windows()
    else:
        raw = _parse_ip_linux()

    # 过滤: 去回环、只保留可扫描规模
    for iface, ip, net_str in raw:
        if ip.startswith("127."):
            continue
        try:
            net = ipaddress.IPv4Network(net_str, strict=False)
            if net.num_addresses <= MAX_SCAN_HOSTS:
                networks.append((iface, ip, net_str))
        except Exception:
            pass

    if networks:
        return networks

    # 方法3: 兜底, 仅 /24
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    if not ip.startswith("127."):
        try:
            net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            networks.append(("(auto)", ip, str(net)))
        except Exception:
            pass

    return networks


def ping_host(ip: str, timeout: float = 0.5) -> bool:
    """Ping 单个 IP, 返回是否在线。"""
    param = "-n" if IS_WINDOWS else "-c"
    timeout_param = "-w" if IS_WINDOWS else "-W"
    timeout_val = str(int(timeout * 1000)) if IS_WINDOWS else str(max(1, int(timeout)))

    try:
        result = subprocess.run(
            ["ping", param, "1", timeout_param, timeout_val, ip],
            capture_output=True,
            timeout=2,
            creationflags=CREATE_NO_WINDOW,
        )
        return result.returncode == 0
    except Exception:
        return False


_dns_lock = threading.Lock()


def get_hostname(ip: str, timeout: float = 0.3) -> str:
    """反向 DNS 查询主机名 (加锁避免全局 socket 超时竞态)。"""
    try:
        with _dns_lock:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(timeout)
            try:
                return socket.gethostbyaddr(ip)[0]
            finally:
                socket.setdefaulttimeout(old_timeout)
    except Exception:
        return ""


def get_netbios_name(ip: str, timeout: float = 1.0) -> str:
    """通过 NetBIOS (nbtstat) 获取 Windows 主机名。"""
    if not IS_WINDOWS:
        return ""
    try:
        result = subprocess.run(
            ["nbtstat", "-a", ip],
            capture_output=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        output = result.stdout.decode(f"cp{_get_windows_cp()}", errors="ignore")
        for line in output.splitlines():
            if "<00>" in line and "UNIQUE" in line:
                parts = line.strip().split()
                if parts:
                    name = parts[0].strip()
                    if name and name != "..__MSBROWSE__.":
                        return name
    except Exception:
        pass
    return ""


def get_local_mac(iface_name: str = "", local_ip: str = "") -> str:
    """获取本机指定网卡的 MAC 地址。支持按网卡名或 IP 地址匹配。"""
    import re
    if IS_WINDOWS:
        try:
            raw_bytes = subprocess.check_output(
                ["ipconfig", "/all"],
                timeout=5,
                creationflags=CREATE_NO_WINDOW,
            )
        except Exception:
            return ""
        output = ""
        for enc in ["gbk", "utf-8", "latin-1"]:
            try:
                output = raw_bytes.decode(enc)
                if "IPv4" in output:
                    break
            except Exception:
                continue
        if not output:
            return ""

        # 按空行分割适配器块
        blocks = re.split(r'\r?\n\r?\n', output)
        for block in blocks:
            # 检查此块是否包含目标 IP
            has_ip = local_ip and (local_ip in block)
            has_name = iface_name and iface_name != "(auto)" and iface_name.lower() in block.lower()
            if not (has_ip or has_name):
                continue

            # 从此块提取 MAC 地址
            for line in block.splitlines():
                if "物理地址" in line or "Physical Address" in line or "physical address" in line:
                    if ":" in line:
                        val = line.split(":", 1)[-1].strip().replace("-", ":").lower()
                        if len(val) == 17:
                            return val
    else:
        try:
            path = f"/sys/class/net/{iface_name}/address"
            with open(path) as f:
                return f.read().strip().lower()
        except Exception:
            pass
    return ""


def get_default_gateway() -> str:
    """获取默认网关 IP。"""
    if IS_WINDOWS:
        try:
            output = subprocess.check_output(
                ["route", "print", "0.0.0.0"],
                timeout=5,
                creationflags=CREATE_NO_WINDOW,
            ).decode(f"cp{_get_windows_cp()}", errors="ignore")
            for line in output.splitlines():
                if line.count("0.0.0.0") >= 2:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == "0.0.0.0" and i + 2 < len(parts):
                            gw = parts[i + 2]
                            if "." in gw and gw != "0.0.0.0":
                                return gw
        except Exception:
            pass
    else:
        try:
            output = subprocess.check_output(
                ["ip", "route", "show", "default"],
                timeout=5,
            ).decode("utf-8", errors="ignore")
            for line in output.splitlines():
                if "default via" in line:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == "via" and i + 1 < len(parts):
                            return parts[i + 1]
        except Exception:
            pass
    return ""


def get_arp_table() -> dict[str, str]:
    """从 ARP 缓存获取 IP → MAC 映射。"""
    arp = {}
    try:
        output = subprocess.check_output(
            ["arp", "-a"],
            timeout=5,
            creationflags=CREATE_NO_WINDOW,
        ).decode(f"cp{_get_windows_cp()}", errors="ignore")

        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0].strip()
                if "." in ip and not ip.startswith("Interface") and not ip.startswith("Internet"):
                    for p in parts[1:]:
                        p = p.strip().replace("-", ":")
                        if ":" in p and len(p) == 17:
                            arp[ip] = p.lower()
                            break
    except Exception:
        pass
    return arp


# ── 设备类型分类 ──────────────────────────────────────

# 根据厂商判断设备大致类型
_VENDOR_TYPE_MAP = {
    # 路由器/网络设备
    "TP-Link": "路由器",
    "Tenda": "路由器",
    "ASUS": "路由器",
    "ASUSTek": "路由器",
    "Netgear": "路由器",
    "Linksys": "路由器",
    "D-Link": "路由器",
    "Ubiquiti": "网络设备",
    "Ubiquiti Networks": "网络设备",
    "MikroTik": "路由器",
    "pfSense": "防火墙/路由器",
    "Cisco": "网络设备",
    "Cisco Systems": "网络设备",
    "Cisco Meraki": "网络设备",
    "Juniper": "网络设备",
    "Arista": "交换机",
    "Brocade": "交换机",
    "HPE": "交换机/服务器",
    "Hewlett Packard Enterprise": "交换机/服务器",
    "Hewlett Packard": "电脑/打印机",
    "HP": "电脑/打印机",
    "Aruba": "无线AP",
    "Ruckus": "无线AP",
    "Extreme": "网络设备",
    "ZyXEL": "路由器",
    "Synology": "NAS",
    "QNAP": "NAS",
    "Western Digital": "NAS/硬盘",
    "Seagate": "NAS/硬盘",
    # 手机
    "Apple": "手机/电脑",
    "Xiaomi": "手机/物联网",
    "Xiaomi Communications": "手机",
    "Huawei": "手机/网络设备",
    "Huawei Device": "手机/平板",
    "Samsung": "手机/电视",
    "Samsung Electronics": "手机/电视",
    "OPPO": "手机",
    "OPPO Electronics": "手机",
    "vivo": "手机",
    "OnePlus": "手机",
    "OnePlus Technology": "手机",
    "realme": "手机",
    "Meizu": "手机",
    "ZTE": "手机/网络设备",
    "Lenovo": "电脑/手机",
    "Lenovo Mobile": "手机",
    "Motorola": "手机",
    "Motorola Mobility": "手机",
    "Google": "手机/物联网",
    "Sony": "手机/电视",
    "Sony Interactive Entertainment": "游戏机",
    "Sony Mobile": "手机",
    "HTC": "手机/VR",
    "LG Electronics": "手机/电视",
    "LG Innotek": "手机组件",
    "Nokia": "手机/网络设备",
    "HMD Global": "手机",
    "BlackBerry": "手机",
    "Micromax": "手机",
    "Lava": "手机",
    "Nothing": "手机",
    # 电脑
    "Dell": "电脑",
    "Dell Inc": "电脑",
    "HP Inc": "电脑",
    "Acer": "电脑",
    "ASRock": "电脑",
    "Gigabyte": "电脑",
    "MSI": "电脑",
    "Razer": "电脑/外设",
    "LENOVO": "电脑",
    "Toshiba": "电脑",
    "Fujitsu": "电脑",
    "Panasonic": "电脑/电视",
    "Hon Hai": "代工设备",
    "Foxconn": "代工设备",
    "Pegatron": "代工设备",
    "Compal": "电脑(代工)",
    "Wistron": "电脑(代工)",
    "Quanta": "电脑(代工)",
    "Inventec": "电脑(代工)",
    # 芯片/组件
    "Intel": "电脑/网卡",
    "Intel Corporate": "电脑/网卡",
    "Qualcomm": "手机/网卡",
    "Qualcomm Atheros": "网卡",
    "Broadcom": "网卡/芯片",
    "Realtek": "网卡",
    "Realtek Semiconductor": "网卡",
    "MediaTek": "手机/物联网",
    "MediaTek Inc": "手机/物联网",
    "Marvell": "网卡/芯片",
    "NVIDIA": "显卡/开发板",
    "AMD": "电脑",
    "Rockchip": "开发板/盒子",
    "Allwinner": "开发板/盒子",
    "Amlogic": "电视盒子",
    "Raspberry Pi": "开发板",
    "Raspberry Pi Foundation": "开发板",
    "Banana Pi": "开发板",
    "Orange Pi": "开发板",
    "ASIX": "网卡/USB网卡",
    "DisplayLink": "扩展坞",
    # 电视/影音
    "Roku": "电视盒子",
    "Amazon": "物联网/电视",
    "Amazon Technologies": "物联网",
    "Hisense": "电视",
    "Skyworth": "电视",
    "TCL": "电视",
    "SHARP": "电视",
    "Philips": "电视/照明",
    "Bose": "音响",
    "Sonos": "音响",
    "Harman": "音响",
    "JBL": "音响",
    "B&O": "音响",
    "Yamaha": "音响/乐器",
    "Denon": "音响",
    "Bowers & Wilkins": "音响",
    # 智能家居/IoT
    "Espressif": "物联网(ESP)",
    "Espressif Inc": "物联网(ESP)",
    "Tuya": "智能家居",
    "Aqara": "智能家居",
    "Lumi United": "智能家居(Aqara)",
    "Philips Lighting": "智能灯(Hue)",
    "Signify": "智能灯",
    "IKEA": "智能家居",
    "Belkin": "智能家居",
    "Ring": "智能门铃",
    "Arlo": "摄像头",
    "Wyze": "摄像头",
    "Dyson": "家电",
    "Roborock": "扫地机",
    "Ecovacs": "扫地机",
    "iRobot": "扫地机",
    "Nest": "智能家居",
    "Nest Labs": "智能家居",
    "Fitbit": "手环",
    "Garmin": "手环/导航",
    "Honeywell": "安防/温控",
    # 打印机
    "Brother": "打印机",
    "Canon": "打印机/相机",
    "Epson": "打印机",
    "Xerox": "打印机",
    "Ricoh": "打印机",
    "Lexmark": "打印机",
    "Zebra": "打印机(标签)",
    "Kyocera": "打印机",
    "Konica Minolta": "打印机",
    # 监控/安防
    "Hikvision": "摄像头/监控",
    "Dahua": "摄像头/监控",
    "Uniview": "摄像头/监控",
    "Axis": "摄像头",
    "Bosch": "安防/汽车",
    "FLIR": "热成像",
    # 游戏
    "Nintendo": "游戏机",
    "Microsoft": "电脑/游戏机",
    "Microsoft Corporation": "电脑/游戏机",
    # 汽车
    "Tesla": "汽车",
    "BYD": "汽车",
    "BMW": "汽车",
    # 虚拟化
    "VMware": "虚拟机",
    "VirtualBox": "虚拟机",
    "Parallels": "虚拟机",
    "QEMU": "虚拟机",
    "Hyper-V": "虚拟机",
    "Xen": "虚拟机",
}

# 简化的厂商名映射 (处理同一厂商的多个 OUI 名称)
_VENDOR_NAME_ALIAS = {
    "TP-Link": "TP-Link",
    "TP-LINK": "TP-Link",
    "TP-Link Technologies": "TP-Link",
    "Tp-link Technologies": "TP-Link",
}


def _normalize_vendor(raw: str) -> str:
    """统一厂商名, 合并同一厂商的不同写法。"""
    return _VENDOR_NAME_ALIAS.get(raw, raw)


def vendor_device_type(vendor: str) -> str:
    """根据厂商名推断设备类型。"""
    if not vendor:
        return ""
    # 精确匹配
    if vendor in _VENDOR_TYPE_MAP:
        return _VENDOR_TYPE_MAP[vendor]
    # 模糊匹配: 检查厂商名包含关键词
    vendor_lower = vendor.lower()
    if any(k in vendor_lower for k in ["router", "route", "网", "tenda", "d-link", "linksys", "asus", "mikrotik"]):
        return "路由器"
    if any(k in vendor_lower for k in ["switch", "交换机"]):
        return "交换机"
    if any(k in vendor_lower for k in ["camera", "cam", "摄像", "hikvision", "dahua", "uniview"]):
        return "摄像头/监控"
    if any(k in vendor_lower for k in ["printer", "print", "打印", "epson", "brother", "canon"]):
        return "打印机"
    if any(k in vendor_lower for k in ["phone", "mobile", "手机", "oppo", "vivo", "oneplus"]):
        return "手机"
    if any(k in vendor_lower for k in ["tv", "电视", "hisense", "skyworth", "tcl", "roku"]):
        return "电视"
    if any(k in vendor_lower for k in ["iot", "esp", "espressif", "tuya", "智能", "sensor"]):
        return "物联网"
    if any(k in vendor_lower for k in ["nas", "synology", "qnap", "storage"]):
        return "NAS/存储"
    return ""


def mac_to_vendor(mac: str) -> str:
    """根据 MAC 前 6 位 (OUI) 识别厂商，覆盖 200+ 常见品牌。"""
    oui = mac.replace(":", "").replace("-", "").upper()[:6]
    table = {
        # === Apple ===
        "F0B429": "Apple", "DC2B61": "Apple", "ACBC32": "Apple", "A4D1D2": "Apple",
        "001DD4": "Apple", "000A95": "Apple", "F0D1A9": "Apple", "20C9D0": "Apple",
        "A886DD": "Apple", "B03495": "Apple", "F0761C": "Apple", "60FEC5": "Apple",
        "38C986": "Apple", "D0D2B0": "Apple", "44D884": "Apple", "E4C6B5": "Apple",
        "28CFDA": "Apple", "A45E60": "Apple", "24F094": "Apple", "44D3CA": "Apple",
        "40A6D9": "Apple", "F099B6": "Apple", "80E82B": "Apple", "08F4EC": "Apple",
        "28FF3C": "Apple", "D4F46F": "Apple", "0C3E9F": "Apple", "ACCF5C": "Apple",
        # === Samsung ===
        "001377": "Samsung", "CC05E8": "Samsung", "50A6D8": "Samsung",
        "0491E2": "Samsung", "84D8C2": "Samsung", "181456": "Samsung",
        "F07959": "Samsung", "D071C4": "Samsung", "C8D5FE": "Samsung",
        "F0533A": "Samsung", "B0793C": "Samsung", "E8E61A": "Samsung",
        "E48B7F": "Samsung", "8C3A75": "Samsung", "1C23B6": "Samsung",
        "F47B5C": "Samsung", "445EF3": "Samsung", "F0421C": "Samsung",
        # === Huawei ===
        "40ED00": "Huawei", "28E31F": "Huawei", "D4F0B4": "Huawei",
        "48A925": "Huawei", "08C128": "Huawei", "00E0FC": "Huawei",
        "1011F3": "Huawei", "C8E7D8": "Huawei", "A03676": "Huawei",
        "E0F9E8": "Huawei", "AC7409": "Huawei", "5450E1": "Huawei",
        "24DA11": "Huawei Device", "28D576": "Huawei Device",
        "F44C36": "Huawei Device", "C86000": "Huawei Device",
        # === Xiaomi ===
        "00163E": "Xiaomi", "04E0A4": "Xiaomi", "34CE00": "Xiaomi",
        "28E02C": "Xiaomi", "F06130": "Xiaomi", "A48CD6": "Xiaomi",
        "D89B3B": "Xiaomi", "58B623": "Xiaomi", "48E1AF": "Xiaomi",
        "806D84": "Xiaomi", "D45AB9": "Xiaomi", "4467D7": "Xiaomi",
        "E8985A": "Xiaomi", "F09F60": "Xiaomi Communications",
        # === OPPO / vivo / OnePlus ===
        "509B21": "OPPO", "8C52E1": "OPPO", "54D46F": "OPPO",
        "E02169": "OPPO", "C80B73": "OPPO", "D89760": "OPPO",
        "A8D2F4": "vivo", "B43052": "vivo", "60F1B1": "vivo",
        "E8BB3D": "OnePlus", "D001DF": "OnePlus", "9820E1": "OnePlus",
        # === Intel ===
        "D89EF3": "Intel", "3432B4": "Intel", "4C3488": "Intel",
        "A41731": "Intel", "E04F43": "Intel", "A41F72": "Intel",
        "B46D83": "Intel", "84A6C8": "Intel", "C8F68C": "Intel",
        "D09466": "Intel", "8000F7": "Intel", "0C54A4": "Intel",
        # === Realtek ===
        "00E04C": "Realtek", "B04414": "Realtek", "08BEAC": "Realtek",
        "00E04F": "Realtek", "105AF0": "Realtek", "349971": "Realtek",
        "D03745": "Realtek", "B8599F": "Realtek", "08EA40": "Realtek",
        # === Broadcom ===
        "001A11": "Broadcom", "002586": "Broadcom", "001018": "Broadcom",
        "181E85": "Broadcom", "2C95FB": "Broadcom",
        # === Qualcomm Atheros ===
        "D85DE2": "Qualcomm Atheros", "B0C554": "Qualcomm Atheros",
        "8CFDF0": "Qualcomm Atheros", "F483CD": "Qualcomm Atheros",
        # === MediaTek ===
        "005043": "MediaTek", "1005B1": "MediaTek", "70F0C8": "MediaTek",
        "64A2F9": "MediaTek", "F093C5": "MediaTek", "30D16A": "MediaTek",
        # === TP-Link ===
        "3CBD3E": "TP-Link", "C0C9E3": "TP-Link", "50C7BF": "TP-Link",
        "B0F1EC": "TP-Link", "984827": "TP-Link", "A42B8C": "TP-Link",
        "E8DE27": "TP-Link", "F8D111": "TP-Link", "10D561": "TP-Link",
        "5CE931": "TP-Link", "3408BC": "TP-Link", "30B5C2": "TP-Link",
        "40EE15": "TP-Link", "E432CB": "TP-Link", "9440C9": "TP-Link",
        # === Tenda ===
        "C83A35": "Tenda", "B0487A": "Tenda", "504D79": "Tenda",
        "14D169": "Tenda", "00B00C": "Tenda",
        # === ASUS ===
        "244B81": "ASUSTek", "3498B5": "ASUSTek", "08BFB8": "ASUSTek",
        "A8DB88": "ASUSTek", "E03F49": "ASUSTek", "38D547": "ASUSTek",
        "04D9F5": "ASUSTek", "C8D9D2": "ASUSTek", "2C4D54": "ASUSTek",
        # === Netgear ===
        "B03956": "Netgear", "A021B7": "Netgear", "9C3DCF": "Netgear",
        "08BD43": "Netgear", "2C30C0": "Netgear", "0023A5": "Netgear",
        # === D-Link ===
        "C4E90A": "D-Link", "F01C2D": "D-Link", "1CBDB9": "D-Link",
        "48EEC4": "D-Link", "0022B3": "D-Link", "B0C5CA": "D-Link",
        # === Linksys ===
        "002368": "Linksys", "C0626B": "Linksys", "14156A": "Linksys",
        # === Cisco ===
        "08001E": "Cisco", "001BD4": "Cisco", "00D0BA": "Cisco",
        "8C604F": "Cisco", "3C0E23": "Cisco", "F44E05": "Cisco",
        "706D15": "Cisco Meraki", "E05597": "Cisco Meraki",
        # === HPE / Aruba ===
        "E0071B": "HPE", "1477F1": "HPE", "98F2B3": "HPE",
        "F40343": "Aruba", "20A6C0": "Aruba", "DCCD2F": "Aruba",
        # === Ubiquiti ===
        "FCECDA": "Ubiquiti", "24A43C": "Ubiquiti", "0440A9": "Ubiquiti",
        "788A20": "Ubiquiti", "74ACB9": "Ubiquiti", "B4FBE4": "Ubiquiti",
        # === MikroTik ===
        "4C5E0C": "MikroTik", "D4CA6D": "MikroTik", "6C3B6B": "MikroTik",
        "001A5F": "MikroTik",
        # === Lenovo ===
        "B075D5": "Lenovo", "344DEA": "Lenovo", "38A545": "Lenovo",
        "E0D173": "Lenovo", "CCB11A": "Lenovo Mobile", "50A715": "Lenovo",
        # === Dell ===
        "B8AC6F": "Dell", "503D56": "Dell", "D0D4E7": "Dell",
        "18DBF2": "Dell", "F48E38": "Dell", "A4BADB": "Dell",
        # === HP Inc ===
        "FC3FAB": "HP", "08117B": "HP", "A09D91": "HP",
        "3863BB": "HP", "1CC1DE": "HP", "B4B686": "HP",
        "AC1D06": "HP Inc", "5447F5": "HP Inc",
        # === Acer ===
        "08EDB9": "Acer", "0446A1": "Acer", "7C8A78": "Acer",
        "908D78": "Acer", "DC0EA1": "Acer",
        # === Gigabyte / MSI / ASRock ===
        "B42E99": "Gigabyte", "FCAA14": "Gigabyte", "18C087": "Gigabyte",
        "D8D385": "MSI", "303B7C": "MSI", "38D8A8": "MSI",
        "A85C2C": "ASRock", "BC5FF4": "ASRock",
        # === Raspberry Pi / 开发板 ===
        "B827EB": "Raspberry Pi", "DC4EDE": "Raspberry Pi",
        "DCA632": "Raspberry Pi", "28D244": "Raspberry Pi",
        "E45F01": "Raspberry Pi", "2C2F65": "Raspberry Pi",
        # === Espressif (ESP32/ESP8266) ===
        "30AEA4": "Espressif", "BCDDC2": "Espressif", "A020A6": "Espressif",
        "ECFA3C": "Espressif", "08F9E0": "Espressif", "D8F150": "Espressif",
        "3C71BF": "Espressif", "FCB467": "Espressif", "6857A7": "Espressif",
        "508D6F": "Espressif", "949AE1": "Espressif", "CC50E3": "Espressif",
        # === Tuya 智能设备 ===
        "105A17": "Tuya", "84F3FE": "Tuya", "D8B6C1": "Tuya",
        # === 海康威视 / 大华 / 宇视 ===
        "54C415": "Hikvision", "C4D08A": "Hikvision", "487ADA": "Hikvision",
        "C0A0BA": "Hikvision", "6C4E37": "Hikvision", "34D480": "Hikvision",
        "0CD696": "Hikvision", "B494C5": "Hikvision",
        "3C5AB4": "Dahua", "4C11BF": "Dahua", "E084F3": "Dahua",
        "9002A9": "Dahua", "74257C": "Dahua", "044D4B": "Uniview",
        # === 索尼 / 任天堂 / 微软 ===
        "0024A5": "Sony", "AC9B0A": "Sony", "F8461C": "Sony",
        "70F18D": "Sony Mobile", "787F62": "Sony Interactive Entertainment",
        "9CD36E": "Sony Interactive Entertainment",
        "B88AEC": "Nintendo", "E0F6B5": "Nintendo", "98B6E8": "Nintendo",
        "58BDA3": "Nintendo", "8C5635": "Nintendo",
        "00D861": "Microsoft", "28D0EA": "Microsoft", "DC4A3E": "Microsoft",
        "B03A99": "Microsoft", "002248": "Microsoft",
        # === 谷歌 / Amazon ===
        "A47733": "Google", "E0DB55": "Google", "54E45A": "Google",
        "3C8BF2": "Google", "F0F2C0": "Google", "AC67B7": "Google",
        "008CF5": "Amazon", "74C246": "Amazon", "FC65DE": "Amazon",
        "A007B6": "Amazon Technologies", "4C0E44": "Amazon",
        # === 打印机: Brother / Canon / Epson / Xerox / Ricoh ===
        "008092": "Brother", "001BA9": "Brother", "30055C": "Brother",
        "001854": "Canon", "000F66": "Canon", "B0029A": "Canon",
        "0000DE": "Canon", "008F20": "Canon",
        "0004C8": "Epson", "00E018": "Epson", "A4C9B6": "Epson",
        "00012A": "Xerox", "000913": "Xerox", "9C934E": "Xerox",
        "0006B0": "Ricoh", "001A70": "Ricoh", "004064": "Ricoh",
        # === 海信 / TCL / Skyworth / 创维 ===
        "54BEF7": "Hisense", "C82A14": "Hisense", "DCCB94": "Hisense",
        "ACD074": "TCL", "A49A58": "TCL", "ECB3A7": "TCL",
        "001A34": "Skyworth", "E0F211": "Skyworth",
        # === 虚拟化 ===
        "525400": "QEMU", "0003FF": "Microsoft (Hyper-V)",
        "000C29": "VMware", "005056": "VMware", "000569": "VMware",
        "001C42": "Parallels", "080027": "VirtualBox",
        # === 其他常见品牌 ===
        "0090C2": "Roku", "B0A737": "Roku", "CC6DA0": "Roku",
        "44F034": "Nest Labs", "18B430": "Nest Labs", "641666": "Nest Labs",
        "C44F57": "Fitbit", "00531B": "Fitbit",
        "0011D8": "ASIX", "80A962": "ASIX",
        "984B4A": "Motorola Mobility", "E411A2": "Motorola Mobility",
        "C8680F": "ZTE", "047A80": "ZTE", "3C81D8": "ZTE",
        "04B648": "Zenith", "04CF8C": "Foxconn", "48437C": "Foxconn",
        "1CE2B7": "Nokia", "68A423": "Nokia", "88DD79": "Nokia",
        "EC1A59": "Belkin", "94A7B7": "Belkin",
        "78E103": "IKEA", "681CA9": "IKEA",
        "D01C0C": "Garmin", "40BBB0": "Garmin", "601185": "Garmin",
        "EC9F0D": "Sonos", "5CAAF3": "Sonos", "B8E937": "Sonos",
        "C09132": "Philips", "DCA989": "Philips", "0015AF": "Philips",
        "0022A2": "Philips Lighting", "D03211": "Signify",
        "54EF44": "Lumi United (Aqara)", "7CDC84": "Lumi United (Aqara)",
        "E06D17": "Roborock", "7811DC": "Roborock",
        "C07B0F": "Ecovacs", "D8D090": "Ecovacs",
        "90E2FC": "iRobot", "001B66": "iRobot",
        "C09C92": "Dyson", "08C15B": "Dyson",
        "6C5A5C": "Tesla", "98B449": "Tesla",
        "F893A4": "Honeywell", "00037F": "Honeywell",
        "14568B": "Juniper", "B0C69A": "Juniper", "28C00F": "Juniper",
        "6CB227": "Synology", "00A0B4": "Synology", "901D27": "Synology",
        "245EBE": "QNAP", "0024A4": "QNAP",
        "00C0A8": "Panasonic", "002354": "Panasonic", "78D9C2": "Panasonic",
        "001DBA": "LG Electronics", "F07960": "LG Electronics",
        "CC2DB2": "LG Innotek", "001C7B": "LG Innotek",
        "6CF587": "Bose", "0012D3": "Bose", "783103": "Bose",
        "3C6114": "Harman", "000954": "Harman",
        "00A05A": "JBL", "804E70": "JBL",
        "0030CD": "Yamaha", "00A0DB": "Yamaha",
        "000DF4": "Denon", "00E036": "Denon",
        "00E07D": "Netronix", "0020E8": "Netronix",
        "90E8CF": "Rockchip", "083A5C": "Allwinner",
        "640C91": "Amlogic", "10D08A": "Amlogic",
        "E0451A": "Razer", "58D9C3": "Razer",
        "2C6E49": "NVIDIA", "48EB30": "NVIDIA", "0024BA": "NVIDIA",
        "3CEA4B": "Wyze", "2C5A05": "Wyze",
        "00E034": "Bosch", "AC83F3": "Bosch",
        "14CC20": "Marvell", "50465D": "Marvell", "F4C4D6": "Marvell",
        "00E0CD": "DisplayLink",
        "2C26C5": "Zebra", "0004D2": "Zebra",
        "00204D": "Kyocera", "00C055": "Kyocera",
        "000553": "Konica Minolta",
        "00E074": "Lexmark", "000013": "Lexmark",
        "4C9EFF": "ZyXEL", "0002ED": "ZyXEL", "349672": "ZyXEL",
        "FC3297": "Xiaoyi", "841B5E": "Netis",
        "00A0C6": "Qualcomm", "0001C8": "Qualcomm",
        "E4F4C6": "Netgear",
        "1C4BD6": "AzureWave", "54AF53": "AzureWave",
        "00B02D": "Ralink", "002618": "Ralink",
        "28DB81": "SHARP", "001D38": "SHARP", "080028": "SHARP",
        "6C8335": "Banana Pi", "02A067": "Banana Pi",
        "C4F14A": "Wistron", "907EBA": "Wistron",
        "D896E0": "Quanta", "A86BD4": "Quanta",
        "00C0EE": "Pegatron",
        "342387": "Hon Hai", "B817C7": "Hon Hai",
        "78629C": "Meizu", "082471": "Meizu",
        "080028": "Oracle",
    }
    return table.get(oui, "")


# ── 扫描引擎 ──────────────────────────────────────────

# 常见的 TCP 端口, 大部分在线主机会响应其中至少一个
COMMON_PORTS = [135, 445, 139, 22, 80, 443, 3389, 8080, 23, 21]


def tcp_probe(ip: str, port: int, timeout: float = 0.08) -> bool:
    """TCP 连接探测, 超短超时, 本地局域网极快。"""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        return result == 0
    except Exception:
        return False
    finally:
        if sock:
            sock.close()


def is_host_alive(ip: str) -> bool:
    """判断主机是否在线: 先 ICMP ping 快速判断, 再 TCP 多端口兜底 (防火墙可能屏蔽 ICMP)。"""
    # ICMP 优先 — Windows 上 ARP 超时不会像 connect_ex 那样长时间阻塞
    if ping_host(ip, timeout=0.5):
        return True
    # TCP 兜底
    for port in COMMON_PORTS:
        if tcp_probe(ip, port, timeout=0.06):
            return True
    return False


def scan_network(network_str: str, max_workers: int = 64) -> list[Device]:
    """扫描整个网段, 返回在线设备列表。"""
    network = ipaddress.IPv4Network(network_str, strict=False)
    hosts = list(network.hosts())
    total = len(hosts)

    print(f"\n  网段: {network.network_address}  掩码: {network.netmask}  主机数: {total}")

    print(f"  阶段 1/2: 读取 ARP 缓存...")
    arp_cache = get_arp_table()
    arp_devices = [Device(ip=ip, mac=mac) for ip, mac in arp_cache.items()
                   if ipaddress.IPv4Address(ip) in network]
    if arp_devices:
        print(f"    ARP 缓存中已有 {len(arp_devices)} 个设备:")
        for d in arp_devices:
            d.vendor = mac_to_vendor(d.mac) if d.mac else ""
            d.dev_type = vendor_device_type(d.vendor) if d.vendor else ""
            print(f"      {d.ip:<16}  {d.mac or '-':<18}  {d.hostname or '-':<20}  {d.vendor_display}")

    print(f"\n  阶段 2/2: ICMP + TCP 扫描 (发现即显示)...")
    devices: dict[str, Device] = {d.ip: d for d in arp_devices}
    lock = threading.Lock()
    finished = [0]

    def scan_one(ip_str: str):
        if ip_str not in devices and is_host_alive(ip_str):
            mac = arp_cache.get(ip_str, "")
            hostname = get_hostname(ip_str, timeout=0.15)
            if not hostname:
                hostname = get_netbios_name(ip_str, timeout=0.8)
            vendor = mac_to_vendor(mac) if mac else ""
            dev_type = vendor_device_type(vendor) if vendor else ""
            d = Device(ip=ip_str, mac=mac, hostname=hostname, vendor=vendor, dev_type=dev_type)
            with lock:
                devices[ip_str] = d
            print(f"    + {d.ip:<16}  {d.mac or '-':<18}  {hostname or '-':<20}  {d.vendor_display}")

        with lock:
            finished[0] += 1
            if finished[0] == total:
                sys.stdout.write(f"\r    扫描完成: {finished[0]}/{total}, 共发现 {len(devices)} 台设备          \n")
                sys.stdout.flush()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_one, str(h)) for h in hosts]
        for f in as_completed(futures):
            try:
                f.result()
            except Exception:
                pass

    print(f"\n  刷新 ARP 缓存...")
    arp_cache2 = get_arp_table()
    for ip_str in list(devices.keys()):
        d = devices[ip_str]
        if not d.mac and ip_str in arp_cache2:
            d.mac = arp_cache2[ip_str]
            d.vendor = mac_to_vendor(d.mac)
            d.dev_type = vendor_device_type(d.vendor) if d.vendor else ""

    print()
    return sorted(devices.values(), key=lambda d: ipaddress.IPv4Address(d.ip))


# ── 输出 ──────────────────────────────────────────────

def print_results(devices: list[Device], network_str: str, local_ip: str = "", gateway: str = ""):
    """打印扫描结果，显示厂商和设备类型，标注本机和网关。"""
    network = ipaddress.IPv4Network(network_str, strict=False)
    gw_display = f"  默认网关: {gateway}" if gateway else ""
    print(f"\n{'=' * 90}")
    print(f"  网络段: {network_str}")
    print(f"  本机 IP: {local_ip or 'N/A'}{gw_display}")
    print(f"  在线设备: {len(devices)} 台")
    print(f"{'=' * 90}\n")

    if not devices:
        print("  未发现其他在线设备。\n")
        return

    header = f"  {'IP 地址':<16}  {'MAC 地址':<18}  {'主机名':<20}  {'厂商 / 设备类型':<20}  状态"
    print(header)
    print(f"  {'-' * 16}  {'-' * 18}  {'-' * 20}  {'-' * 20}  ----")

    for d in devices:
        name_display = d.hostname or "-"
        if d.ip == local_ip and d.ip == gateway:
            tag = "(本机/网关)"
        elif d.ip == local_ip:
            tag = "(本机)"
        elif d.ip == gateway:
            tag = "(网关)"
        else:
            tag = "在线"
        print(f"  {d.ip:<16}  {d.mac or '-':<18}  {name_display:<20}  {d.vendor_display:<20}  {tag}")

    print()


# ── 入口 ──────────────────────────────────────────────

def export_csv(devices: list[Device], filename: str = ""):
    """导出结果到 CSV 文件 (含设备类型列)。"""
    import csv
    if not filename:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"lan_scan_{timestamp}.csv"
    os.makedirs(os.path.dirname(os.path.abspath(filename)) or ".", exist_ok=True)
    with open(filename, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP 地址", "MAC 地址", "主机名", "厂商", "设备类型"])
        for d in devices:
            writer.writerow([d.ip, d.mac or "", d.hostname, d.vendor, d.dev_type])
    print(f"  已导出到: {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="局域网 IP 扫描器 —— 扫描同一网段内的所有在线设备"
    )
    parser.add_argument("-y", "--yes", action="store_true",
                        help="非交互模式, 自动选择默认选项")
    parser.add_argument("-e", "--export", action="store_true",
                        help="扫描完成后自动导出 CSV 文件")
    parser.add_argument("-o", "--output", type=str, default="",
                        help="指定 CSV 导出路径 (与 -e 配合使用)")
    parser.add_argument("-n", "--network", type=str, default="",
                        help="手动指定网段 (如 192.168.1.0/24)")
    parser.add_argument("-t", "--threads", type=int, default=128,
                        help="并发线程数 (默认 128)")
    parser.add_argument("-i", "--interface", type=str, default="",
                        help="指定网卡: 序号(1,2,3) 或网卡名(如 WLAN)")
    parser.add_argument("-l", "--list", action="store_true",
                        help="列出所有可用网卡并退出")
    args = parser.parse_args()

    if args.threads < 1 or args.threads > 512:
        print(f"\n  错误: 线程数必须在 1-512 之间，收到 {args.threads}。\n")
        sys.exit(1)

    print("\n" + "=" * 70)
    print("  局域网 IP 扫描器 v2.0")
    print("=" * 70)

    # 手动指定网段
    iface_name = ""
    if args.network:
        try:
            net = ipaddress.IPv4Network(args.network, strict=False)
        except Exception as e:
            print(f"\n  错误: 无效的网段格式 - {e}\n")
            sys.exit(1)
        if net.num_addresses > MAX_SCAN_HOSTS:
            print(f"\n  错误: 网段过大 ({net.num_addresses} 个地址)，最多支持 {MAX_SCAN_HOSTS} 个。\n")
            sys.exit(1)
        network_str = args.network
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            local_ip = ""
        print(f"\n  使用指定网段: {network_str}")
    else:
        networks = get_local_networks()
        if not networks:
            print("\n  错误: 无法获取本机网络信息。请检查网络连接。\n")
            sys.exit(1)

        if args.list:
            print(f"\n  检测到 {len(networks)} 个网络接口:\n")
            for i, (iface, ip, net) in enumerate(networks, 1):
                print(f"    [{i}] {iface}  ->  {net}  (本机: {ip})")
            print()
            sys.exit(0)

        if args.interface:
            choice = args.interface.strip()
            idx = -1
            if choice.isdigit():
                num = int(choice)
                if 1 <= num <= len(networks):
                    idx = num - 1
            if idx < 0:
                for i, (iface, ip, net) in enumerate(networks):
                    if choice.lower() in iface.lower():
                        idx = i
                        break
            if idx < 0:
                print(f"\n  错误: 找不到匹配的网卡 \"{choice}\"。可用的网卡:\n")
                for i, (iface, ip, net) in enumerate(networks, 1):
                    print(f"    [{i}] {iface}  ->  {net}  (本机: {ip})")
                print()
                sys.exit(1)
        elif not args.yes:
            print(f"\n  检测到 {len(networks)} 个网络接口:\n")
            for i, (iface, ip, net) in enumerate(networks, 1):
                print(f"    [{i}] {iface}  ->  {net}  (本机: {ip})")
            print()
            if len(networks) == 1:
                choice = input("  按回车键开始扫描, 输入 q 取消: ").strip()
                if choice.lower() == "q":
                    print("\n  已取消。\n")
                    sys.exit(0)
                idx = 0
            else:
                try:
                    choice = input(f"  请选择要扫描的网络 [1-{len(networks)}] (直接回车=1): ").strip()
                    idx = int(choice) - 1 if choice else 0
                    idx = max(0, min(idx, len(networks) - 1))
                except (ValueError, KeyboardInterrupt):
                    print("\n  已取消。\n")
                    sys.exit(0)
        else:
            idx = 0

        iface_name, local_ip, network_str = networks[idx]
        print(f"\n  使用网卡: [{iface_name}]  ->  {network_str}  (本机: {local_ip})")

    # 获取本机 MAC 地址 (按 IP 或网卡名匹配) 和默认网关
    local_mac = get_local_mac(iface_name, local_ip)
    gateway = get_default_gateway()

    # 验证 ping 可用
    if not ping_host("127.0.0.1", timeout=1.0):
        print("  提示: ICMP Ping 不可用, 将仅使用 TCP 端口探测\n")

    devices = scan_network(network_str, max_workers=args.threads)

    # 过滤 网络地址 与 广播地址
    net = ipaddress.IPv4Network(network_str, strict=False)
    others = [d for d in devices
              if d.ip not in (str(net.network_address), str(net.broadcast_address))]

    # 如果本机没有从 ARP 获取到 MAC, 从网卡直接读取
    for d in others:
        if d.ip == local_ip and not d.mac and local_mac:
            d.mac = local_mac

    print_results(others, network_str, local_ip, gateway)

    # 导出
    if args.export or (not args.yes and input("  导出结果到文件? (y/n, 默认 n): ").strip().lower() == "y"):
        export_csv(others, args.output)

    print("  扫描完成。\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  扫描已中断。\n")
        sys.exit(0)
