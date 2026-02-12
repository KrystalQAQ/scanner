#!/usr/bin/env python3
"""
LAN scanner backend service.

Run:
  python server.py
"""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


HOST = "0.0.0.0"
PORT = 8000
MAX_HOSTS = 512
PING_WORKERS = 64
PORT_WORKERS = 36
PORT_TIMEOUT = 0.22
ARP_WORKERS = 48
MAX_LOGS = 300

COMMON_PORTS = [21, 22, 23, 53, 80, 135, 139, 443, 445, 554, 3389, 5000, 8080, 9100]
TCP_FALLBACK_PORTS = [80, 443, 22, 445, 3389, 53]

PING_TIMEOUT_MS = max(100, int(os.getenv("PING_TIMEOUT_MS", "700")))
PING_RETRIES = max(1, int(os.getenv("PING_RETRIES", "2")))
TCP_FALLBACK_TIMEOUT = max(0.1, float(os.getenv("TCP_FALLBACK_TIMEOUT", "0.28")))
ENABLE_ARP = os.getenv("ENABLE_ARP", "1").strip() != "0"

JOBS: dict[str, "ScanJob"] = {}
JOBS_LOCK = threading.Lock()
KNOWN_DEVICES: set[str] = set()
KNOWN_LOCK = threading.Lock()


def resource_path(name: str) -> str:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        base = getattr(sys, "_MEIPASS")
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, name)


def now_str() -> str:
    return datetime.now().strftime("%H:%M:%S")


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


@dataclass
class ScanJob:
    cidr: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:10])
    status: str = "running"
    progress: int = 0
    current_step: str = "Waiting"
    logs: list[str] = field(default_factory=list)
    devices: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=lambda: {"total": 0, "online": 0, "risk": 0, "new": 0})
    started_at: str = field(default_factory=now_iso)
    finished_at: str | None = None
    error: str | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def log(self, message: str) -> None:
        with self.lock:
            self.logs.append(f"[{now_str()}] {message}")
            if len(self.logs) > MAX_LOGS:
                self.logs = self.logs[-MAX_LOGS:]

    def update(self, *, progress: int | None = None, step: str | None = None) -> None:
        with self.lock:
            if progress is not None:
                self.progress = max(0, min(100, int(progress)))
            if step is not None:
                self.current_step = step

    def set_devices(self, devices: list[dict]) -> None:
        with self.lock:
            self.devices = devices

    def set_summary(self, summary: dict) -> None:
        with self.lock:
            self.summary = summary

    def fail(self, err: str) -> None:
        with self.lock:
            self.status = "failed"
            self.error = err
            self.finished_at = now_iso()
            self.progress = 100
            self.current_step = "Failed"
            self.logs.append(f"[{now_str()}] 扫描失败: {err}")

    def complete(self) -> None:
        with self.lock:
            self.status = "completed"
            self.finished_at = now_iso()
            self.progress = 100
            self.current_step = "Completed"
            self.logs.append(f"[{now_str()}] 扫描完成")

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "jobId": self.id,
                "cidr": self.cidr,
                "status": self.status,
                "progress": self.progress,
                "currentStep": self.current_step,
                "logs": list(self.logs),
                "devices": list(self.devices),
                "summary": dict(self.summary),
                "startedAt": self.started_at,
                "finishedAt": self.finished_at,
                "error": self.error,
            }


def parse_cidr(cidr: str) -> list[str]:
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(ip) for ip in network.hosts()]
    if network.prefixlen == 32 and not hosts:
        hosts = [str(network.network_address)]
    if not hosts:
        raise ValueError("无可扫描主机")
    if len(hosts) > MAX_HOSTS:
        raise ValueError(f"网段过大，最大支持 {MAX_HOSTS} 个主机")
    return hosts


def ping_host(ip: str) -> int | None:
    system = platform.system().lower()

    for _ in range(PING_RETRIES):
        if "windows" in system:
            cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), ip]
        else:
            timeout_sec = max(1, int((PING_TIMEOUT_MS + 999) / 1000))
            cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]

        start = time.time()
        try:
            proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if proc.returncode == 0:
                return max(1, int((time.time() - start) * 1000))
        except OSError:
            return None
    return None


def scan_ports(ip: str) -> list[int]:
    opens: list[int] = []
    for port in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(PORT_TIMEOUT)
        try:
            if sock.connect_ex((ip, port)) == 0:
                opens.append(port)
        except OSError:
            pass
        finally:
            sock.close()
    return opens


def tcp_probe_host(ip: str) -> tuple[int | None, int | None]:
    start = time.time()
    for port in TCP_FALLBACK_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TCP_FALLBACK_TIMEOUT)
        try:
            if sock.connect_ex((ip, port)) == 0:
                latency = max(1, int((time.time() - start) * 1000))
                return port, latency
        except OSError:
            pass
        finally:
            sock.close()
    return None, None


def read_arp_table_ips() -> set[str]:
    system = platform.system().lower()
    commands: list[list[str]] = []
    if "windows" in system:
        commands = [["arp", "-a"]]
    else:
        commands = [["ip", "neigh"], ["arp", "-an"]]

    ips: set[str] = set()
    for cmd in commands:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
            text = f"{proc.stdout}\n{proc.stderr}"
        except Exception:
            continue
        for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
            try:
                ipaddress.IPv4Address(candidate)
                ips.add(candidate)
            except ipaddress.AddressValueError:
                continue
        if ips:
            break
    return ips


def arping_command_templates() -> list[list[str]]:
    if not ENABLE_ARP:
        return []
    arping = shutil.which("arping")
    if not arping:
        return []
    system = platform.system().lower()
    if "linux" in system:
        return [
            [arping, "-c", "1", "-w", "1", "{ip}"],
            [arping, "-c", "1", "-W", "1", "{ip}"],
        ]
    if "darwin" in system:
        return [[arping, "-c", "1", "{ip}"]]
    return []


def arping_host(ip: str, templates: list[list[str]]) -> bool:
    if not templates:
        return False
    for cmd_template in templates:
        cmd = [part.format(ip=ip) for part in cmd_template]
        try:
            proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.2, check=False)
            if proc.returncode == 0:
                return True
        except Exception:
            continue
    return False


def infer_device_type(open_ports: list[int]) -> str:
    ports = set(open_ports)
    if 554 in ports:
        return "Camera / CCTV"
    if 9100 in ports:
        return "Printer"
    if 445 in ports and 139 in ports:
        return "Windows Host"
    if 53 in ports:
        return "Router / DNS"
    if 5000 in ports or 8080 in ports:
        return "NAS / Appliance"
    if 3389 in ports:
        return "Remote Desktop Host"
    if 22 in ports:
        return "Linux / Unix Host"
    if 443 in ports or 80 in ports:
        return "Web Device"
    return "Unknown Device"


def risk_score(open_ports: list[int]) -> int:
    score = 12
    ports = set(open_ports)
    if 23 in ports:
        score += 35
    if 21 in ports:
        score += 16
    if 445 in ports:
        score += 17
    if 3389 in ports:
        score += 14
    if 554 in ports:
        score += 14
    if 80 in ports and 443 not in ports:
        score += 8
    if len(ports) >= 6:
        score += 10
    if len(ports) == 0:
        score -= 4
    return max(1, min(99, score))


def hostname_for(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return "unknown-host"


def summarize(devices: list[dict]) -> dict:
    total = len(devices)
    online = sum(1 for d in devices if d["state"] in {"online", "risky"})
    risky = sum(1 for d in devices if d["state"] == "risky" or d["risk"] >= 70)
    new_count = sum(1 for d in devices if d.get("isNew"))
    return {"total": total, "online": online, "risk": risky, "new": new_count}


def run_scan(job: ScanJob) -> None:
    try:
        hosts = parse_cidr(job.cidr)
        host_set = set(hosts)
        total_hosts = len(hosts)
        network = ipaddress.ip_network(job.cidr, strict=False)
        job.update(progress=2, step="Host discovery")
        job.log(f"任务已创建，网段 {job.cidr}，待检测主机 {total_hosts}")
        job.log(f"Ping 参数: timeout={PING_TIMEOUT_MS}ms retries={PING_RETRIES}")

        alive_map: dict[str, dict] = {}

        def mark_alive(ip: str, source: str, latency: int | None) -> bool:
            source_rank = {
                "arp-active": 1,
                "arp-table": 1,
                "tcp-fallback": 2,
                "ping": 3,
            }
            current = alive_map.get(ip)
            candidate = {"source": source, "latency": latency if latency is not None else 0}
            if current is None:
                alive_map[ip] = candidate
                return True
            if source_rank.get(source, 0) >= source_rank.get(current["source"], 0):
                alive_map[ip] = candidate
            return False

        # Stage 1: active ARP scan when available.
        arp_templates = arping_command_templates()
        if network.version == 4 and network.is_private and arp_templates:
            job.update(progress=4, step="Host discovery (ARP active)")
            job.log("开始 ARP 主动探测")
            arp_found = 0
            done = 0
            workers = min(ARP_WORKERS, total_hosts)
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(arping_host, ip, arp_templates): ip for ip in hosts}
                for future in as_completed(futures):
                    done += 1
                    ip = futures[future]
                    ok = future.result()
                    if ok:
                        if mark_alive(ip, "arp-active", 0):
                            arp_found += 1
                            if arp_found <= 40:
                                job.log(f"ARP 响应 {ip}")
                    progress = 4 + int((done / total_hosts) * 16)
                    job.update(progress=progress)
            job.log(f"ARP 主动探测完成，新发现 {arp_found} 台")
        else:
            if network.version == 4 and network.is_private:
                job.log("未找到 arping 命令，跳过 ARP 主动探测")
            else:
                job.log("网段非私有 IPv4，跳过 ARP 主动探测")
            job.update(progress=20)

        # Stage 2: ping sweep with retries.
        job.update(progress=20, step="Host discovery (ping)")
        job.log("开始 Ping 探测")
        ping_found = 0
        done = 0
        with ThreadPoolExecutor(max_workers=PING_WORKERS) as pool:
            futures = {pool.submit(ping_host, ip): ip for ip in hosts}
            for future in as_completed(futures):
                done += 1
                ip = futures[future]
                latency = future.result()
                if latency is not None:
                    created = mark_alive(ip, "ping", latency)
                    if created:
                        ping_found += 1
                    if ping_found <= 60 and created:
                        job.log(f"Ping 在线 {ip} ({latency}ms)")
                progress = 20 + int((done / total_hosts) * 35)
                job.update(progress=progress)
        job.log(f"Ping 探测完成，可达主机累计 {len(alive_map)} 台")

        # Stage 3: ARP table enrichment.
        job.update(progress=55, step="Host discovery (ARP table)")
        table_hits = 0
        if network.version == 4 and network.is_private:
            for ip in read_arp_table_ips():
                if ip in host_set and mark_alive(ip, "arp-table", 0):
                    table_hits += 1
            job.log(f"ARP 表补充发现 {table_hits} 台")
        else:
            job.log("跳过 ARP 表补充")
        job.update(progress=60)

        # Stage 4: TCP fallback for ping-failed hosts.
        unresolved = [ip for ip in hosts if ip not in alive_map]
        job.update(progress=60, step="Host discovery (TCP fallback)")
        tcp_found = 0
        if unresolved:
            job.log(f"开始 TCP 兜底探测，待探测 {len(unresolved)} 台")
            done = 0
            with ThreadPoolExecutor(max_workers=PING_WORKERS) as pool:
                futures = {pool.submit(tcp_probe_host, ip): ip for ip in unresolved}
                for future in as_completed(futures):
                    done += 1
                    ip = futures[future]
                    port, latency = future.result()
                    if port is not None:
                        if mark_alive(ip, "tcp-fallback", latency):
                            tcp_found += 1
                            if tcp_found <= 40:
                                job.log(f"TCP 命中 {ip} (port {port})")
                    progress = 60 + int((done / len(unresolved)) * 10)
                    job.update(progress=progress)
            job.log(f"TCP 兜底完成，新发现 {tcp_found} 台")
        else:
            job.log("无剩余主机需要 TCP 兜底")
        job.update(progress=70)

        alive = [(ip, meta["latency"], meta["source"]) for ip, meta in alive_map.items()]
        alive.sort(key=lambda x: ipaddress.ip_address(x[0]))
        job.log(f"主机发现完成，在线主机 {len(alive)} 台")
        job.update(progress=71, step="Port and fingerprint scan")

        devices: list[dict] = []
        if alive:
            scanned = 0
            with ThreadPoolExecutor(max_workers=PORT_WORKERS) as pool:
                futures = {
                    pool.submit(scan_ports, ip): (ip, latency, source)
                    for ip, latency, source in alive
                }
                for future in as_completed(futures):
                    scanned += 1
                    ip, latency, source = futures[future]
                    open_ports = sorted(future.result())
                    ports_text = ", ".join(str(p) for p in open_ports) if open_ports else "-"
                    host = hostname_for(ip)
                    risk = risk_score(open_ports)
                    state = "risky" if risk >= 70 else "online"
                    device = {
                        "ip": ip,
                        "host": host,
                        "type": infer_device_type(open_ports),
                        "state": state,
                        "ports": ports_text,
                        "risk": risk,
                        "latencyMs": latency,
                        "discovery": source,
                        "lastSeen": now_iso(),
                    }
                    with KNOWN_LOCK:
                        device["isNew"] = ip not in KNOWN_DEVICES
                        KNOWN_DEVICES.add(ip)
                    devices.append(device)
                    if scanned <= 60:
                        job.log(f"完成主机分析 {ip} 端口[{ports_text}] 风险{risk} 来源[{source}]")
                    progress = 71 + int((scanned / len(alive)) * 24)
                    job.update(progress=progress)
                    if scanned % 8 == 0:
                        partial = sorted(devices, key=lambda x: x["risk"], reverse=True)
                        job.set_devices(partial)
                        job.set_summary(summarize(partial))

        devices = sorted(devices, key=lambda x: x["risk"], reverse=True)
        job.set_devices(devices)
        job.set_summary(summarize(devices))
        job.update(progress=99, step="Finalizing")
        job.log("正在汇总结果")
        time.sleep(0.1)
        job.complete()
    except Exception as exc:
        job.fail(str(exc))


class ScannerHandler(BaseHTTPRequestHandler):
    server_version = "LANScanner/1.0"

    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.end_headers()

    def _json_response(self, payload: dict, status: int = HTTPStatus.OK) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        body = self.rfile.read(length).decode("utf-8")
        return json.loads(body)

    def do_POST(self) -> None:
        path = urlparse(self.path).path

        if path == "/api/scan/start":
            try:
                body = self._read_json()
                cidr = (body.get("cidr") or "").strip()
                if not cidr:
                    raise ValueError("cidr 不能为空")
                parse_cidr(cidr)
            except Exception as exc:
                self._json_response({"ok": False, "error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return

            job = ScanJob(cidr=cidr)
            with JOBS_LOCK:
                JOBS[job.id] = job

            thread = threading.Thread(target=run_scan, args=(job,), daemon=True)
            thread.start()

            self._json_response({"ok": True, "jobId": job.id, "status": job.status, "cidr": cidr})
            return

        self._json_response({"ok": False, "error": "Not Found"}, status=HTTPStatus.NOT_FOUND)

    def do_GET(self) -> None:
        path = urlparse(self.path).path

        if path == "/api/health":
            self._json_response(
                {
                    "ok": True,
                    "service": "lan-scanner-backend",
                    "time": now_iso(),
                    "jobs": len(JOBS),
                }
            )
            return

        if path.startswith("/api/scan/"):
            job_id = path.rsplit("/", 1)[-1]
            with JOBS_LOCK:
                job = JOBS.get(job_id)
            if not job:
                self._json_response({"ok": False, "error": "Job not found"}, status=HTTPStatus.NOT_FOUND)
                return
            snap = job.snapshot()
            snap["ok"] = True
            self._json_response(snap)
            return

        if path in {"/", "/index.html"}:
            file_path = resource_path("index.html")
            if not os.path.exists(file_path):
                self._json_response({"ok": False, "error": "index.html not found"}, status=HTTPStatus.NOT_FOUND)
                return
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        self._json_response({"ok": False, "error": "Not Found"}, status=HTTPStatus.NOT_FOUND)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), ScannerHandler)
    print(f"LAN scanner server listening on http://127.0.0.1:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
