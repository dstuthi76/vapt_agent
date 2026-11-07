"""Scope enforcement. Every scan, import and validation passes through ScopeGuard.

Rules (deny wins):
  * the target must be an IP inside a registered CIDR / IP, or a registered hostname;
  * hostnames are resolved and the resolved IP must not be excluded;
  * non-private (public) addresses are refused unless the scope file explicitly allows it;
  * the port must be inside allowed_ports, the tool must be in allowed_tools;
  * the current time must be inside the engagement window (if set).
"""
from __future__ import annotations

import ipaddress
import json
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    target: str
    resolved_ip: Optional[str] = None

    def to_dict(self):
        return self.__dict__.copy()


def _parse_ports(spec: str) -> list[tuple[int, int]]:
    out = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.append((int(a), int(b)))
        else:
            out.append((int(part), int(part)))
    return out


class ScopeGuard:
    def __init__(self, scope: dict):
        self.scope = scope
        self.networks = []
        self.hostnames = {}
        self.target_meta = []
        for t in scope.get("targets", []):
            v = str(t["value"]).strip()
            self.target_meta.append(t)
            try:
                self.networks.append((ipaddress.ip_network(v, strict=False), t))
            except ValueError:
                self.hostnames[v.lower()] = t
        self.excl_networks, self.excl_hosts = [], set()
        for e in scope.get("exclusions", []):
            try:
                self.excl_networks.append(ipaddress.ip_network(str(e), strict=False))
            except ValueError:
                self.excl_hosts.add(str(e).lower())
        self.ports = _parse_ports(scope.get("allowed_ports", "1-65535"))
        self.allowed_tools = set(scope.get("allowed_tools", []))
        self.allow_non_private = bool(scope.get("allow_non_private", False))

    @classmethod
    def from_file(cls, path: Path) -> "ScopeGuard":
        return cls(json.loads(Path(path).read_text()))

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def split_target(target: str) -> tuple[str, Optional[int]]:
        """Return (host, port) for an IP, hostname, host:port or URL."""
        t = target.strip()
        if "://" in t:
            u = urlparse(t)
            port = u.port or (443 if u.scheme == "https" else 80)
            return (u.hostname or "").lower(), port
        if t.count(":") == 1 and not t.startswith("["):
            h, p = t.split(":")
            if p.isdigit():
                return h.lower(), int(p)
        return t.lower(), None

    def _resolve(self, host: str) -> Optional[str]:
        alias = (self.scope.get("host_aliases") or {}).get(host)
        if alias:
            return alias
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        try:
            return socket.gethostbyname(host)
        except OSError:
            return None

    def _excluded(self, host: str, ip: Optional[str]) -> bool:
        if host in self.excl_hosts:
            return True
        if ip:
            ipa = ipaddress.ip_address(ip)
            return any(ipa in n for n in self.excl_networks)
        return False

    def _window_ok(self) -> tuple[bool, str]:
        w = self.scope.get("window") or {}
        now = datetime.now(timezone.utc)
        for key, cmp in (("start", lambda n, x: n >= x), ("end", lambda n, x: n <= x)):
            if w.get(key):
                x = datetime.fromisoformat(w[key].replace("Z", "+00:00"))
                if x.tzinfo is None:
                    x = x.replace(tzinfo=timezone.utc)
                if not cmp(now, x):
                    return False, f"outside engagement window ({key}={w[key]})"
        return True, ""

    def meta_for(self, host: str) -> dict:
        """Criticality/exposure metadata for an asset (used by risk scoring)."""
        host = host.lower()
        if host in self.hostnames:
            return self.hostnames[host]
        ip = self._resolve(host) if host else None
        if ip:
            for hn, meta in self.hostnames.items():
                if self._resolve(hn) == ip:
                    return meta
            ipa = ipaddress.ip_address(ip)
            best = None
            for net, meta in self.networks:
                if ipa in net and (best is None or net.prefixlen > best[0].prefixlen):
                    best = (net, meta)
            if best:
                return best[1]
        return {"criticality": "medium", "exposure": "internal"}

    # ------------------------------------------------------------------ main API
    def check(self, target: str, tool: Optional[str] = None, port: Optional[int] = None) -> ScopeDecision:
        host, url_port = self.split_target(target)
        port = port or url_port
        if not host:
            return ScopeDecision(False, "empty or unparsable target", target)
        ok, why = self._window_ok()
        if not ok:
            return ScopeDecision(False, why, target)
        if tool and self.allowed_tools and tool not in self.allowed_tools:
            return ScopeDecision(False, f"tool '{tool}' is not permitted by the scope", target)

        # a CIDR target (for discovery sweeps) must equal / sit inside a registered network
        if "/" in host:
            try:
                net = ipaddress.ip_network(host, strict=False)
            except ValueError:
                return ScopeDecision(False, "invalid network", target)
            if not any(net.subnet_of(n) for n, _ in self.networks if n.version == net.version):
                return ScopeDecision(False, f"network {net} is not inside any registered scope network", target)
            if not self.allow_non_private and not net.is_private:
                return ScopeDecision(False, "public network ranges are never scanned (allow_non_private=false)", target)
            return ScopeDecision(True, "network inside registered scope (exclusions applied by tool flags)", target)

        ip = self._resolve(host)
        if ip is None:
            return ScopeDecision(False, f"hostname '{host}' does not resolve", target)
        if self._excluded(host, ip):
            return ScopeDecision(False, f"{host} ({ip}) is explicitly excluded", target, ip)
        ipa = ipaddress.ip_address(ip)
        if not self.allow_non_private and not (ipa.is_private or ipa.is_loopback):
            return ScopeDecision(False, f"{ip} is a public address; third-party/public systems are never tested", target, ip)
        in_scope = host in self.hostnames or any(ipa in n for n, _ in self.networks)
        if not in_scope:
            return ScopeDecision(False, f"{host} ({ip}) is not a registered target", target, ip)
        if port is not None and not any(a <= port <= b for a, b in self.ports):
            return ScopeDecision(False, f"port {port} is outside allowed_ports", target, ip)
        return ScopeDecision(True, "target is registered and not excluded", target, ip)

    def nmap_exclude_arg(self) -> list[str]:
        ex = [str(n) for n in self.excl_networks] + sorted(self.excl_hosts)
        return ["--exclude", ",".join(ex)] if ex else []

    def summary(self) -> dict:
        s = dict(self.scope)
        return s
