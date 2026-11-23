import os
import socket as _socket

from dataclasses import dataclass, field
from typing import Dict, List

_CFPROXY_ENC: List[str] = [
    'virkgj.com', 
    'vmmzovy.com', 
    'mkuosckvso.com', 
    'zaewayzmplad.com', 
    'twdmbzcm.com',
    'awzwsldi.com',
    'clngqrflngqin.com',
    'tjacxbqtj.com',
    'bxaxtxmrw.com',
    'dmohrsgmohcrwb.com',
    'vwbmtmoi.com',
    'khgrre.com',
    'ulihssf.com',
    'tmhqsdqmfpmk.com',
    'xwuwoqbm.com',
    'orgcnunpj.com',
    'zhkuldz.com',
    'zypoljnslxa.com',
    'efabnxaowuzs.com',
    'zaftuzsftqdq.com'
]
_S = ''.join(chr(c) for c in (46, 99, 111, 46, 117, 107))


def _dd(s: str) -> str:
    """Only for decoding CF proxy domains"""
    if not s[-4:] == '.com':
        return s
    p, n = s[:-4], sum(c.isalpha() for c in s[:-4])
    return ''.join(
        chr((ord(c) - (97 if c > '`' else 65) - n) % 26 + (97 if c > '`' else 65))
        if c.isalpha() else c for c in p
    ) + _S


CFPROXY_DEFAULT_DOMAINS: List[str] = [_dd(d) for d in _CFPROXY_ENC]


@dataclass
class ProxyConfig:
    port: int = 1443
    host: str = '127.0.0.1'
    secret: str = field(default_factory=lambda: os.urandom(16).hex())
    dc_redirects: Dict[int, str] = field(default_factory=dict)
    buffer_size: int = 256 * 1024
    pool_size: int = 4
    fallback_cfproxy: bool = True
    fallback_cfproxy_priority: bool = True
    cfproxy_user_domains: List[str] = field(default_factory=list)
    cfproxy_worker_domains: List[str] = field(default_factory=list)
    cfproxy_h2_media: bool = True
    disable_secure: bool = False
    fake_tls_domain: str = ''
    proxy_protocol: bool = False
    force_test_dc: bool = False
    active_cfproxy_domain: str = ''  

    @property
    def h2_enabled(self) -> bool:
        return (self.cfproxy_h2_media and self.fallback_cfproxy
                and not self.disable_secure and not self.force_test_dc)


proxy_config = ProxyConfig()


def parse_dc_ip_list(dc_ip_list: List[str]) -> Dict[int, str]:
    dc_redirects: Dict[int, str] = {}
    for entry in dc_ip_list:
        if ':' not in entry:
            err = ValueError(
                f"Invalid --dc-ip format {entry!r}, expected DC:IP")
            err.entry = entry
            err.kind = "format"
            raise err
        dc_s, ip_s = entry.split(':', 1)
        try:
            dc_n = int(dc_s)
            _socket.inet_pton(_socket.AF_INET, ip_s)
        except (ValueError, OSError):
            err = ValueError(f"Invalid --dc-ip {entry!r}")
            err.entry = entry
            err.kind = "invalid"
            raise err from None
        dc_redirects[dc_n] = ip_s
    return dc_redirects