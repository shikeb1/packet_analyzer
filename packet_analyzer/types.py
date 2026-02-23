from enum import Enum, auto
from dataclasses import dataclass
from typing import Optional

class AppType(Enum):
    UNKNOWN = auto()
    HTTP = auto()
    HTTPS = auto()
    DNS = auto()
    GOOGLE = auto()
    YOUTUBE = auto()
    FACEBOOK = auto()
    # Add more as needed

@dataclass
class FiveTuple:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int   # 6=TCP, 17=UDP

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))

@dataclass
class Flow:
    five_tuple: FiveTuple
    app_type: AppType = AppType.UNKNOWN
    sni: Optional[str] = None
    blocked: bool = False
    packets: list = None

    def __post_init__(self):
        if self.packets is None:
            self.packets = []