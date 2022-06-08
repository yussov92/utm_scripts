# хендлеры для файрвола и схемы API
from dataclasses import dataclass
from typing import Any, Dict, List

FIREWALL_HANDLER = '/firewall/settings'
FIREWALL_STATE = '/firewall/state'
FIREWALL_STATUS = '/firewall/status'
FIREWALL_WATCH = '/firewall/watch'
FORWARD_HANDLER = '/firewall/rules/forward'
DNAT_HANDLER = '/firewall/rules/dnat'
INPUT_HANDLER = '/firewall/rules/input'
SNAT_HANDLER = '/firewall/rules/snat'


@dataclass(frozen=True)
class SnatSettings:
    automatic_snat_enabled: bool


@dataclass(frozen=True)
class FirewallAddForward:
    action: str
    comment: str
    destination_addresses: List[str]
    destination_ports: List[str]
    incoming_interface: str
    outgoing_interface: str
    protocol: str
    source_addresses: List[str]
    timetable: List[str]
    enabled: bool


@dataclass(frozen=True)
class FirewallAddDnat:
    action: str
    change_destination_address: str
    change_destination_port: str
    comment: str
    destination_addresses: List[str]
    destination_ports: List[str]
    incoming_interface: str
    protocol: str
    source_addresses: List[str]
    timetable: List[str]
    enabled: bool


@dataclass(frozen=True)
class FirewallAddInput:
    action: str
    comment: str
    destination_addresses: List[str]
    destination_ports: List[str]
    incoming_interface: str
    outgoing_interface: str
    protocol: str
    source_addresses: List[str]
    timetable: List[str]
    enabled: bool


@dataclass(frozen=True)
class FirewallAddSnat:
    action: str
    comment: str
    destination_addresses: List[str]
    destination_ports: List[str]
    outgoing_interface: str
    protocol: str
    change_source_address: str
    source_addresses: List[str]
    timetable: List[str]
    enabled: bool


firewall_schema: Dict[str, Any] = {
    'firewall_autosnat': SnatSettings,
    'firewall_forward': FirewallAddForward,
    'firewall_dnat': FirewallAddDnat,
    'firewall_input': FirewallAddInput,
    'firewall_snat': FirewallAddSnat,
}
