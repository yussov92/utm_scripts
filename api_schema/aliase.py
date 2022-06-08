# хендлеры для алиасов и схемы API
from dataclasses import dataclass
from typing import Any, Dict, List, Union

PORT_HANDLER = '/aliases/ports'
RANGE_PORT_HANDLER = '/aliases/port_ranges'
PORT_LIST = '/aliases/lists/ports'
IP_HANDLER = '/aliases/ip_addresses'
RANGE_IP_HANDLER = '/aliases/ip_ranges'
NETWORK_HANDLER = '/aliases/networks'
DOMAIN_HANDLER = '/aliases/domains'
IP_LIST_HANDLER = '/aliases/lists/addresses'


@dataclass(frozen=True)
class Aliase:
    title: str
    comment: str
    value: Union[int, str]


@dataclass(frozen=True)
class AliaseRange:
    title: str
    comment: str
    start: Union[int, str]
    end: Union[int, str]


@dataclass(frozen=True)
class AliaseList:
    title: str
    comment: str
    values: List[str]


aliase_schema: Dict[str, Any] = {
    'aliase': Aliase,
    'aliase_range': AliaseRange,
    'aliase_list': AliaseList,
}
