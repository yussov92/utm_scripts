from typing import Any, Dict, Optional
from dataclasses import dataclass

CREATE_USER_HANDLER = '/user_backend/create_user'
USER_IP_MAC_AUTH = '/auth/rules'


@dataclass(frozen=True)
class UsersCreateUser:
    parent_id: int
    name: str
    login: str
    psw: str


@dataclass(frozen=True)
class UserIPMACAuth:
    always_logged: bool
    comment: str
    enabled: bool
    ip: Optional[str]
    mac: Optional[str]
    user_id: int


users_schema: Dict[str, Any] = {
    'create_user': UsersCreateUser,
    'user_ip_mac_auth': UserIPMACAuth,
}
