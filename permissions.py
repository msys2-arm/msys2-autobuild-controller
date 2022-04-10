#!/usr/bin/env python

from enum import Flag, auto
from typing import NamedTuple, Dict, Optional

__all__ = ('Principal', 'AccessRights', 'AccessControlList')

class Principal(NamedTuple):
    type: str
    login: str

class AccessRights(Flag):
    NO_ACCESS = 0
    TRIGGER_RUN = auto()
    BREAK_CYCLES = auto()
    CLEAR_FAILURES = auto()
    CANCEL_RUN = auto()
    ALL_ACCESS = 0xFF

class AccessControlList(Dict[Principal, AccessRights]):
    # idiomatic usage would be if acl.check(principal, rights) == rights
    def check(self, principal: Principal, access_requested: AccessRights) -> Optional[AccessRights]:
        access_entry = self.get(principal)
        if access_entry is not None:
            access_entry &= access_requested
        return access_entry

    def grant(self, principal: Principal, access_rights: AccessRights) -> None:
        self.setdefault(principal, AccessRights.NO_ACCESS)
        self[principal] |= access_rights

    def revoke(self, principal: Principal, access_rights: AccessRights) -> None:
        self[principal] &= ~access_rights

    def remove(self, principal: Principal) -> None:
        del self[principal]

