#!/usr/bin/env python

import re

__all__ = (
    'validate_optional_deps',
    'validate_clear_failed_build_types',
    'validate_clear_failed_packages',
)

_PKGNAME_RE = re.compile(r'^(?![.-])[A-Za-z0-9+_.@-]+$', re.A)
# could enumerate all the currently known BuildTypes, but this is probably good
# enough
_BUILDTYPE_RE = re.compile(r'^[a-z]+(?:-src|32|64)?$', re.A)


def validate_optional_deps(optional_deps: str) -> str:
    optional_deps = optional_deps.replace(' ', '')
    if not optional_deps:
        return optional_deps

    for entry in optional_deps.split(','):
        if ':' not in entry:
            raise ValueError(f"Malformed optional_deps entry: '{entry}'")
        first, second = entry.split(':', 2)
        if not _PKGNAME_RE.fullmatch(first):
            raise ValueError(f"Malformed optional_deps pkgname: '{first}'")
        if not _PKGNAME_RE.fullmatch(second):
            raise ValueError(f"Malformed optional_deps pkgname: '{second}'")

    return optional_deps


def validate_clear_failed_build_types(clear_failed_build_types: str) -> str:
    clear_failed_build_types = clear_failed_build_types.replace(' ', '')
    for entry in clear_failed_build_types.split(','):
        if not _BUILDTYPE_RE.fullmatch(entry):
            raise ValueError(f"Malformed clear_failed_build_types entry: '{entry}'")
    return clear_failed_build_types


def validate_clear_failed_packages(clear_failed_packages: str) -> str:
    clear_failed_packages = clear_failed_packages.replace(' ', '')
    for entry in clear_failed_packages.split(','):
        if not _PKGNAME_RE.fullmatch(entry):
            raise ValueError(f"Malformed clear_failed_packages entry: '{entry}'")
    return clear_failed_packages
