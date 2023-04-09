#!/usr/bin/env python

from typing import Dict

import github
from github import Github, GithubIntegration

from permissions import Principal


__all__ = ["get_installations"]


def get_installations(githubintegration: GithubIntegration) -> Dict[Principal, int]:
    ret = {}
    gh = Github(jwt=githubintegration.create_jwt())
    ghapp = gh.get_app()
    installations = github.PaginatedList.PaginatedList(github.Installation.Installation, ghapp._requester, '/app/installations', None)
    for installation in installations:
        account = installation._rawData['account']
        ret[Principal(account['type'], account['login'])] = installation.id
    return ret
