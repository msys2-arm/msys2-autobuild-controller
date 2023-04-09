#!/usr/bin/env python


import re
import requests
from typing import List, Tuple, NamedTuple, Optional

import github.WorkflowRun


__all__ = ["PackageUpdate", "DepCycleList", "parse_schedule_job_log"]


class PackageUpdate(NamedTuple):
    pkgname: str
    repoversion: str
    updateversion: str


DepCycleList = List[Tuple[PackageUpdate, PackageUpdate]]

_GITHUB_LOG_TIMESTAMP_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z ', re.M)
_DEP_CYCLE_RE = re.compile(r'^##\[group\]Dependency Cycles \(\d+\)\s*$(.*?)^##\[endgroup\]\s*$', re.M | re.S)
_DEP_CYCLE_ENTRY_RE = re.compile(r'^(\S+) \[(\S+) -> (\S+)\]\s+<-->\s+(\S+) \[(\S+) -> (\S+)\]\s*$')


def parse_schedule_job_log(run: github.WorkflowRun.WorkflowRun) -> Optional[DepCycleList]:
    if run.status in ('in_progress', 'completed'):
        # TODO: create a WorkflowJob object and use PaginatedList?
        headers, jobs = run._requester.requestJsonAndCheck("GET", run.jobs_url)
        for job in jobs["jobs"]:
            if job["name"] == "schedule" and job["status"] in ('in_progress', 'completed'):
                for step in job["steps"]:
                    if step["name"] == "Check what we should run":
                        if step["status"] == "completed" and step["conclusion"] == "success":
                            ret = []
                            status, headers, log = run._requester.requestBlob("GET", job["url"] + "/logs")
                            # bah, pygithub didn't handle 302
                            if status == 302 and 'location' in headers:
                                resp = requests.get(headers["location"])
                                status = resp.status_code
                                headers = resp.headers
                                log = resp.text

                            log = _GITHUB_LOG_TIMESTAMP_RE.sub("", log)
                            match = _DEP_CYCLE_RE.search(log)
                            if match:
                                lines = match[1].strip().splitlines()
                                # skip header and linebelowheader
                                for line in lines[2:]:
                                    match = _DEP_CYCLE_ENTRY_RE.fullmatch(line)
                                    if match:
                                        groups = match.groups()
                                        ret.append((PackageUpdate._make(groups[:3]),
                                                    PackageUpdate._make(groups[3:])))
                            return ret
                        break  # the steps loop
                break  # the jobs loop
    return None
