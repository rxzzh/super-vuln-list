from model import HostReportModel, TargetModel
from typing import List
class Filter:
    def __init__(self):
        pass

class FilterPlugin:
    def __init__(self):
        pass

    def next_plugin(self, plugin):
        pass

    def run(self):
        pass

class SelectTargetByKeywordFilterPlugin(FilterPlugin):
    def __init__(self):
        pass

class SelectHostByVulnByKeywordFilterPlugin(FilterPlugin):
    def __init__(self):
        pass

class SelectHostByVulnBySeverityFilterPlugin(FilterPlugin):
    def __init__(self):
        pass

class ReverseSelectFilterPlugin(FilterPlugin):
    def __init__(self):
        pass

class StaticFilter:
    def __init__(self, hosts: List[HostReportModel], targets: List[TargetModel]):
        self.hosts = hosts
        self.targets = targets
    
    def run(self) -> (List[HostReportModel], List[TargetModel]):
        return None

class SelectHostByTargetsStaticFilter(StaticFilter):
    def run(self) -> (List[HostReportModel], List[TargetModel]):
        res_hosts = []
        targets_ip = [_.ip for _ in self.targets]
        for host in self.hosts:
            if host.ip in targets_ip:
                res_hosts.append(host)
        return res_hosts, self.targets

class SelectTargetByDedupValidIPStaticFilter(StaticFilter):
    def run(self) -> (List[HostReportModel], List[TargetModel]):
        res_targets = []
        added = []
        for target in self.targets:
            if target.ip not in added and not target.ip == 'NotAnIP': 
                res_targets.append(target)
                added.append(target.ip)
        return self.hosts, res_targets

class SelectTargetByHostStaticFilter(StaticFilter):
    def run(self) ->  (List[HostReportModel], List[TargetModel]):
        res_targets = []
        added = []
        scanned_ip = [_.ip for _ in self.hosts]
        for target in self.targets:
            if target.ip in scanned_ip:
                res_targets.append(target)
        return self.hosts, res_targets
        