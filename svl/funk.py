from os import lseek, name
from svl.db import MiddleLayer, SchemaManager
from lxml import etree
from svl.model import VulnModel
from pydantic import BaseModel
import re

from .builder import VulnTableBuilder, SubtotalTableBuilder


class HostModel(BaseModel):
    ip: str
    project_name: str


class HostVulnRelation(BaseModel):
    host_ip: str
    vuln_name: str


ml = MiddleLayer()
sm = SchemaManager()


class IndexReader():
    def __init__(self) -> None:
        pass

    def read_and_dump(self, path: str, project_name=str) -> None:
        root = etree.HTML(open(path).read())
        vuln_names = [_.lstrip().rstrip() for _ in root.xpath(
            '//*[@id="vuln_distribution"]/tbody/tr/td/span/text()')]
        if vuln_names:
            tmp_regex = re.compile(r'_(low|middle|high).gif')
            vuln_severity = root.xpath(
                '//*[@id="vuln_distribution"]/tbody/tr/td/img[2]/@src')
            vuln_severity = [tmp_regex.search(_).group(1) for _ in vuln_severity]
            
        else:
            print('entering subroutine vuln')
            vuln_names = [_.lstrip().rstrip() for _ in root.xpath(
            '//*[@id="vulDataTable"]/tbody/tr/td[1]/a/text()')]
            print(vuln_names)
            vuln_severity = root.xpath('//*[@id="vulDataTable"]/tbody/tr/td[1]/img[2]/@src')
            tmp_regex = re.compile(r'v([a-z])\.gif')
            mapping = {'h':'high','m':'middle','l':'low'}
            vuln_severity = [mapping[tmp_regex.search(_).group(1)] for _ in vuln_severity]
            print(vuln_severity)
        vulns = [VulnModel(name=vuln_names[i], severity=vuln_severity[i])
            for i in range(len(vuln_names))]
        host_ips = root.xpath(
            '//*[@id="content"]/div[6]/div[2]/table/tbody/tr/td[1]/text()')
        if not host_ips:
            host_ips = root.xpath(
                '//*[@id="content"]/div[6]/div[2]/table/tbody/tr/td/a/text()')
        if not host_ips:
            print('hostip')
            host_ips = root.xpath(
                '//*[@id="ipList"]/table/tr/td[1]/a/text()'
            )
            print(host_ips)
        hosts = [HostModel(ip=_, project_name=project_name) for _ in host_ips]
        # print(vulns)
        # print(hosts)
        ips_list = []
        
        # for some shitty old format of report. i hope never uncomment this block of code again.
        # for i in range(len(vuln_names)):
        #     ips = root.xpath(('//*[@id="vulDataTable"]/tbody/tr[{}]/td/table/tr[1]/td[2]/a/text()').format((i+1)*2))
        #     print(ips)
        #     ips_list.append(ips)
        
        for i in range(len(vuln_names)):
            ips = root.xpath(
                '//*[@id="vuln_distribution"]/tbody/tr[{}]/td/table/tr[1]/td/text()'.format((i+1)*2))
            ips = root.xpath(
                '//*[@id="vulDataTable"]/tbody/tr[{}]/td/table/tr[1]/td[2]/a/text()'.format((i+1)*2)
            )
            print('alpha:',ips)
            if ips:
                ips = ips[0]
            print(ips)
            if ips == ';&nbsp':
                print('entering subroutine')
                ips = root.xpath(
                    ('//*[@id="vuln_distribution"]/tbody/tr[{}]/td/table/tr[1]/td/a/text()').format((i+1)*2))
                ips = [_.lstrip().rstrip() for _ in ips]
                regex = re.compile(r'(\d+\.){3}\d+')
                ips = list(filter(lambda x: regex.match(x), ips))
                print(ips)
            else:
                ips = ips.split(';&nbsp')
                ips = [_.lstrip().rstrip() for _ in ips]
                ips = list(filter(lambda x: x, ips))
            ips_list.append(ips)
        print(vulns)
        print(hosts)
        print(ips_list)
        hvrs = []
        for i in range(len(vulns)):
            for ip in ips_list[i]:
                hvrs.append(HostVulnRelation(
                    host_ip=ip, vuln_name=vulns[i].name))
        sm.reset_database()
        ml.insert_project(project_name=project_name)
        for vuln in vulns:
            ml.insert_vuln(name=vuln.name, severity=vuln.severity)
        for host in hosts:
            ml.insert_host(ip=host.ip, project_name=project_name)
        for hvr in hvrs:
            ml.insert_host_vuln(project_name=project_name,
                                host_ip=hvr.host_ip, vuln_name=hvr.vuln_name)
        VulnTableBuilder().build(project_name=project_name)
        SubtotalTableBuilder().build(project_name=project_name)



if __name__ == '__main__':
    ir = IndexReader()
    ir.read_and_dump('tmp/index.html', project_name='devvv')
