from lxml import etree
import json
from .model import (HostReportModel, VulnModel, TargetModel)
from tqdm import tqdm
from openpyxl import Workbook
from openpyxl import load_workbook
from typing import List
from rich import print as pprint
import os
from .utils import ip_regex, concat_path,true_ip_regex

class RSASReader:
    def __init__(self):
        pass

    def read_all(self, host_file_path):
        files = os.listdir(host_file_path)
        files = list(filter(ip_regex.match, files))
        # print(files)
        res = []
        for _ in files:
            res.append(self.read(host_file_path=concat_path(host_file_path, _)))
        return res

    def read(self, host_file_path) -> HostReportModel:
        
        with open(host_file_path) as f:
            html_text = f.read()
        root = etree.HTML(html_text)
        
        ip = root.xpath(
            '//*[@id="content"]/div[2]/table[2]/tr/td[1]/table/tbody/tr[1]/td/text()')[0]
        os = root.xpath(
            '//*[@id="content"]/div[2]/table[2]/tr/td[1]/table/tbody/tr[2]/td/text()')[0]
        threat_score_str = root.xpath(
            '//*[@id="content"]/div[2]/table[2]/tr/td[3]/table/tbody/tr[3]/td/text()')[0]
        threat_score = float(threat_score_str.strip('分'))

        host = HostReportModel(ip=ip, os=os, threat_score=threat_score)

        vulns = []
        vuln_names = root.xpath(
            '//*[@id="vul_detail"]/table/tr/td/span/text()')
        vuln_names = list(map(str.strip, vuln_names))
        vuln_threat = root.xpath(
            '//*[@id="vul_detail"]/table/tr/td/span/@class')
        vuln_threat = list(map(lambda x: x.split('_')[2], vuln_threat))
        vulns = [VulnModel(name=_[0], severity=_[1])
                 for _ in list(zip(vuln_names, vuln_threat))]
        host.vulns = vulns
        # print(host)
        return host

class TRXReader:
    def __init__(self) -> None:
        pass

    def read_all(self, host_file_path):
        files = os.listdir(host_file_path)
        # print(files)
        res = []
        for _ in files:
            res.append(self.read(host_file_path=concat_path(host_file_path, _)))
        return res

    def read(self, host_file_path) -> HostReportModel:
        root = etree.HTML(open(host_file_path).read())

        ip = root.xpath('/html/body/div/div[2]/div[2]/div[2]/table/tr/td[1]/table/tbody/tr[1]/td/text()')[0]
        vulns = []

        elements = root.xpath("/html/body/div/div[6]/div/table/tbody/tr[contains(@class, 'vuln_middle')]")
        for _ in elements:
            vuln_name = _.xpath("td/span/text()")[0]
            vuln_class = _.xpath("td/span/@class")[0]
            class_severity_mapper = {
                'color-severity-1':'low',
                'color-severity-2':'middle',
                'color-severity-3':'high'
            }
            vuln_severity = class_severity_mapper[vuln_class]
            vulns.append(VulnModel(name=vuln_name, severity=vuln_severity))

        from rich import print as pprint
        new_host = HostReportModel(
            ip=ip,
            os='',
            threat_score=0.0,
            vulns = vulns
        )
        return new_host


class TargetExcelReader:
    def __init__(self):
        pass

    def read(self, target_excel_path) -> List[TargetModel]:
        wb = load_workbook(filename=target_excel_path)
        sheets = list(wb)
        # only work when col size are not greater than 26.

        def count_col_size(sheet):
            int_a = ord('A')
            for i in range(256):
                if not sheet[chr(int_a+i)+'1'].value:
                    return i
        res = []
        for sheet in tqdm(sheets):
            col_size = count_col_size(sheet=sheet)
            fields = [sheet[chr(65+i)+'1'].value for i in range(col_size)]
            row_i = 2
            records = []
            while sheet['A'+str(row_i)].value:
                values = [
                    sheet[chr(65+i)+str(row_i)].value for i in range(col_size)]
                records.append(dict(zip(fields, values)))
                row_i += 1
            records = self.formalize_records(records)
            res.extend(records)
        return [TargetModel(**_) for _ in res]

    def formalize_records(self, records) -> list:
        raw_fields = list(records[0])
        keyword_pairs = self.formalize_mapper(raw_fields)
        res = []
        for record in records:
            _ = {}
            for key in list(keyword_pairs):
                _[key] = record[keyword_pairs[key]]
            res.append(_)
        records = res
        for record in records:
            for key in list(record):
                if not record[key]:
                    record[key] = 'NoValue'
            if not true_ip_regex.match(record['ip']):
                record['ip'] = 'NotAnIP'
        res = records
        return res

    def formalize_mapper(self, raw_fileds) -> dict:
        res = {}
        def keywords_in_any(keywords: list, names):
            for name in names:
                for keyword in keywords:
                    if keyword in name:
                        return name
            return None
        names = raw_fileds
        res['name'] = keywords_in_any(['名称','名'], names)
        res['ip'] = keywords_in_any(['IP','ip','Ip'], names)
        if name:= keywords_in_any(['区域'], names):
            res['area'] = name
        return res



