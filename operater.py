from reader import RSASReader, TargetExcelReader
from model import HostReportModel, VulnModel, TargetModel
from db import MiddleLayer
import os
from utils import concat_path, dedup
from docx import Document
from utils import gadget_fill_cell, gadget_fill_cell_super, gadget_set_row_height
from tqdm import tqdm
class Main:
    def __init__(self):
        pass

    def load_project_into_db(self, project_name):
        xlsx_filename = os.listdir('project/{}/targets_xlsx/'.format(project_name))[0]
        targets = TargetExcelReader().read(target_excel_path='project/{}/targets_xlsx/{}'.format(project_name, xlsx_filename))
        hosts = RSASReader().read_all(host_file_path='project/{}/hosts/'.format(project_name))

        targets = dedup(records=targets, func=lambda x: x.ip)

        dbl = DBLoader(project_name=project_name)
        dbl.load_project()
        dbl.load_target(targets=targets)
        dbl.load_host(hosts=hosts)
        dbl.load_vuln_from_host(hosts=hosts)
        dbl.load_host_vuln(hosts=hosts)
    
class Builder:
    def __init__(self):
        self.ml = MiddleLayer()
        self.dh = DocHandler()

class TableBuilder(Builder):
    def build(self, project_name):
        pass

    def query(self, project_name):
        pass

    def prefix_id(self, records):
        i = 1
        new_records = []
        for _ in records:
            new_records.append((i,)+_)
            i+=1
        return new_records
    
    def count(self, records, key):
        return len(list(filter(key, records)))

class SubtotalTableBuilder(TableBuilder):
    def build(self, project_name):
        records = self.query(project_name=project_name)
        records = [(_[0], _[1], _[2], _[3], _[4]) for _ in records]
        # def select()
        records.append(('漏洞数量合计',sum([_[1] for _ in records]),sum([_[2] for _ in records]),sum([_[3] for _ in records]),sum([_[4] for _ in records])))
        self.dh.build_doc_tablelike(records=self.prefix_id(records), template_path='static/template-subtotal.docx', filename='数量统计.docx', project_name=project_name)
    
    def query(self, project_name):
        return self.ml.query_artifact_VULN_COUNT(project_name=project_name)

class TargetTableBuilder(TableBuilder):
    def build(self, project_name):
        records = self.query(project_name)
        self.dh.build_doc_tablelike(records=self.prefix_id(records), template_path='static/template-scan-target.docx', filename='已扫资产表格.docx', project_name=project_name)

    def query(self, project_name):
        return self.ml.query_artifact_SCAN_TARGETS(project_name=project_name)

class AllTargetTableBuilder(TableBuilder):
    def build(self, project_name):
        records = self.query(project_name)
        self.dh.build_doc_tablelike(records=self.prefix_id(records), template_path='static/template-scan-target.docx', filename='所有资产表格.docx', project_name=project_name)

    def query(self, project_name):
        return self.ml.query_artifact_TARGETS(project_name=project_name)

class VulnTableBuilder(TableBuilder):
    def build(self, project_name):
        records = self.query(project_name=project_name)
        names = {}
        for record in records:
            if record[0] not in names:
                names[record[0]] = (record[0], record[1], [])
            # print(record)
            names[record[0]][2].append(record[2])
        records = [(_[0],_[1],','.join(_[2])) for _ in names.values()]
        hanzi_mapper = {'high':'高','middle':'中','low':'低'}
        severity_mapper = {'high':0,'middle':1,'low':2}
        records.sort(key=lambda x: severity_mapper[x[1]])
        records = [(_[0],hanzi_mapper[_[1]],_[2]) for _ in records]
        high_sum = len(list(filter(lambda x: x[1]=='高', records)))
        mid_sum = len(list(filter(lambda x: x[1]=='中', records)))
        low_sum = len(list(filter(lambda x: x[1]=='低', records)))
        records.append(('高：{}\t中：{}\t低：{}'.format(high_sum, mid_sum, low_sum),'',''))
        self.dh.build_doc_tablelike(records=self.prefix_id(records), template_path='static/template-vulnlist.docx', filename='漏洞类型.docx', project_name=project_name)

    def query(self, project_name):
        return self.ml.query_artifact_VULN_TYPE(project_name=project_name)

class CompareTableBuilder(TableBuilder):

    def build(self, project_name_a, project_name_b):
        def get_records(project_name):
            records = self.query(project_name=project_name)
            names = {}
            for record in records:
                if record[0] not in names:
                    names[record[0]] = (record[0], record[1], [])
                # print(record)
                names[record[0]][2].append(record[2])
            records = [(_[0],_[1],','.join(_[2]),_[2]) for _ in names.values()]
            hanzi_mapper = {'high':'高','middle':'中','low':'低'}
            severity_mapper = {'high':0,'middle':1,'low':2}
            records.sort(key=lambda x: severity_mapper[x[1]])
            # records = [(_[0],hanzi_mapper[_[1]],_[2]) for _ in records]
            return records
        records_a = get_records(project_name=project_name_a)
        records_b = get_records(project_name=project_name_b)
        names = [_[0] for _ in records_a+records_b]
        records_a = dict(zip([_[0] for _ in records_a], records_a))
        records_b = dict(zip([_[0] for _ in records_b], records_b))
        names = list(set(names))
        res = []
        for name in names:
            severity = records_a[name][1] if name in records_a else records_b[name][1]
            ip_str_a = records_a[name][2] if name in records_a else '--'
            ip_str_b = records_b[name][2] if name in records_b else '--'
            ip_a = records_a[name][3] if name in records_a else []
            ip_b = records_b[name][3] if name in records_b else []
            ip_a = set(ip_a)
            ip_b = set(ip_b)
            def judge(old:set, new:set):
                if len(new)==0:
                    return '已整改'
                if new.issubset(old) and len(new)>len(old):
                    return '部分整改'
                return '未整改'
            judge_result = judge(old=ip_a, new=ip_b)
            hanzi_mapper = {'high':'高','middle':'中','low':'低'}
            new_res = (name, hanzi_mapper[severity], ip_str_a, ip_str_b, judge_result)
            res.append(new_res)
        
        severity_mapper = {'高':0,'中':1,'低':2}
        res = sorted(res, key=lambda x: (severity_mapper[x[1]],x[0]))
        self.dh.build_doc_tablelike(records=self.prefix_id(res), template_path='static/template-compare.docx', filename='前后对比-{}-{}.docx'.format(project_name_a, project_name_b), project_name=project_name_b)

    def query(self, project_name):
        return self.ml.query_artifact_VULN_TYPE(project_name=project_name)


class DocHandler:
    def __init__(self):
        pass
    
    def build_plain_txt(self, message, output_path='dev.txt'):
        with open(output_path,'w+') as f:
            f.write(message)

    def build_doc_tablelike(self, records, template_path, filename, project_name, path_pattern='project/{}/out/'):
        doc = Document(template_path)
        table = doc.tables[0]
        ROWS = len(records)
        HEAD_ROWS = len(table.rows)
        for i in range(ROWS):
            new_row = table.add_row()
        gadget_set_row_height(rows=table.rows[HEAD_ROWS:])
        COLUMNS = len(new_row.cells)
        cells = table._cells
        cells = cells[HEAD_ROWS*COLUMNS:]
        # print(cells)
        for i in tqdm(range(len(records))):
            gadget_fill_cell_super(cells=cells[i*COLUMNS:(i+1)*COLUMNS], fields=records[i])
        doc.save(path_pattern.format(project_name)+filename)
from tqdm import tqdm
class DBLoader:
    def __init__(self, project_name):
        self.ml = MiddleLayer()
        self.project_name = project_name

    def load_project(self):
        self.ml.insert_project(project_name=self.project_name)
    
    def load_target(self, targets):
        for record in tqdm(targets):
            self.ml.insert_target(project_name=self.project_name,name=record.name,ip=record.ip)
    
    def load_host(self, hosts):
        for record in tqdm(hosts):
            self.ml.insert_host(ip=record.ip, project_name=self.project_name)
    
    def load_vuln_from_host(self, hosts):
        vulns = []
        for host in hosts:
            vulns.extend(host.vulns)
        uniq_vulns = []
        names = []
        for record in tqdm(vulns):
            if record.name not in names:
                names.append(record.name)
                uniq_vulns.append(record)
        self.load_vuln(vulns=uniq_vulns)

    def load_vuln(self, vulns):
        exsist_vulns = self.ml.query_all_vulns()
        names = [_[0] for _ in exsist_vulns]
        for record in tqdm(vulns):
            if record.name not in names:
                self.ml.insert_vuln(name=record.name, severity=record.severity)
    
    def load_host_vuln(self, hosts):
        for record in tqdm(hosts):
            self.ml.update_host_scan_state(project_name=self.project_name, host_ip=record.ip)
            host_ip = record.ip
            vulns = record.vulns
            for vuln in vulns:
                self.ml.insert_host_vuln(project_name=self.project_name, host_ip=host_ip, vuln_name=vuln.name)

from db import SchemaManager


# dh = DocHandler()
# from db import MiddleLayer
# ml = MiddleLayer()
# dh.build_doc_tablelike(records=ml.query_artifact_VULN_COUNT(project_name='dev'), template_path='static/template-subtotal.docx', filename='dev.docx', project_name='dev')
# ml.query_hosts_scan(project_name='dev')






# m.load_project_into_db(project_name='dev0')

project_name = 'up3'
# sm = SchemaManager()
# sm.reset_database()
m = Main()
import profile
# profile.run('m.load_project_into_db(project_name=project_name)')

VulnTableBuilder().build(project_name=project_name)
SubtotalTableBuilder().build(project_name=project_name)
TargetTableBuilder().build(project_name=project_name)
AllTargetTableBuilder().build(project_name=project_name)
CompareTableBuilder().build(project_name_a='up0', project_name_b='up3')
# stb = SubtotalTableBuilder()
# stb.build(project_name='dev')
# vtb = VulnTableBuilder()
# vtb.build(project_name='dev')

# res = MiddleLayer().query_artifact_SCAN_TARGETS(project_name='dev').fetchall()
# from rich import print
# print(res)
# print(len(res))
