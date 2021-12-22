from .reader import RSASReader, TargetExcelReader
from .model import HostReportModel, VulnModel, TargetModel
from .db import MiddleLayer
import os
from .utils import concat_path, dedup
from docx import Document
from .utils import gadget_fill_cell, gadget_fill_cell_super, gadget_set_row_height
from tqdm import tqdm


class Builder:
    def __init__(self):
        self.ml = MiddleLayer()
        self.dh = DocHandler()

class TextBuilder(Builder):
    def build(self, project_name):
        pass

class BriefingTextBuilder(TextBuilder):
    def build(self, project_name):
        scan_count = len(self.ml.query_hosts_scan(project_name=project_name))
        targets_count = len(self.ml.query_artifact_TARGETS(project_name=project_name))
        scan_targets_count = len(self.ml.query_artifact_SCAN_TARGETS(project_name=project_name))
        scan_rate = scan_targets_count/targets_count
        vulns = self.ml.query_vulns(project_name=project_name)
        severities = [_[1] for _ in vulns]
        keys = ['high', 'middle', 'low']
        counts = [str(len(list(filter(lambda x: x==key, severities)))) for key in keys]
        msg = ''
        msg += 'RSAS OUTPUT HOSTS COUNT: {}\n'.format(str(scan_count))
        msg += 'TARGETS COUNT: {}\n'.format(str(targets_count))
        msg += 'SCANED TARGETS COUNT: {}\n'.format(str(scan_targets_count))
        msg += 'SCAN RATE: {}\n'.format(str(scan_rate))
        msg += 'VULN: \n  HIGH:{} MID:{} LOW:{}\n'.format(counts[0], counts[1], counts[2])
        self.dh.build_plain_txt(message=msg, filename='简报.txt', project_name=project_name)


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
        hanzi_mapper = {'high':'高危','middle':'中危','low':'低危'}
        severity_mapper = {'high':0,'middle':1,'low':2}
        records.sort(key=lambda x: severity_mapper[x[1]])
        records = [(_[0],_[2],hanzi_mapper[_[1]]) for _ in records]
        high_sum = len(list(filter(lambda x: x[1]=='高危', records)))
        mid_sum = len(list(filter(lambda x: x[1]=='中危', records)))
        low_sum = len(list(filter(lambda x: x[1]=='低危', records)))
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
    
    def build_plain_txt(self, message, filename, project_name, path_pattern='project/{}/out/'):
        with open(path_pattern.format(project_name)+filename,'w+') as f:
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
