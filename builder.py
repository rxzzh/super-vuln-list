from model import TargetModel, VulnModel, HostReportModel
from typing import List
from utils import gadget_fill_cell, doc_add_comment
from docx import Document
from tqdm import tqdm
from utils import gadget_fill_cell_super, gadget_set_row_height

class Builder:
    def config_template(self, template_path):
        self.template_path = template_path
    
    def config_output_path(self, output_path):
        self.output_path = output_path

    def send_to_doc_handler(self, records):
        dh = DocHandler()
        dh.build_doc_tablelike(records=records, template_path=self.template_path, output_path=self.output_path)

class SubtotalTableBuilder(Builder):
    def __init__(self):
        self.config_output_path('dev.docx')

    def build(self, hosts: List[HostReportModel]) -> None:
        pass
        total_high = 0
        total_mid = 0
        total_low = 0
        records = []
        id_ = 1
        for host in hosts:
            vulns = host.vulns
            keys = ['high', 'middle', 'low']
            vulns_by_severity = dict(
                zip(keys, [list(filter(lambda x: x.severity == key, vulns)) for key in keys]))
            count_high = len(vulns_by_severity['high'])
            count_mid = len(vulns_by_severity['middle'])
            count_low = len(vulns_by_severity['low'])
            total_high += count_high
            total_mid += count_mid
            total_low += count_low
            records.append([str(id_),host.ip, str(count_low), str(
                count_mid), str(count_high), str(count_high+count_mid+count_low)])
            id_ += 1
        records.append(['安全漏洞数量小计', '', total_low, total_mid,
                        total_high, total_low+total_mid+total_high])
        dh = DocHandler()
        self.config_template(template_path='static/template-subtotal.docx')
        self.send_to_doc_handler(records=records)
        return 'VULN INSTANCE COUNT: HIGH:{}\tMID:{}\tLOW:{}\tSUM:{}'.format(total_high, total_mid, total_low,  total_low+total_mid+total_high)


class VulnTableBuilder(Builder):
    def __init__(self):
        self.config_output_path('dev.docx')

    def build(self, hosts: List[HostReportModel]) -> None:
        class VulnWithHostModel(VulnModel):
            ip: str
        vulns = []
        for host in hosts:
            for vuln in host.vulns:
                vulns.append(VulnWithHostModel(**dict(vuln), ip=host.ip))
        severity_map = {'high': 2, 'middle': 1, 'low': 0}
        vulns.sort(key=lambda x: severity_map[x.severity], reverse=True)
        records = {}
        id_ = 1
        for vuln in vulns:
            if vuln.name not in records:
                records[vuln.name] = {
                    'id': str(id_), 'name': vuln.name, 'severity': vuln.severity, 'hosts': []}
                id_ += 1
            records[vuln.name]['hosts'].append(vuln.ip)

        def ip_to_int(ip: str) -> int:
            pcs = ip.split('.')
            return int(pcs[0])*255*255*255+int(pcs[1])*255*255+int(pcs[2])*255+int(pcs[3])
        for record in records:
            records[record]['hosts'].sort(key=ip_to_int)
        dh = DocHandler()
        dh_records = []
        for key in list(records):
            record = records[key]
            convert = {'high': '高', 'middle': '中', 'low': '低'}
            dh_records.append([record['id'], record['name'],
                               convert[record['severity']], ','.join(record['hosts'])])
        message = 'VLUN TYPE COUNT: HIGH:{}\tMID:{}\tLOW:{}\tSUM:{}'.format(len(list(filter(lambda x: x[2]=='高', dh_records))), len(list(filter(lambda x: x[2]=='中', dh_records))),len(list(filter(lambda x: x[2]=='低', dh_records))),len(dh_records))
        dh_records.append(['', message])
        self.config_template(template_path='static/template-vulnlist.docx')
        self.send_to_doc_handler(records=dh_records)
        return message

class BriefingBuilder(Builder):
    def __init__(self):
        self.config_output_path('dev.docx')

    def build(self, message: str) -> None:
        dh = DocHandler()
        dh.build_plain_txt(message=message, output_path=self.output_path)


class TargetTableBuilder(Builder):
    def __init__(self):
        self.config_output_path('dev.docx')

    def build(self, targets: List[TargetModel]) -> None:
        id_ = 1
        records = []
        for target in targets:
            records.append([id_, target.name, target.ip])
            id_ += 1
        dh = DocHandler()
        self.config_template(template_path='static/template-scan-target.docx')
        self.send_to_doc_handler(records=records)


class DocHandler:
    def __init__(self):
        pass
    
    def build_plain_txt(self, message, output_path='dev.txt'):
        with open(output_path,'w+') as f:
            f.write(message)

    def build_doc_tablelike(self, records, template_path, output_path='dev.docx'):
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
        doc.save(output_path)

# if True:
#     from reader import RSASReader
#     rsasr = RSASReader()
#     rsasr.read(host_file_path=)