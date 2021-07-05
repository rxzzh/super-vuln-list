from model import TargetModel, VulnModel, HostReportModel
from typing import List
from utils import gadget_fill_cell, doc_add_comment
from docx import Document
from tqdm import tqdm
from utils import gadget_fill_cell_super, gadget_set_row_height
from typing import Optional

class Builder:
    def config_template(self, template_path):
        self.template_path = template_path
    
    def config_output_path(self, output_path):
        self.output_path = output_path

    def send_to_doc_handler(self, records):
        dh = DocHandler()
        dh.build_doc_tablelike(records=records, template_path=self.template_path, output_path=self.output_path)

class CompareTableBuilder(Builder):
    def __init__(self):
        self.config_output_path('dev-compare.docx')
    
    def build(self, hosts_0: List[HostReportModel], hosts_1: List[HostReportModel]) -> None:
        class ThisVulnModel(VulnModel):
            unfix_ip: Optional[list]
            ip: list
            fixed: Optional[str]
        vulns_0 = {}
        vulns_1 = {}

        for host in hosts_0:
            for vuln in host.vulns:
                if vuln.name not in vulns_0:
                    vulns_0[vuln.name] = ThisVulnModel(**dict(vuln), ip=[])
                vulns_0[vuln.name].ip.append(host.ip)

        for host in hosts_1:
            for vuln in host.vulns:
                if vuln.name not in vulns_1:
                    vulns_1[vuln.name] = ThisVulnModel(**dict(vuln), ip=[])
                vulns_1[vuln.name].ip.append(host.ip)

        last_vulns = {}

        for vuln_name in vulns_0:
            if vuln_name not in vulns_1:
                last_vulns[vuln_name] = ThisVulnModel(**dict(vulns_0[vuln_name]))
                last_vulns[vuln_name].unfix_ip = []
                last_vulns[vuln_name].fixed = 'fixed'
            else:
                original_affected_ip = vulns_0[vuln_name].ip
                alternate_affected_ip = vulns_1[vuln_name].ip
                if set(original_affected_ip).issubset(set(alternate_affected_ip)):
                    last_vulns[vuln_name] = ThisVulnModel(**dict(vulns_0[vuln_name]))
                    last_vulns[vuln_name].unfix_ip = alternate_affected_ip
                    last_vulns[vuln_name].fixed = 'unfixed'
                else:
                    last_vulns[vuln_name] = ThisVulnModel(**dict(vulns_0[vuln_name]))
                    last_vulns[vuln_name].unfix_ip = alternate_affected_ip
                    last_vulns[vuln_name].fixed = 'partly fixed'
        for vuln_name in vulns_1:
            if vuln_name not in list(vulns_0):
                # print('wow, new vuln{}'.format(vuln_name))
                last_vulns[vuln_name] = vulns_1[vuln_name]
                last_vulns[vuln_name].fixed = 'unfixed'
                last_vulns[vuln_name].unfix_ip = last_vulns[vuln_name].ip
                last_vulns[vuln_name].ip = []
        severity_map = {'high': 2, 'middle': 1, 'low': 0}
        fix_map = {'unfixed': 2, 'partly fixed':1, 'fixed': 0}
        # records.sort(key=lambda x: severity_map[x.severity])
        # for record in records:
        #     records[record]['hosts'].sort(key=ip_to_int)
        dh = DocHandler()
        dh_records = []
        records = last_vulns
        keys = list(records)
        keys.sort(key=lambda x: (severity_map[records[x].severity],fix_map[records[x].fixed]), reverse=True)
        def ip_to_int(ip: str) -> int:
            pcs = ip.split('.')
            return int(pcs[0])*255*255*255+int(pcs[1])*255*255+int(pcs[2])*255+int(pcs[3])
        id_ = 1
        for key in keys:
            record = records[key]
            record.ip.sort(key=ip_to_int)
            record.unfix_ip.sort(key=ip_to_int)
            convert = {'high': '高', 'middle': '中', 'low': '低'}
            convert_change = {'fixed':'已整改','unfixed':'未整改','partly fixed':'部分整改 '}
            dh_records.append([id_, record.name,
                               convert[record.severity], ','.join(record.ip) if record.ip else '--', convert_change[record.fixed], ','.join(record.unfix_ip) if record.unfix_ip else '--'])
            id_ += 1
        message = 'VLUN TYPE COUNT: HIGH:{}\tMID:{}\tLOW:{}\tSUM:{}'.format(len(list(filter(lambda x: x[2]=='高', dh_records))), len(list(filter(lambda x: x[2]=='中', dh_records))),len(list(filter(lambda x: x[2]=='低', dh_records))),len(dh_records))
        fix_count = [len(list(filter(lambda x: x.fixed==_, records.values()))) for _ in ['fixed','unfixed','partly fixed']]
        message += '\nFIX COUNT: FIXED:{}\tUNFIXED:{}\tPARTLY FIXED:{}'.format(fix_count[0], fix_count[1], fix_count[2])
        records_value = [records[_] for _ in list(records)]
        high_fix = len(list(filter(lambda x: x.fixed=='fixed' and x.severity=='high', records_value)))
        mid_fix = len(list(filter(lambda x: x.fixed=='fixed' and x.severity=='middle', records_value)))
        low_fix = len(list(filter(lambda x: x.fixed=='fixed' and x.severity=='low', records_value)))
        message += '\nFIXED: HIGH:{} MID:{} LOW:{}'.format(high_fix, mid_fix, low_fix)
        dh_records.append(['', message])
        self.config_template(template_path='static/template-vulnlist-custom.docx')
        self.send_to_doc_handler(records=dh_records)
        return message

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