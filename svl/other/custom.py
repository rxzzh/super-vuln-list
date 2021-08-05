from orchestra import Control

up0_c = Control(hosts_path='project/up0/hosts', targets_table_path='project/up0/targets_xlsx/properties.xlsx', output_path='project/up0/out')
up1_c = Control(hosts_path='project/up3/hosts', targets_table_path='project/up3/targets_xlsx/properties.xlsx', output_path='project/up3/out')

up0_c.do_filter_dev()
up1_c.do_filter_dev()

hosts_0 = up0_c.hosts
hosts_1 = up1_c.hosts

from model import VulnModel
from typing import Optional
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
from builder import VulnTableBuilder
# vtb = VulnTableBuilder()
from builder import DocHandler
class CustomVulnTableBuilder(VulnTableBuilder):
    def build(self, records) -> None:
        severity_map = {'high': 2, 'middle': 1, 'low': 0}
        fix_map = {'unfixed': 2, 'partly fixed':1, 'fixed': 0}
        # records.sort(key=lambda x: severity_map[x.severity])
        # for record in records:
        #     records[record]['hosts'].sort(key=ip_to_int)
        dh = DocHandler()
        dh_records = []
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
        self.config_output_path('dev-0623.docx')
        return message
cvb = CustomVulnTableBuilder()
cvb.build(records=last_vulns)
# print(last_vulns)


