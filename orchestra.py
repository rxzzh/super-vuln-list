from reader import TargetExcelReader, RSASReader
from builder import TargetTableBuilder, SubtotalTableBuilder, VulnTableBuilder, BriefingBuilder, CompareTableBuilder
import os
from utils import ip_regex, concat_path
import logging
import re
from filter import SelectHostByTargetsStaticFilter, SelectTargetByDedupValidIPStaticFilter, SelectTargetByHostStaticFilter
from tqdm import tqdm
from rich import print as pprint
from rich.logging import RichHandler
FORMAT = "%(message)s"
logging.basicConfig(level='INFO',format=FORMAT,handlers=[RichHandler()])
class Control:
    def __init__(self, hosts_path, targets_table_path, output_path):
        # self.host_reports = RSASReader().read(host_file_path=hosts_path)
        self.hosts_path = hosts_path
        self.targets_table_path = targets_table_path
        self.hosts = self.read_all_reports()
        self.targets = TargetExcelReader().read(target_excel_path=targets_table_path)
        self.output_path = output_path

        self.filtered_targets = self.targets
        self.filtered_hosts = self.hosts
        self.output_file_tag = 'dev'

    def read_all_reports(self):
        logging.info('reading host files...')
        filenames = os.listdir(self.hosts_path)
        report_filenames = list(filter(lambda x: ip_regex.match(x), filenames))
        rr = RSASReader()
        hosts = []
        for filename in tqdm(report_filenames):
            hosts.append(
                rr.read(host_file_path=concat_path(self.hosts_path, filename)))
        return hosts


    # static filter, will be replaced by a dynamic constructed filter soon
    def do_filter_dev(self):
        # filter out hosts which are not in target list
        filter_ = SelectHostByTargetsStaticFilter(hosts=self.hosts, targets=self.targets)
        self.filtered_hosts, self.filtered_targets = filter_.run()
        # filter out targets, dedup and with valid IP
        filter_ = SelectTargetByDedupValidIPStaticFilter(hosts=self.filtered_hosts, targets=self.filtered_targets)
        self.filtered_hosts, self.filtered_targets = filter_.run()
        # filter out targets which are not been scanned
        filter_ = SelectTargetByHostStaticFilter(hosts=self.filtered_hosts, targets=self.filtered_targets)
        self.filtered_hosts, self.filtered_targets = filter_.run()

    def get_hosts(self):
        return self.hosts

    def get_targets(self):
        return self.targets

    def set_output_file_tag(self, tag):
        self.output_file_tag = tag

    def calc_scan_rate(self) -> float():
        target_num = len(self.targets)
        scaned_num = len(
            list(filter(lambda x: x.ip in [_.ip for _ in self.filtered_hosts], self.filtered_targets)))
        return scaned_num/target_num

    def build_all(self):
        ttb = TargetTableBuilder()
        vtb = VulnTableBuilder()
        stb = SubtotalTableBuilder()
        bfb = BriefingBuilder()
        
        ttb.config_output_path(output_path=concat_path(
            self.output_path, '漏扫目标{}.docx'.format(self.output_file_tag)))
        vtb.config_output_path(output_path=concat_path(
            self.output_path, '漏洞类型{}.docx'.format(self.output_file_tag)))
        stb.config_output_path(output_path=concat_path(
            self.output_path, '数量统计{}.docx'.format(self.output_file_tag)))
        bfb.config_output_path(output_path=concat_path(
            self.output_path, '简报{}.txt'.format(self.output_file_tag)))
        messages = []
        m = ttb.build(targets=self.filtered_targets)
        m = vtb.build(hosts=self.filtered_hosts)
        messages.append(m)
        m = stb.build(hosts=self.filtered_hosts)
        messages.append(m)
        message = '\n'.join(messages)
        bfb.build(message=self.make_briefing()+message)
    
    def build_compare(self, other_control):
        ctb = CompareTableBuilder()
        ctb.config_output_path(output_path=concat_path(
            self.output_path, '比对结果{}.docx'.format(self.output_file_tag)))
        messages = []
        m = ctb.build(hosts_1=self.filtered_hosts, hosts_0=other_control.filtered_hosts)
        messages = '\n'.join(messages)
        


    def make_briefing(self) -> str:
        res = []
        res.append('HOSTS: {}\n'.format(len(self.hosts)))
        res.append('TARGETS: {}\n'.format(len(self.targets)))
        res.append('TARGETS (valid): {}\n'.format(len(self.filtered_targets)))
        res.append('SCANED TARGETS: {}\n'.format(len(self.filtered_hosts)))
        res.append('SCAN RATE: {}\n'.format(self.calc_scan_rate()))
        return ''.join(res)
        # res.append('HOSTS: {}\n'.format(len(self.hosts)))


# c = Control(hosts_path='project/dev/hosts', targets_table_path='project/dev/properties.xlsx', output_path='project/dev/out')
# # c.read_all_reports()
# print(c.calc_scan_rate())
# c.build_all()


class User:
    def __init__(self):
        self.PATH = './project/'
        self.tag = ''


        self.interactive()
        

    def generate_project(self, project_name):

        project_dir_names = os.listdir(self.PATH)
        if project_name in project_dir_names:
            logging.warning(
                'project {} already exists! nothing to do.'.format(project_name))
            return False
        else:
            project_path = self.PATH+project_name+'/'
            os.mkdir(project_path)
            os.mkdir(project_path+'hosts')
            os.mkdir(project_path+'out')
            os.mkdir(project_path+'targets_xlsx')
        return True

    def list_projects(self):
        return os.listdir(self.PATH)

    def go(self, project_name):
        if not self.environment_check(project_name):
            logging.critical(
                'An critical error has occured, please read error messages and try again.')
            return
        # hp = Helper(project_name=project_name, rsas_hosts_path=self.PATH+project_name+'/hosts/',
            # properties_xlsx_path=self.PATH+project_name+'/'+'targets_xlsx/'+self.get_xlsx_filename(project_name) if self.get_xlsx_filename(project_name) else None, output_path=self.PATH+project_name+'/output/')
        # hp.go()
        control = Control(hosts_path=self.PATH+project_name+'/hosts/', targets_table_path=self.PATH+project_name+'/'+'targets_xlsx/' +
                          self.get_xlsx_filename(project_name) if self.get_xlsx_filename(project_name) else None, output_path=self.PATH+project_name+'/out/')
        control.set_output_file_tag(self.tag)
        # dev
        control.do_filter_dev()
        control.build_all()
        return True

    def compare(self, project_name_0, project_name_1):
        # control_0 use targets.xlsx from control_1. since two targets need to be identical and targets.xlsx in control_1 will be newer version.
        control_0 = Control(hosts_path=self.PATH+project_name_0+'/hosts/', targets_table_path=self.PATH+project_name_1+'/'+'targets_xlsx/' +
                          self.get_xlsx_filename(project_name_1) if self.get_xlsx_filename(project_name_1) else None, output_path=self.PATH+project_name_0+'/out/')
        control_1 = Control(hosts_path=self.PATH+project_name_1+'/hosts/', targets_table_path=self.PATH+project_name_1+'/'+'targets_xlsx/' +
                          self.get_xlsx_filename(project_name_1) if self.get_xlsx_filename(project_name_1) else None, output_path=self.PATH+project_name_1+'/out/')
        control_0.do_filter_dev()
        control_1.do_filter_dev()
        control_1.set_output_file_tag(self.tag)
        control_1.build_compare(other_control=control_0)
        return True
    
    
    def get_xlsx_filename(self, project_name):
        filenames = os.listdir(self.PATH+project_name+'/'+'targets_xlsx')
        xlsx_names = list(filter(lambda x: '.xlsx' in x, filenames))
        xlsx_names = list(filter(lambda x: '~$' not in x, filenames))
        return xlsx_names[0] if xlsx_names else None

    def environment_check(self, project_name):
        if not project_name in os.listdir(self.PATH):
            logging.critical(
                'Project {} not found. Please check the spell or call "new" command to create one.'.format(project_name))
            return False
        if not os.listdir(self.PATH+project_name+'/hosts'):
            logging.critical(
                'No file were found in {}/hosts, please copy the hosts directory in the vuln scan reports to cover this path.'.format(project_name))
            return False
        if not any(['.xlsx' in _ for _ in os.listdir(self.PATH+project_name+'/'+'targets_xlsx/')]):
            logging.warning(
                'No targets file in {}/, program will output all .html files.'.format(project_name))
        return True

    def interactive(self):
        # print('greetings!')
        with open('static/banner.txt') as f:
            banner = f.read()
        pprint('[green bold]'+banner)
        while True:
            cmd = input('builder >:')
            if not cmd:
                continue
            if cmd not in ['help', 'ls', 'new', 'go', 'exit', 'banner', 'tag', 'compare']:
                print('help ls new go banner tag exit')
                continue
            if cmd == 'exit':
                print('bye!')
                return
            if cmd == 'help':
                # print('help ls new go exit')
                print('help: \tshow this message')
                print('ls: \tlist projects')
                print('new: \tcreate a new directory structure with given project name')
                print('go: \tinitiate basic doc building process with given project name')
                print('compare:initiate compare sequence between two projects, previous and later.')
                print('banner: show that awesome banner')
                print('tag: \tapply a tag to output file')
                print('exit: \tbye')
            if cmd == 'ls':
                pprint('[blue]'+' '.join(self.list_projects()))
            if cmd == 'new':
                name = input('enter project name:')
                if not name:
                    print('project name can not be empty!')
                else:
                    self.generate_project(project_name=name)
            if cmd == 'go':
                name = input('enter project name:')
                if not name:
                    print('project name can not be empty!')
                else:
                    if self.go(project_name=name):
                        logging.info('done. report has been write to {}/out'.format(name))
                        pprint('[green bold]TASK SUCCESS!')
            if cmd == 'compare':
                name_0 = input('enter project previous name:')
                name_1 = input('enter project later name:')
                if self.compare(project_name_0=name_0, project_name_1=name_1):
                    logging.info('done. report has been write to {}/out'.format(name_1))
                    pprint('[green bold]TASK SUCCESS!')
            if cmd == 'tag':
                tag = input('enter tag:')
                if not re.compile('^(-|[a-z]|[A-Z]|[0-9])*$').match(tag):
                    print('tag should be (-|[a-z]|[A-Z]|[0-9])*')
                else:
                    self.tag = tag
                    print('tag has been set as: {}'.format(tag))
            if cmd == 'banner':
                pprint('[green bold]'+banner)
                print('pretty cool')

if __name__ == '__main__':
    User()
