from rich import print as pprint
from .reader import RSASReader, TargetExcelReader, TRXReader
from .model import HostReportModel, VulnModel, TargetModel
from .db import MiddleLayer, SchemaManager
import os
from docx import Document
from .utils import gadget_fill_cell, gadget_fill_cell_super, gadget_set_row_height,concat_path, dedup
from tqdm import tqdm
from .builder import VulnTableBuilder, SubtotalTableBuilder, TargetTableBuilder, AllTargetTableBuilder, CompareTableBuilder, BriefingTextBuilder
from tqdm import tqdm
import logging
from rich.logging import RichHandler
FORMAT = "%(message)s"
logging.basicConfig(level='INFO', format=FORMAT, handlers=[RichHandler()])


class MainControl:
    class READERS:
        RSAS = "RSAS"
        TRX = "TRX"
    
    def __init__(self):
        self.sm = SchemaManager()
        self.ml = MiddleLayer()
        self.reader = RSASReader()
    
    def config_reader(self, reader_type: str):
        if reader_type == self.READERS.RSAS:
            self.reader = RSASReader()
        elif reader_type == self.READERS.TRX:
            self.reader = TRXReader()
        else:
            raise Exception

    def db_dump(self, project_name):
        if not self.ml.query_targets(project_name=project_name).fetchall():
            # self.dump_excel(project_name=project_name)
            pass
        if not self.ml.query_hosts(project_name=project_name):
            self.dump_host(project_name=project_name)

    def dump_excel(self, project_name):
        xlsx_filename = os.listdir(
            'project/{}/targets_xlsx/'.format(project_name))[0]
        targets = TargetExcelReader().read(
            target_excel_path='project/{}/targets_xlsx/{}'.format(project_name, xlsx_filename))
        targets = dedup(records=targets, func=lambda x: x.ip)
        dbl = DBLoader(project_name=project_name)
        dbl.load_project()
        dbl.load_target(targets=targets)

    def dump_host(self, project_name):
        hosts = self.reader.read_all(host_file_path='project/{}/hosts/'.format(project_name))
        dbl = DBLoader(project_name=project_name)
        dbl.load_project()
        dbl.load_host(hosts=hosts)
        dbl.load_vuln_from_host(hosts=hosts)
        dbl.load_host_vuln(hosts=hosts)

    def db_purge(self):
        self.sm.reset_database()

    def db_projects(self):
        return [_[0] for _ in self.ml.query_projects()]

    def analysis_basic(self, project_name):
        VulnTableBuilder().build(project_name=project_name)
        SubtotalTableBuilder().build(project_name=project_name)
        # TargetTableBuilder().build(project_name=project_name)
        # AllTargetTableBuilder().build(project_name=project_name)
        # BriefingTextBuilder().build(project_name=project_name)


    def analysis_compare(self, project_name_a, project_name_b):
        CompareTableBuilder().build(project_name_a=project_name_a,
                                    project_name_b=project_name_b)


class User:
    def __init__(self, interactive=True):
        self.PATH = './project/'
        self.tag = ''
        if 'project' not in os.listdir():
            os.mkdir('project')
        self.mc = MainControl()
        if interactive:
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
        dirs = os.listdir(self.PATH)
        dirs.sort()
        return dirs

    def db_projects(self):
        return self.mc.db_projects()

    def db_dump(self, project_name):
        if project_name in self.db_projects():
            logging.error('{} already exists.'.format(project_name))
            return False
        logging.info('dumping data into database')
        if not self.environment_check(project_name=project_name):
            return
        self.mc.db_dump(project_name=project_name)
        return True

    def db_purge(self):
        self.mc.db_purge()
        return True

    def go(self, project_name):
        if project_name not in self.db_projects():
            self.db_dump(project_name=project_name)
        if project_name in self.db_projects():
            logging.info('building tables')
            self.mc.analysis_basic(project_name=project_name)
            return True

    def compare(self, project_name_0, project_name_1):
        if project_name_0 not in self.db_projects() or project_name_1 not in self.db_projects():
            logging.error('"{}" or "{}" not in database yet. please call "dump" first'.format(
                project_name_0, project_name_1))
            return
        # control_0 use targets.xlsx from control_1. since two targets need to be identical and targets.xlsx in control_1 will be newer version.
        self.mc.analysis_compare(
            project_name_a=project_name_0, project_name_b=project_name_1)
        return True

    def get_xlsx_filename(self, project_name):
        filenames = os.listdir(self.PATH+project_name+'/'+'targets_xlsx')
        xlsx_names = list(filter(lambda x: '.xlsx' in x, filenames))
        xlsx_names = list(filter(lambda x: '~$' not in x, filenames))
        return xlsx_names[0] if xlsx_names else None

    def environment_check(self, project_name):
        if not project_name in os.listdir(self.PATH):
            logging.error(
                'Project "{}" not found. Please check the spell or call "new" command to create one.'.format(project_name))
            return False
        if not os.listdir(self.PATH+project_name+'/hosts'):
            logging.error(
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
        pprint(banner)
        while True:
            cmd = input('builder >:').strip()
            if not cmd:
                continue
            cmds = ['help', 'ls', 'new', 'go',
                    'exit', 'banner', 'tag', 'compare', 'lsdb', 'dump', 'purge', 'cfg_reader']
            if cmd not in cmds:
                pprint('[green]'+' '.join(cmds))
                continue
            if cmd == 'exit':
                print('bye!')
                return
            if cmd == 'help':
                # print('help ls new go exit')
                def sprint(x): return pprint(
                    '[green]'+x.split(':')[0]+'[white]:'+x.split(':')[1])
                sprint('help: \tshow this message')
                sprint('ls: \tlist projects')
                sprint(
                    'new: \tcreate a new directory structure with given project name')
                sprint(
                    'go: \tinitiate basic doc building process with given project name')

                sprint(
                    'compare:initiate compare sequence between two projects, previous and later.')
                sprint('dump: \tread raw data from html and xlsx from particular project directory and dump them into backend database')
                sprint('lsdb: \tshow dumped projects')     
                sprint('purge: \tdelete all project in backend database')   
                sprint('banner: show that awesome banner')
                sprint('tag: \tapply a tag to output file')
                sprint('exit: \tbye')
            if cmd == 'ls':
                pprint('[blue]'+' '.join(self.list_projects()))
            if cmd == 'new':
                name = input('enter project name:')
                if '/' in name:
                    logging.critical('contains special characters')
                    return
                if not name:
                    print('project name can not be empty!')
                else:
                    self.generate_project(project_name=name)
            if cmd == 'lsdb':
                pprint('[blue]'+' '.join(self.db_projects()))
            if cmd == 'dump':
                name = input('enter project name:')
                if self.db_dump(project_name=name):
                    pprint('[green bold]TASK SUCCESS!')
            if cmd == 'cfg_reader':
                pprint(['TRX','RSAS'])
                reader_str = input(':>')
                self.mc.config_reader(reader_type=reader_str)
            if cmd == 'go':
                name = input('enter project name:')
                if not name:
                    print('project name can not be empty!')
                else:
                    if self.go(project_name=name):
                        logging.info(
                            'done. report has been write to {}/out'.format(name))
                        pprint('[green bold]TASK SUCCESS!')
            if cmd == 'compare':
                name_0 = input('enter project previous name:')
                name_1 = input('enter project later name:')
                if self.compare(project_name_0=name_0, project_name_1=name_1):
                    logging.info(
                        'done. report has been write to {}/out'.format(name_1))
                    pprint('[green bold]TASK SUCCESS!')
            if cmd == 'tag':
                tag = input('enter tag:')
                if not re.compile('^(-|[a-z]|[A-Z]|[0-9])*$').match(tag):
                    print('tag should be (-|[a-z]|[A-Z]|[0-9])*')
                else:
                    self.tag = tag
                    print('tag has been set as: {}'.format(tag))
            if cmd == 'purge':
                pprint('[red bold]this action will delete all data in database, are you sure? [y/n]',end='')
                sure = input()
                if sure in ['y','Y']:
                    self.db_purge()
                    pprint('[green bold]DONE.')
            if cmd == 'banner':
                pprint(banner)
                print('pretty cool')


class DBLoader:
    def __init__(self, project_name):
        self.ml = MiddleLayer()
        self.project_name = project_name

    def load_project(self):
        if not self.ml.query_project_id(project_name=self.project_name):
            self.ml.insert_project(project_name=self.project_name)

    def load_target(self, targets):
        for record in tqdm(targets):
            self.ml.insert_target(
                project_name=self.project_name, name=record.name, ip=record.ip)

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
            self.ml.update_host_scan_state(
                project_name=self.project_name, host_ip=record.ip)
            host_ip = record.ip
            vulns = record.vulns
            for vuln in vulns:
                self.ml.insert_host_vuln(
                    project_name=self.project_name, host_ip=host_ip, vuln_name=vuln.name)

if __name__ == '__main__':
    User()
