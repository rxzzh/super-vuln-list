TEST_MODE = True
from reader import TargetExcelReader, RSASReader
from builder import VulnTableBuilder, SubtotalTableBuilder, TargetTableBuilder
from model import HostReportModel
from orchestra import Control
import logging
logging.basicConfig(level=logging.INFO)

def test_big():
    hosts_path = 'project/up0/hosts/'
    targets_table_path = 'project/up0/targets_xlsx/properties.xlsx'
    output_path = 'project/up0/out/'
    control = Control(hosts_path, targets_table_path, output_path)
    hosts = control.hosts
    stb = SubtotalTableBuilder()
    stb.build(hosts)

test_big()