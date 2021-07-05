TEST_MODE = True
from reader import TargetExcelReader, RSASReader
from builder import VulnTableBuilder, SubtotalTableBuilder, TargetTableBuilder
from model import HostReportModel
import logging
logging.basicConfig(level=logging.INFO)

TEST_VULNLIST = True
TEST_TARGET = True
TEST_SUBTOTAL = True

def test_rsas():
    rsas_reader = RSASReader()
    res = rsas_reader.read(host_file_path='project/dev/hosts/10.231.50.3.html')
    if TEST_VULNLIST:
        vtb = VulnTableBuilder()
        vtb.build(hosts=[res])
        logging.info('VULNLIST PASSED')
    if TEST_TARGET:
        excel_reader = TargetExcelReader()
        targets = excel_reader.read(target_excel_path='project/dev/properties.xlsx')
        ttb = TargetTableBuilder()
        ttb.build(targets=targets)
        pass
    if TEST_SUBTOTAL:
        stb = SubtotalTableBuilder()
        stb.build(hosts=[res])
        logging.info('SUBTOTAL PASSED')