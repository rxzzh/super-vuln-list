import pytest
from ..reader import TargetExcelReader

def test_read_xlsx():
  ter = TargetExcelReader()
  ter.read(target_excel_path='project/dev/targets_xlsx/properties.xlsx')