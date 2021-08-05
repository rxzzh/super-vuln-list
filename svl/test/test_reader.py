import pytest
from ..reader import TargetExcelReader, RSASReader
from .config import DEV_PROJECT_BASE_PATH
def test_read_xlsx():
  ter = TargetExcelReader()
  # ter.read(target_excel_path='project/dev/targets_xlsx/properties.xlsx')
  return True

def test_read_html():
  ter = RSASReader()