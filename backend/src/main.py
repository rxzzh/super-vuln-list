from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()
origins = [
  'http://localhost:8080',
  'http://172.20.131.114:8080'
]
app.add_middleware(middleware_class=CORSMiddleware,allow_origins=origins)

@app.get('/')
def root():
  return {'message':'HelloWorld!'}

@app.get('/api/project/name')
def get_project_name():
  mock_res = {"projects":[{"name":"dev0","status":"pending"},{"name":"dev1","status":"standby"},{"name":"dev2","status":"error"},{"name":"dev3","status":"waiting"}]}
  return mock_res

@app.get('/api/project/{name}/status')
def get_project_by_name(name):
  mock_res = {"project_name":name,"status":"standby"}
  return mock_res

@app.post('api/project/{name}/import/xlsx')
def post_project_import_xlsx(name):
  mock_res = {"status":"success"}
  return mock_res

@app.post('api/project/{name}/import/zip')
def post_project_import_zip(name):
  mock_res = {"status":"success"}
  return mock_res

@app.get('api/project/xlsx/{name}')
def get_project_xlsx(name):
  mock_res = {"name":name,"xlsx":[{"name":"mock0","ip":"10.1.1.1"},{"name":"mock1","ip":"10.1.1.2"},{"name":"mock2","ip":"10.1.1.3"},{"name":"mock3","ip":"10.1.1.4"},{"name":"mock4","ip":"10.1.1.5"}]}
  return mock_res

@app.get('api/project/{name}/html')
def get_project_html(name):
  mock_res = {"html":[{"name":"10.1.1.1.html"},{"name":"10.1.1.2.html"},{"name":"10.1.1.3.html"}]}
  return mock_res

@app.get('api/project/{name}/build/default')
def get_project_build_default(name):
  mock_res = {"status":"success"}
  return mock_res

@app.get('api/project/{name}/build/compare')
def get_project_build_compare(name, another_project):
  mock_res = {"status":"success"}
  return mock_res

@app.get('api/project/{name}/outputs')
def get_project_outputs_by_id(name):
  mock_res = {"files":[{"name":"漏洞类型.docx","type":"docx","url":"files/dev0_file0"},{"name":"简报.txt","type":"txt","url":"files/dev0_file1"}, {"name":"test.xlsx","type":"xlsx","url":"files/dev0_file2"}]}
  return mock_res

@app.get('files/{file_name}')
def get_file(file_name):
  mock_res = 'MOCKING_FILE'
  return mock_res

